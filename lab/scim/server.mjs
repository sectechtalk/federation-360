#!/usr/bin/env node
// Federation 360 lab SCIM app.
//
// A small SCIM 2.0 service provider (RFC 7643/7644) for the free lab tenant. Microsoft Entra's
// provisioning service sends it users; it stores them in lab/scim/data and writes every request
// and response to lab/scim/logs in a form you can paste straight into Federation 360's SCIM checker.
// Entra ID Free has no provisioning logs, so these files are how you see what Entra sent.
//
// No dependencies. Node 18 or later.
//
//   node lab/scim/server.mjs                     token from F360_SCIM_TOKEN
//   node lab/scim/server.mjs --fault 401         answer every Users/Groups call with that error
//   node lab/scim/server.mjs --reset             start with no users or groups
//
// Usually started for you by lab/scim/Start-F360ScimLab.ps1.

import { createServer } from "node:http";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const URN = {
  user: "urn:ietf:params:scim:schemas:core:2.0:User",
  group: "urn:ietf:params:scim:schemas:core:2.0:Group",
  enterprise: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
  list: "urn:ietf:params:scim:api:messages:2.0:ListResponse",
  patch: "urn:ietf:params:scim:api:messages:2.0:PatchOp",
  error: "urn:ietf:params:scim:api:messages:2.0:Error",
  spc: "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
  resourceType: "urn:ietf:params:scim:schemas:core:2.0:ResourceType",
  schema: "urn:ietf:params:scim:schemas:core:2.0:Schema",
};

const HERE = dirname(fileURLToPath(import.meta.url));
const CT = "application/scim+json";

class ScimError extends Error {
  constructor(status, detail, scimType) {
    super(detail);
    this.status = status;
    this.scimType = scimType;
  }
}

const errorBody = (status, detail, scimType) => ({
  schemas: [URN.error],
  status: String(status),
  ...(scimType ? { scimType } : {}),
  detail,
});

// ------------------------------------------------------------------ filters and PATCH paths

/** Parses the simple filters Entra sends: attr eq "value" (also ne, co, sw, ew, pr). */
export function parseFilter(filter) {
  const m = String(filter)
    .trim()
    .match(/^([\w.:$-]+)\s+(eq|ne|co|sw|ew)\s+(?:"((?:[^"\\]|\\.)*)"|(\S+))$|^([\w.:$-]+)\s+pr$/i);
  if (!m) throw new ScimError(400, `Unsupported filter: ${filter}. This lab app understands: attribute eq "value".`, "invalidFilter");
  if (m[5]) return { attr: m[5], op: "pr" };
  return { attr: m[1], op: m[2].toLowerCase(), value: m[3] !== undefined ? m[3].replace(/\\(.)/g, "$1") : m[4] };
}

// Attributes compared without regard to case, per RFC 7643 (userName, emails and displayName are caseExact=false).
const CASE_INSENSITIVE = new Set(["username", "emails.value", "displayname", "externalid"]);

function readAttr(resource, attr) {
  let a = attr;
  let base = resource;
  const urn = a.match(/^(urn:[^[\]]+):([\w$-]+(?:\.[\w$-]+)?)$/);
  if (urn) {
    if (urn[1] !== URN.user && urn[1] !== URN.group) base = resource[urn[1]] ?? {};
    a = urn[2];
  }
  const [top, sub] = a.split(".");
  const key = Object.keys(base).find((k) => k.toLowerCase() === top.toLowerCase());
  const v = key === undefined ? undefined : base[key];
  if (sub === undefined) return Array.isArray(v) ? v : [v];
  const arr = Array.isArray(v) ? v : v && typeof v === "object" ? [v] : [];
  return arr.map((x) => (x && typeof x === "object" ? x[Object.keys(x).find((k) => k.toLowerCase() === sub.toLowerCase())] : undefined));
}

export function matches(resource, f) {
  const values = readAttr(resource, f.attr).filter((v) => v !== undefined && v !== null && v !== "");
  if (f.op === "pr") return values.length > 0;
  const ci = CASE_INSENSITIVE.has(f.attr.replace(/^urn:.*:/, "").toLowerCase());
  const norm = (v) => (ci ? String(v).toLowerCase() : String(v));
  const want = norm(f.value);
  const test = (v) => {
    const s = norm(v);
    switch (f.op) {
      case "eq": return s === want;
      case "ne": return s !== want;
      case "co": return s.includes(want);
      case "sw": return s.startsWith(want);
      case "ew": return s.endsWith(want);
      default: return false;
    }
  };
  return f.op === "ne" ? values.every(test) : values.some(test);
}

/** Splits a PATCH path into its container (core or extension schema), attribute, filter and sub-attribute. */
export function parsePath(path) {
  const m = String(path)
    .trim()
    .match(/^(?:(urn:[^[\]]+):)?([A-Za-z$][\w$-]*)(?:\[(.+)\])?(?:\.([\w$-]+))?$/);
  if (!m) throw new ScimError(400, `Unsupported PATCH path: ${path}`, "invalidPath");
  const urn = m[1] && m[1] !== URN.user && m[1] !== URN.group ? m[1] : undefined;
  return { urn, attr: m[2], filter: m[3] ? parseFilter(m[3]) : undefined, sub: m[4] };
}

// Entra's default (non-compliant) PATCH sends booleans as the text "True" or "False".
const coerce = (attr, v) => {
  if (attr.toLowerCase() === "active" && typeof v === "string") {
    if (/^true$/i.test(v)) return true;
    if (/^false$/i.test(v)) return false;
  }
  return v;
};

const findKey = (obj, attr) => Object.keys(obj).find((k) => k.toLowerCase() === attr.toLowerCase()) ?? attr;

function setTopLevel(res, key, value, op) {
  // A key may name a whole schema ("urn:...:enterprise:2.0:User": {...}), be schema-qualified
  // ("urn:...:enterprise:2.0:User:employeeNumber"), or be a plain attribute name.
  if (/^urn:.*:(User|Group)$/.test(key) && value && typeof value === "object" && !Array.isArray(value)) {
    if (key === URN.user || key === URN.group) {
      for (const [k, v] of Object.entries(value)) applyOp(res, op, k, v);
    } else {
      res[key] = { ...(res[key] ?? {}), ...value };
      if (!res.schemas?.includes(key)) res.schemas = [...(res.schemas ?? []), key];
    }
    return;
  }
  applyOp(res, op, key, value);
}

function applyOp(res, op, path, value) {
  if (!path) {
    if (op === "remove") throw new ScimError(400, "remove needs a path.", "noTarget");
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new ScimError(400, "An operation without a path needs an object value.", "invalidValue");
    for (const [k, v] of Object.entries(value)) setTopLevel(res, k, v, op);
    return;
  }

  const p = parsePath(path);
  let container = res;
  if (p.urn) {
    res[p.urn] = res[p.urn] ?? {};
    container = res[p.urn];
    if (!res.schemas?.includes(p.urn)) res.schemas = [...(res.schemas ?? []), p.urn];
  }
  const [attrTop, attrSub] = p.attr.includes(".") ? p.attr.split(".") : [p.attr, undefined];
  const key = findKey(container, attrTop);
  const sub = p.sub ?? attrSub;

  if (p.filter) {
    // e.g. emails[type eq "work"].value  or  members[value eq "id"]
    const list = Array.isArray(container[key]) ? container[key] : [];
    const hits = list.filter((x) => matches(x, p.filter));
    if (op === "remove") {
      if (sub) hits.forEach((h) => delete h[findKey(h, sub)]);
      else container[key] = list.filter((x) => !hits.includes(x));
      return;
    }
    if (!hits.length) {
      if (p.filter.op !== "eq") throw new ScimError(400, `No ${p.attr} matches ${path}.`, "noTarget");
      const fresh = { [p.filter.attr]: p.filter.value };
      list.push(fresh);
      hits.push(fresh);
      container[key] = list;
    }
    for (const h of hits) {
      if (sub) h[findKey(h, sub)] = coerce(sub, value);
      else if (value && typeof value === "object") Object.assign(h, value);
    }
    return;
  }

  if (sub) {
    if (op === "remove") {
      if (container[key] && typeof container[key] === "object") delete container[key][findKey(container[key], sub)];
      return;
    }
    container[key] = container[key] && typeof container[key] === "object" && !Array.isArray(container[key]) ? container[key] : {};
    container[key][findKey(container[key], sub)] = coerce(sub, value);
    return;
  }

  if (op === "remove") {
    if (Array.isArray(container[key]) && value !== undefined) {
      // Entra removes group members with path "members" and a value list.
      const drop = new Set((Array.isArray(value) ? value : [value]).map((v) => String(v?.value ?? v)));
      container[key] = container[key].filter((x) => !drop.has(String(x?.value ?? x)));
    } else delete container[key];
    return;
  }

  const v = coerce(attrTop, value);
  if (op === "add" && Array.isArray(container[key])) {
    const items = Array.isArray(v) ? v : [v];
    for (const item of items) {
      const same = container[key].findIndex(
        (x) => (item?.value !== undefined && x?.value === item.value && (item?.type ?? x?.type) === x?.type) || (item?.type && x?.type === item.type && attrTop !== "members"),
      );
      if (same >= 0) container[key][same] = { ...container[key][same], ...item };
      else container[key].push(item);
    }
    return;
  }
  container[key] = v;
}

/** Applies a SCIM PatchOp body to a copy of the resource and returns it. Accepts Entra's capitalised op names. */
export function applyPatch(resource, body) {
  if (!body || !Array.isArray(body.Operations)) throw new ScimError(400, "PATCH body needs an Operations list.", "invalidSyntax");
  const res = structuredClone(resource);
  for (const o of body.Operations) {
    const op = String(o?.op ?? "").toLowerCase();
    if (!["add", "replace", "remove"].includes(op)) throw new ScimError(400, `Unknown PATCH op: ${o?.op}`, "invalidSyntax");
    applyOp(res, op, o.path, o.value);
  }
  return res;
}

// ------------------------------------------------------------------ discovery documents

const attr = (name, type, extra = {}) => ({
  name,
  type,
  multiValued: false,
  required: false,
  caseExact: false,
  mutability: "readWrite",
  returned: "default",
  uniqueness: "none",
  ...extra,
});

const SCHEMAS = [
  {
    id: URN.user,
    name: "User",
    description: "User account",
    attributes: [
      attr("userName", "string", { required: true, uniqueness: "server" }),
      attr("externalId", "string", { caseExact: true }),
      attr("active", "boolean"),
      attr("displayName", "string"),
      attr("title", "string"),
      attr("preferredLanguage", "string"),
      attr("name", "complex", { subAttributes: [attr("givenName", "string"), attr("familyName", "string"), attr("formatted", "string")] }),
      attr("emails", "complex", { multiValued: true, subAttributes: [attr("value", "string"), attr("type", "string"), attr("primary", "boolean")] }),
      attr("phoneNumbers", "complex", { multiValued: true, subAttributes: [attr("value", "string"), attr("type", "string")] }),
      attr("addresses", "complex", { multiValued: true, subAttributes: [attr("type", "string"), attr("formatted", "string"), attr("country", "string")] }),
    ],
  },
  {
    id: URN.enterprise,
    name: "EnterpriseUser",
    description: "Enterprise user extension",
    attributes: [attr("employeeNumber", "string"), attr("department", "string"), attr("costCenter", "string"), attr("organization", "string"), attr("division", "string"),
      attr("manager", "complex", { subAttributes: [attr("value", "string")] })],
  },
  {
    id: URN.group,
    name: "Group",
    description: "Group",
    attributes: [
      attr("displayName", "string", { required: true }),
      attr("externalId", "string", { caseExact: true }),
      attr("members", "complex", { multiValued: true, subAttributes: [attr("value", "string"), attr("display", "string")] }),
    ],
  },
].map((s) => ({ schemas: [URN.schema], ...s, meta: { resourceType: "Schema", location: `/Schemas/${s.id}` } }));

const SPC = {
  schemas: [URN.spc],
  documentationUri: "https://github.com/sectechtalk/federation-360",
  patch: { supported: true },
  bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
  filter: { supported: true, maxResults: 200 },
  changePassword: { supported: false },
  sort: { supported: false },
  etag: { supported: false },
  authenticationSchemes: [{ type: "oauthbearertoken", name: "Bearer token", description: "The secret token set in the Entra provisioning settings.", primary: true }],
  meta: { resourceType: "ServiceProviderConfig", location: "/ServiceProviderConfig" },
};

const RESOURCE_TYPES = [
  { id: "User", name: "User", endpoint: "/Users", schema: URN.user, schemaExtensions: [{ schema: URN.enterprise, required: false }] },
  { id: "Group", name: "Group", endpoint: "/Groups", schema: URN.group },
].map((r) => ({ schemas: [URN.resourceType], ...r, meta: { resourceType: "ResourceType", location: `/ResourceTypes/${r.id}` } }));

// ------------------------------------------------------------------ store

function openStore(dataDir, reset) {
  mkdirSync(dataDir, { recursive: true });
  const file = join(dataDir, "store.json");
  if (reset && existsSync(file)) rmSync(file);
  let data = { Users: [], Groups: [] };
  if (existsSync(file)) {
    try {
      data = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      /* start empty if the file is damaged */
    }
  }
  data.Users ??= [];
  data.Groups ??= [];
  return {
    data,
    save: () => writeFileSync(file, JSON.stringify(data, null, 2)),
  };
}

// ------------------------------------------------------------------ server

/**
 * Creates the lab SCIM server (not yet listening).
 * @param {{ token: string, dataDir?: string, logDir?: string, fault?: number, reset?: boolean, quiet?: boolean }} opts
 */
export function createScimServer(opts) {
  if (!opts?.token || opts.token.length < 16) throw new Error("A bearer token of at least 16 characters is required (set F360_SCIM_TOKEN).");
  const token = Buffer.from(opts.token);
  const dataDir = opts.dataDir ?? join(HERE, "data");
  const logDir = opts.logDir ?? join(HERE, "logs");
  mkdirSync(logDir, { recursive: true });
  const store = openStore(dataDir, opts.reset);
  let seq = 0;
  const log = (...a) => opts.quiet || console.log(...a);

  const authorized = (req) => {
    const m = String(req.headers.authorization ?? "").match(/^Bearer\s+(.+)$/i);
    if (!m) return false;
    const got = Buffer.from(m[1].trim());
    return got.length === token.length && timingSafeEqual(got, token);
  };

  const now = () => new Date().toISOString();

  function finish(res, base, type, item) {
    item.meta = { ...(item.meta ?? {}), resourceType: type === "Users" ? "User" : "Group", lastModified: now(), location: `${base}/${type}/${item.id}` };
    return item;
  }

  function handle(method, route, query, body, base) {
    // Discovery endpoints need auth too, as Entra sends the token on every call.
    if (/^\/ServiceProviderConfig$/i.test(route)) return [200, SPC];
    if (/^\/ResourceTypes\/?$/i.test(route)) return [200, { schemas: [URN.list], totalResults: RESOURCE_TYPES.length, Resources: RESOURCE_TYPES }];
    if (/^\/Schemas\/?$/i.test(route)) return [200, { schemas: [URN.list], totalResults: SCHEMAS.length, Resources: SCHEMAS }];
    const sch = route.match(/^\/Schemas\/(.+)$/i);
    if (sch) {
      const s = SCHEMAS.find((x) => x.id === decodeURIComponent(sch[1]));
      if (!s) throw new ScimError(404, `Schema ${sch[1]} not found.`);
      return [200, s];
    }

    const m = route.match(/^\/(Users|Groups)(?:\/([^/]+))?\/?$/i);
    if (!m) throw new ScimError(404, `No SCIM endpoint at ${route}. Use /Users or /Groups.`);
    const type = m[1].toLowerCase() === "users" ? "Users" : "Groups";
    const id = m[2] ? decodeURIComponent(m[2]) : undefined;
    const list = store.data[type];
    if (opts.fault) throw new ScimError(opts.fault, `Fault injected by the lab app (--fault ${opts.fault}).`);

    const strip = (r) => {
      if (type === "Groups" && /\bmembers\b/i.test(query.get("excludedAttributes") ?? "")) {
        const { members, ...rest } = r;
        return rest;
      }
      return r;
    };

    if (!id) {
      if (method === "GET") {
        let found = list;
        if (query.get("filter")) {
          const f = parseFilter(query.get("filter"));
          found = list.filter((r) => matches(r, f));
        }
        const start = Math.max(1, Number(query.get("startIndex")) || 1);
        const count = query.has("count") ? Math.max(0, Number(query.get("count")) || 0) : 100;
        const page = found.slice(start - 1, start - 1 + count).map(strip);
        return [200, { schemas: [URN.list], totalResults: found.length, startIndex: start, itemsPerPage: page.length, Resources: page }];
      }
      if (method === "POST") {
        if (!body || typeof body !== "object") throw new ScimError(400, "The request body must be a JSON object.", "invalidSyntax");
        if (type === "Users") {
          if (!body.userName) throw new ScimError(400, "userName is required.", "invalidValue");
          if (list.some((u) => String(u.userName).toLowerCase() === String(body.userName).toLowerCase()))
            throw new ScimError(409, `A user with userName ${body.userName} already exists.`, "uniqueness");
        } else if (!body.displayName) throw new ScimError(400, "displayName is required.", "invalidValue");
        const item = { ...structuredClone(body), id: randomUUID() };
        if (type === "Users") item.active = coerce("active", item.active ?? true);
        item.meta = { created: now() };
        finish(null, base, type, item);
        list.push(item);
        store.save();
        return [201, item];
      }
      throw new ScimError(405, `${method} is not allowed on /${type}.`);
    }

    const idx = list.findIndex((r) => r.id === id);
    if (idx < 0) throw new ScimError(404, `${type === "Users" ? "User" : "Group"} ${id} not found.`);
    const current = list[idx];

    switch (method) {
      case "GET":
        return [200, strip(current)];
      case "PUT": {
        if (!body || typeof body !== "object") throw new ScimError(400, "The request body must be a JSON object.", "invalidSyntax");
        const item = { ...structuredClone(body), id, meta: { created: current.meta?.created } };
        if (type === "Users") item.active = coerce("active", item.active ?? true);
        list[idx] = finish(null, base, type, item);
        store.save();
        return [200, list[idx]];
      }
      case "PATCH": {
        const next = applyPatch(current, body);
        next.id = id;
        if (type === "Users" && next.userName !== current.userName && list.some((u, i) => i !== idx && String(u.userName).toLowerCase() === String(next.userName).toLowerCase()))
          throw new ScimError(409, `A user with userName ${next.userName} already exists.`, "uniqueness");
        list[idx] = finish(null, base, type, next);
        store.save();
        return [200, list[idx]];
      }
      case "DELETE":
        list.splice(idx, 1);
        store.save();
        return [204, null];
      default:
        throw new ScimError(405, `${method} is not allowed here.`);
    }
  }

  function writeLog(n, method, url, reqBody, status, resBody) {
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const name = `${stamp}-${String(n).padStart(4, "0")}-${method}-${status}.txt`;
    const reqText = `${method} ${url}\n${reqBody ? "\n" + JSON.stringify(reqBody, null, 2) + "\n" : ""}`;
    const resText = `HTTP/1.1 ${status}\n${resBody ? "\n" + JSON.stringify(resBody, null, 2) + "\n" : ""}`;
    writeFileSync(
      join(logDir, name),
      `# Paste the request part or the response part (not both) into Federation 360 > SCIM checker.\n# The Authorization header is never written to these files.\n\n${reqText}\n----- response -----\n\n${resText}`,
    );
    return name;
  }

  return createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const n = ++seq;
      const url = new URL(req.url ?? "/", "http://lab.local");
      // Accept both https://host/scim/Users and https://host/Users.
      const route = url.pathname.replace(/^\/scim(?=\/|$)/i, "") || "/";
      const base = `${req.headers["x-forwarded-proto"] ?? "http"}://${req.headers.host ?? "localhost"}${url.pathname.toLowerCase().startsWith("/scim") ? "/scim" : ""}`;
      let reqBody = null;
      let status;
      let out;
      try {
        if (!authorized(req)) throw new ScimError(401, "Missing or wrong bearer token. Check the Secret Token in the Entra provisioning settings.");
        const raw = Buffer.concat(chunks).toString("utf8");
        if (raw.trim()) {
          try {
            reqBody = JSON.parse(raw);
          } catch {
            throw new ScimError(400, "The request body is not valid JSON.", "invalidSyntax");
          }
        }
        [status, out] = handle(req.method ?? "GET", route, url.searchParams, reqBody, base);
      } catch (e) {
        status = e instanceof ScimError ? e.status : 500;
        out = errorBody(status, e instanceof ScimError ? e.message : `Lab app error: ${e?.message ?? e}`, e?.scimType);
      }
      const file = writeLog(n, req.method ?? "GET", `${url.pathname}${url.search}`, reqBody, status, out);
      log(`${new Date().toLocaleTimeString()}  ${req.method} ${url.pathname}${url.search ? decodeURIComponent(url.search) : ""}  ->  ${status}   (${file})`);
      res.writeHead(status, out ? { "Content-Type": CT } : {});
      res.end(out ? JSON.stringify(out) : undefined);
    });
  });
}

// ------------------------------------------------------------------ command line

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const opt = (name) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const port = Number(opt("--port") ?? process.env.PORT ?? 8787);
  const fault = opt("--fault") ? Number(opt("--fault")) : undefined;
  try {
    const server = createScimServer({ token: process.env.F360_SCIM_TOKEN ?? "", fault, reset: args.includes("--reset") });
    server.listen(port, "127.0.0.1", () => {
      console.log(`F360 lab SCIM app listening on http://127.0.0.1:${port}/scim${fault ? `  (every Users/Groups call returns ${fault})` : ""}`);
      console.log(`Request logs: ${join(HERE, "logs")}`);
    });
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}

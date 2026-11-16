import type { Finding } from "./types";

/**
 * SCIM 2.0 (RFC 7643 schema, RFC 7644 protocol) message parsing and checks.
 * Works on what an admin can actually capture: a request or response body from
 * the Entra provisioning logs, an app's API log, or a tool such as curl.
 */

export const URN = {
  user: "urn:ietf:params:scim:schemas:core:2.0:User",
  group: "urn:ietf:params:scim:schemas:core:2.0:Group",
  enterprise: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
  patch: "urn:ietf:params:scim:api:messages:2.0:PatchOp",
  list: "urn:ietf:params:scim:api:messages:2.0:ListResponse",
  error: "urn:ietf:params:scim:api:messages:2.0:Error",
  bulk: "urn:ietf:params:scim:api:messages:2.0:BulkRequest",
} as const;

export type ScimKind = "user" | "group" | "patch" | "list" | "error" | "query" | "unknown";

export interface ScimMessage {
  /** HTTP method, when a request line was pasted. */
  method?: string;
  /** Request path and query, when a request line was pasted. */
  path?: string;
  /** HTTP status, from a status line or the body of an error. */
  status?: number;
  /** Decoded filter from a ?filter= query. */
  filter?: string;
  body: any | null;
  kind: ScimKind;
}

const METHODS = "GET|POST|PUT|PATCH|DELETE";

/** Accepts a bare JSON body, or an HTTP capture: request/status line, headers, blank line, body. */
export function parseScim(input: string): ScimMessage {
  const text = input.replace(/^﻿/, "").trim();
  if (!text) throw new Error("Paste a SCIM request or response.");

  const msg: ScimMessage = { body: null, kind: "unknown" };
  const brace = text.search(/[{[]/);
  const head = brace === -1 ? text : text.slice(0, brace);
  const jsonText = brace === -1 ? "" : text.slice(brace);

  const req = head.match(new RegExp(`^\\s*(${METHODS})\\s+(\\S+)`, "im"));
  if (req) {
    msg.method = req[1].toUpperCase();
    msg.path = req[2];
    const f = req[2].match(/[?&]filter=([^&]+)/i);
    if (f) {
      try {
        msg.filter = decodeURIComponent(f[1].replace(/\+/g, " "));
      } catch {
        msg.filter = f[1];
      }
    }
  }
  const st = head.match(/^\s*(?:HTTP\/[\d.]+\s+|Status(?:\s*code)?\s*[:=]\s*)(\d{3})\b/im);
  if (st) msg.status = Number(st[1]);

  if (jsonText) {
    try {
      msg.body = JSON.parse(jsonText);
    } catch (e: any) {
      throw new Error(`The body isn't valid JSON (${e.message}). Copy the whole body, from the first { to the last }.`);
    }
  } else if (!req && !st) {
    throw new Error("This doesn't look like SCIM. Paste a JSON body, or a request line such as: GET /Users?filter=userName eq \"a@b.example\"");
  }

  msg.kind = kindOf(msg);
  if (msg.kind === "error" && !msg.status && msg.body?.status) msg.status = Number(msg.body.status) || undefined;
  return msg;
}

const schemasOf = (b: any): string[] => (Array.isArray(b?.schemas) ? b.schemas.map((s: any) => String(s)) : []);
const has = (list: string[], urn: string) => list.some((s) => s.toLowerCase() === urn.toLowerCase());

function kindOf(m: ScimMessage): ScimKind {
  const b = m.body;
  if (b && typeof b === "object" && !Array.isArray(b)) {
    const s = schemasOf(b);
    if (has(s, URN.error)) return "error";
    if (has(s, URN.patch)) return "patch";
    if (has(s, URN.list)) return "list";
    if (has(s, URN.user)) return "user";
    if (has(s, URN.group)) return "group";
    // Bodies with the schemas line cut off: guess from the shape.
    if (Array.isArray(b.Operations)) return "patch";
    if (Array.isArray(b.Resources) || "totalResults" in b) return "list";
    if ("userName" in b) return "user";
    if ("members" in b || ("displayName" in b && !("emails" in b))) return "group";
    if ("scimType" in b || ("detail" in b && "status" in b)) return "error";
  }
  if (!b && m.method === "GET") return "query";
  return "unknown";
}

export const KIND_LABEL: Record<ScimKind, string> = {
  user: "User resource",
  group: "Group resource",
  patch: "PATCH operations",
  list: "List response (search result)",
  error: "Error response",
  query: "Search request",
  unknown: "Unrecognised",
};

/** One-sentence description of what the message does, in plain words. */
export function describeScim(m: ScimMessage): string {
  const target = m.path ? ` ${m.path.split("?")[0]}` : "";
  switch (m.kind) {
    case "user":
      if (m.method === "POST" || (!m.method && !m.body?.id)) return `Create a user account in the app for ${m.body?.userName ?? "(no userName)"}.`;
      if (m.method === "PUT") return `Replace the whole user record${target} for ${m.body?.userName ?? "this user"}.`;
      return `A user record as the app stores it: ${m.body?.userName ?? "(no userName)"}${m.body?.active === false ? ", currently disabled" : ""}.`;
    case "group":
      return m.method === "POST" || (!m.method && !m.body?.id)
        ? `Create the group ${m.body?.displayName ?? "(no displayName)"} in the app.`
        : `A group record as the app stores it: ${m.body?.displayName ?? "(no displayName)"}.`;
    case "patch": {
      const ops: any[] = Array.isArray(m.body?.Operations) ? m.body.Operations : [];
      const disables = ops.some((o) => isActivePath(o) && isFalse(activeValue(o)));
      const enables = ops.some((o) => isActivePath(o) && isTrue(activeValue(o)));
      const members = ops.some((o) => /^members\b/i.test(String(o?.path ?? "")));
      if (disables) return `Disable the account${target ? ` at${target}` : ""}. This is the leaver path: the user can no longer use the app.`;
      if (enables) return `Re-enable the account${target ? ` at${target}` : ""}.`;
      if (members) return `Change the members of the group${target ? ` at${target}` : ""}.`;
      return `Update ${ops.length} attribute${ops.length === 1 ? "" : "s"} on${target || " a resource"}.`;
    }
    case "list": {
      const n = Number(m.body?.totalResults ?? m.body?.Resources?.length ?? 0);
      return n === 0 ? "The app searched and found no matching account." : `The app searched and found ${n} matching record${n === 1 ? "" : "s"}.`;
    }
    case "error":
      return `The app refused the request${m.status ? ` with HTTP ${m.status}` : ""}${m.body?.scimType ? ` (${m.body.scimType})` : ""}.`;
    case "query":
      return m.filter ? `Ask the app whether an account exists where ${m.filter}.` : `Read${target || " a resource"} from the app.`;
    default:
      return "This is JSON, but it doesn't carry a SCIM schema that this checker recognises.";
  }
}

const isFalse = (v: any) => v === false || (typeof v === "string" && v.toLowerCase() === "false");
const isTrue = (v: any) => v === true || (typeof v === "string" && v.toLowerCase() === "true");
const isActivePath = (o: any) =>
  String(o?.path ?? "").toLowerCase() === "active" || (!o?.path && o?.value && typeof o.value === "object" && "active" in o.value);
const activeValue = (o: any) => (o?.path ? o.value : o?.value?.active);

export interface ScimPath {
  attr: string;
  filter?: { attr: string; op: string; value: string };
  sub?: string;
}

/** Parses a PATCH path such as emails[type eq "work"].value or name.givenName. */
export function parseScimPath(path: string): ScimPath | null {
  const m = path.trim().match(/^((?:urn:[^\s[\]]+:)?[A-Za-z$][\w$-]*)(?:\[\s*([\w.$-]+)\s+(eq|ne|co|sw|ew|gt|ge|lt|le|pr)\s*(?:"([^"]*)"|(\S+))?\s*\])?(?:\.([\w$-]+))?$/i);
  if (!m) return null;
  const p: ScimPath = { attr: m[1] };
  if (m[2]) p.filter = { attr: m[2], op: m[3].toLowerCase(), value: m[4] ?? m[5] ?? "" };
  if (m[6]) p.sub = m[6];
  return p;
}

/** The identifiers an app could match a sign-in against, read from a User resource. */
export function userIdentifiers(body: any): { label: string; value: string }[] {
  const out: { label: string; value: string }[] = [];
  const add = (label: string, v: any) => {
    if (typeof v === "string" && v.trim()) out.push({ label, value: v.trim() });
  };
  add("userName", body?.userName);
  add("externalId", body?.externalId);
  if (Array.isArray(body?.emails)) body.emails.forEach((e: any) => add(`emails[${e?.type ?? "?"}]${e?.primary ? " (primary)" : ""}`, e?.value));
  add("id", body?.id);
  return out;
}

/**
 * Compares the identifier sent at sign-in (SAML NameID, or the OIDC claim the app matches on)
 * with the identifiers SCIM wrote into the app. This is "gate 2": Entra let the user in, but
 * does the app have an account under that name?
 */
export function compareSignInId(signInId: string, body: any): Finding[] {
  const want = signInId.trim();
  if (!want) return [];
  const ids = userIdentifiers(body).filter((i) => i.label !== "id");
  if (!ids.length) return [{ severity: "info", title: "No identifiers to compare", detail: "This message has no userName, externalId or emails. Paste a User resource (a create request or the app's stored record)." }];

  const exact = ids.filter((i) => i.value === want);
  const loose = ids.filter((i) => i.value.toLowerCase() === want.toLowerCase());
  const f: Finding[] = [];
  if (exact.some((i) => i.label === "userName")) {
    f.push({ severity: "ok", title: "Sign-in identifier matches userName exactly", detail: `Both are ${want}. An app that matches accounts on userName will find this user.` });
  } else if (exact.length) {
    f.push({
      severity: "info",
      title: `Sign-in identifier matches ${exact.map((i) => i.label).join(", ")}, not userName`,
      detail: `Sign-in sends ${want}; userName is ${body?.userName ?? "(missing)"}. This works only if the app matches sign-ins on that attribute. Most match on userName.`,
      playbook: "scim-identifier-mismatch",
    });
  } else if (loose.length) {
    f.push({
      severity: "warn",
      title: "Identifiers differ only by upper/lower case",
      detail: `Sign-in sends ${want}; the app has ${loose[0].value} in ${loose[0].label}. Apps that compare case-sensitively report “user not found” or create a duplicate.`,
      playbook: "scim-identifier-mismatch",
    });
  } else {
    f.push({
      severity: "critical",
      title: "Sign-in identifier doesn't match the provisioned account",
      detail: `Sign-in sends ${want}. The account has ${ids.map((i) => `${i.label} = ${i.value}`).join("; ")}. Entra sign-in will succeed and the app will say “user not found”.`,
      playbook: "scim-identifier-mismatch",
    });
  }
  if (body?.active === false || isFalse(body?.active)) {
    f.push({ severity: "critical", title: "The account exists but is disabled", detail: "active is false, so the app will refuse the user even though Entra signs them in.", playbook: "scim-leaver" });
  }
  return f;
}

const ERROR_HELP: Record<string, { title: string; detail: string; playbook?: string }> = {
  "400": { title: "400 Bad Request: the app couldn't understand the request", detail: "The body or filter isn't in a form the app accepts. Check scimType and detail for which part.", playbook: "scim-400" },
  "401": { title: "401 Unauthorized: the app rejected the credential", detail: "The bearer token Entra sends is missing, wrong or expired. Provisioning stops for every user until it's replaced.", playbook: "scim-401" },
  "403": { title: "403 Forbidden: the credential is valid but not allowed to do this", detail: "The token's account lacks permission in the app, or the app's plan doesn't include SCIM.", playbook: "scim-401" },
  "404": { title: "404 Not Found: no resource with that id", detail: "For a PATCH or GET by id, the account was deleted in the app after it was provisioned. For every request, the Tenant URL is probably wrong.", playbook: "scim-404" },
  "409": { title: "409 Conflict: an account with that identifier already exists", detail: "The app already has a user with this userName or email, usually one created by hand before provisioning was turned on.", playbook: "scim-409" },
  "412": { title: "412 Precondition Failed: the record changed since it was read", detail: "The app uses ETags and the version Entra sent is stale. It normally succeeds on the next cycle." },
  "413": { title: "413 Payload Too Large", detail: "The request, usually a group with many members, is bigger than the app accepts.", playbook: "scim-group-members" },
  "429": { title: "429 Too Many Requests: the app is rate limiting", detail: "Entra retries later. Persistent 429s make the initial cycle very slow and can lead to quarantine.", playbook: "scim-quarantine" },
  "500": { title: "500 Internal Server Error: the app failed", detail: "The fault is on the app's side. Collect the time and request, and raise it with the vendor.", playbook: "scim-quarantine" },
  "501": { title: "501 Not Implemented: the app doesn't support this operation", detail: "Common for PATCH, for filters, or for /Groups. The app's SCIM support is partial.", playbook: "scim-400" },
};

const SCIM_TYPE_HELP: Record<string, string> = {
  invalidFilter: "The app doesn't support the filter Entra used to look for the user. Entra needs filtering on the matching attribute (userName or externalId) with eq.",
  tooMany: "The filter matched more results than the app will return.",
  uniqueness: "A value that must be unique (usually userName) is already used by another account.",
  mutability: "The request tried to change a read-only or immutable attribute (often userName or id).",
  invalidSyntax: "The JSON body is malformed or breaks the SCIM schema, for example a text value where the app expects true/false.",
  invalidPath: "The PATCH path isn't valid for this app, for example a filter path such as emails[type eq \"work\"].value that the app can't parse.",
  noTarget: "The PATCH path matched nothing, for example removing an email type the user doesn't have.",
  invalidValue: "A required attribute is missing or the value isn't allowed.",
  invalidVers: "The SCIM version isn't supported.",
  sensitive: "The request put sensitive data in the URL.",
};

export interface ScimOptions {
  /** Identifier the app receives at sign-in (SAML NameID or the matching OIDC claim). */
  signInId?: string;
}

export function checkScim(m: ScimMessage, opts: ScimOptions = {}): Finding[] {
  const f: Finding[] = [];
  const b = m.body;
  const schemas = schemasOf(b);

  // ---- request line and status ----
  if (m.method === "PUT") f.push({ severity: "info", title: "PUT replaces the whole record", detail: "Any attribute left out is cleared. Entra uses PATCH for updates; PUT usually comes from another identity provider or a script." });
  if (m.method === "DELETE") f.push({ severity: "warn", title: "DELETE permanently removes the account", detail: "The user's data in the app may go with it. Entra normally disables first (active = false) and only deletes when the user is hard-deleted from the directory.", playbook: "scim-leaver" });
  if (m.path && !/\/(Users|Groups|Schemas|ServiceProviderConfig|ResourceTypes|Bulk|Me)\b/i.test(m.path)) {
    f.push({ severity: "warn", title: "Path isn't a standard SCIM endpoint", detail: `${m.path}. Expected a path ending in /Users, /Groups, /Schemas or /ServiceProviderConfig. Check the Tenant URL.`, playbook: "scim-404" });
  }
  if (m.filter) {
    const fm = m.filter.match(/^\s*([\w.:$-]+)\s+(eq|ne|co|sw|ew|pr)\s*"?([^"]*)"?\s*$/i);
    if (fm) {
      f.push({ severity: "ok", title: `Looks up an account where ${fm[1]} ${fm[2]} "${fm[3]}"`, detail: "Entra does this before every create. No match means it will create the user; one match means it will link to and update that account." });
      if (opts.signInId && /^(userName|externalId)$/i.test(fm[1]) && fm[2].toLowerCase() === "eq" && fm[3] !== opts.signInId.trim()) {
        f.push({
          severity: fm[3].toLowerCase() === opts.signInId.trim().toLowerCase() ? "warn" : "critical",
          title: "Provisioning looks for a different identifier than sign-in sends",
          detail: `Provisioning matches on ${fm[1]} = ${fm[3]}; sign-in sends ${opts.signInId.trim()}.`,
          playbook: "scim-identifier-mismatch",
        });
      }
    } else {
      f.push({ severity: "info", title: "Complex filter", detail: `${m.filter}. Many apps only support simple filters such as userName eq "value".`, playbook: "scim-400" });
    }
  }
  if (m.status && m.kind !== "error") {
    if (m.status >= 400) {
      const h = ERROR_HELP[String(m.status)];
      f.push({ severity: "critical", title: h?.title ?? `HTTP ${m.status}: the request failed`, detail: h?.detail, playbook: h?.playbook });
    } else if (m.status === 204) f.push({ severity: "ok", title: "204 No Content: the app accepted the change" });
    else if (m.status === 201) f.push({ severity: "ok", title: "201 Created: the app created the resource" });
    else if (m.status === 200) f.push({ severity: "ok", title: "200 OK: the app accepted the request" });
  }

  if (!b) return f;

  if (typeof b !== "object" || Array.isArray(b)) {
    f.push({ severity: "critical", title: "A SCIM body must be a JSON object", detail: "This is a JSON array or a bare value." });
    return f;
  }
  if (!schemas.length) {
    f.push({ severity: m.kind === "unknown" ? "critical" : "warn", title: "No schemas attribute", detail: "Every SCIM message must start with a schemas list naming what it is. Strict apps reject a body without it (400 invalidSyntax).", playbook: "scim-400" });
  }

  // ---- by kind ----
  if (m.kind === "user") checkUser(b, m, f);
  else if (m.kind === "group") checkGroup(b, f);
  else if (m.kind === "patch") checkPatch(b, m, f);
  else if (m.kind === "list") checkList(b, f);
  else if (m.kind === "error") checkError(b, m, f);
  else if (schemas.length) f.push({ severity: "info", title: "Schema not covered by this checker", detail: schemas.join(", ") });

  if (opts.signInId && m.kind === "user") f.push(...compareSignInId(opts.signInId, b));
  if (opts.signInId && m.kind === "list" && Array.isArray(b.Resources) && b.Resources.length === 1) f.push(...compareSignInId(opts.signInId, b.Resources[0]));

  return f;
}

function checkUser(b: any, m: ScimMessage, f: Finding[]) {
  if (typeof b.userName !== "string" || !b.userName.trim()) {
    f.push({ severity: "critical", title: "userName is missing", detail: "userName is the one required attribute of a SCIM user and is what most apps match sign-ins on.", playbook: "scim-400" });
  } else {
    f.push({ severity: "ok", title: `userName is ${b.userName}`, detail: "This must equal what the app receives at sign-in (the SAML NameID or the claim the app matches on)." });
  }
  if (!b.externalId) {
    f.push({ severity: "info", title: "No externalId", detail: "externalId carries the identity provider's own stable ID for the user. Without it, a renamed user (new userName) can be treated as a new person." });
  }
  if (typeof b.active === "string") {
    f.push({
      severity: "warn",
      title: `active is the text "${b.active}", not true/false`,
      detail: "SCIM defines active as a boolean. Entra sends it as text unless the app's Tenant URL has the feature flag ?aadOptscim062020. Strict apps reject it (400 invalidSyntax) or read every value as true.",
      playbook: "scim-400",
    });
  }
  if (isFalse(b.active)) {
    f.push({ severity: "warn", title: "The account is disabled (active = false)", detail: "The user will be refused by the app even if Entra signs them in. Expected for a leaver; a problem for anyone else.", playbook: "scim-leaver" });
  } else if (b.active === undefined) {
    f.push({ severity: "info", title: "No active attribute", detail: "Most apps treat a missing value as active. Without it, there is no standard way to disable the account later." });
  }
  if (Array.isArray(b.emails)) {
    const primaries = b.emails.filter((e: any) => e?.primary === true || isTrue(e?.primary)).length;
    if (primaries > 1) f.push({ severity: "warn", title: "More than one email is marked primary", detail: "Only one value may be primary. Apps pick one unpredictably or reject the request." });
    if (b.emails.some((e: any) => !e?.value)) f.push({ severity: "warn", title: "An email entry has no value" });
    if (b.emails.length && primaries === 0) f.push({ severity: "info", title: "No email is marked primary", detail: "Apps that send notifications or match on the primary email may ignore these addresses." });
  } else if (b.emails !== undefined) {
    f.push({ severity: "warn", title: "emails must be a list", detail: 'Expected [{"value": "a@b.example", "type": "work", "primary": true}].', playbook: "scim-400" });
  } else {
    f.push({ severity: "info", title: "No emails", detail: "Fine for apps that only need a username. Many apps require a work email to create the account." });
  }
  if (!b.name?.givenName && !b.name?.familyName && !b.displayName) {
    f.push({ severity: "info", title: "No name attributes", detail: "No name.givenName, name.familyName or displayName. Some apps refuse to create a user without them." });
  }
  if ((m.method === "POST" || !m.method) && b.id && !b.meta) {
    f.push({ severity: "info", title: "A create request shouldn't set id", detail: "The app assigns id and returns it. Entra stores it and uses it in the URL of every later PATCH." });
  }
  if (b.password) f.push({ severity: "warn", title: "The message contains a password", detail: "Treat this capture as a secret, and prefer single sign-on over provisioning passwords." });
  const s = schemasOf(b);
  if (b[URN.enterprise] && !has(s, URN.enterprise)) {
    f.push({ severity: "warn", title: "Enterprise attributes used but the extension schema isn't declared", detail: `Add ${URN.enterprise} to schemas, or strict apps ignore department, manager and employeeNumber.` });
  }
}

function checkGroup(b: any, f: Finding[]) {
  if (typeof b.displayName !== "string" || !b.displayName.trim()) {
    f.push({ severity: "critical", title: "displayName is missing", detail: "displayName is required for a group, and Entra matches groups on it.", playbook: "scim-400" });
  } else f.push({ severity: "ok", title: `Group displayName is ${b.displayName}` });
  if (b.members !== undefined && !Array.isArray(b.members)) {
    f.push({ severity: "warn", title: "members must be a list", detail: 'Expected [{"value": "<the app\'s id for the user>"}].', playbook: "scim-group-members" });
  } else if (Array.isArray(b.members)) {
    if (b.members.some((x: any) => !x?.value)) f.push({ severity: "warn", title: "A member entry has no value", detail: "Each member needs value set to the app's id for that user (not the userName, and not the Entra object ID).", playbook: "scim-group-members" });
    f.push({ severity: "info", title: `${b.members.length} member${b.members.length === 1 ? "" : "s"} listed`, detail: "Members are referenced by the app's id for each user, so every member must be provisioned before they can be added." });
  }
}

function checkPatch(b: any, m: ScimMessage, f: Finding[]) {
  const ops: any[] = Array.isArray(b.Operations) ? b.Operations : Array.isArray(b.operations) ? b.operations : [];
  if (!Array.isArray(b.Operations) && Array.isArray(b.operations)) {
    f.push({ severity: "warn", title: "“operations” should be “Operations”", detail: "SCIM attribute names are case-insensitive by the standard, but many apps only accept the capitalised form.", playbook: "scim-400" });
  }
  if (!ops.length) {
    f.push({ severity: "critical", title: "No operations", detail: "A PATCH must carry at least one entry in Operations.", playbook: "scim-400" });
    return;
  }
  if (m.method && m.method !== "PATCH") f.push({ severity: "warn", title: `PatchOp body sent with ${m.method}`, detail: "A PatchOp message is only valid with the PATCH method." });

  let capital = false;
  ops.forEach((o, i) => {
    const n = `Operation ${i + 1}`;
    const op = String(o?.op ?? "");
    const lower = op.toLowerCase();
    if (!["add", "replace", "remove"].includes(lower)) {
      f.push({ severity: "critical", title: `${n}: op must be add, replace or remove`, detail: `Found “${op || "(missing)"}”.`, playbook: "scim-400" });
      return;
    }
    if (op !== lower) capital = true;
    const path = o?.path === undefined ? undefined : String(o.path);
    if (lower === "remove" && !path) {
      f.push({ severity: "critical", title: `${n}: remove needs a path`, detail: "Without a path the app can't know what to remove (400 noTarget).", playbook: "scim-400" });
    }
    if (lower !== "remove" && o?.value === undefined) {
      f.push({ severity: "critical", title: `${n}: ${lower} needs a value`, playbook: "scim-400" });
    }
    if (path) {
      const p = parseScimPath(path);
      if (!p) f.push({ severity: "warn", title: `${n}: path can't be parsed`, detail: `${path}. Apps answer 400 invalidPath.`, playbook: "scim-400" });
      else if (p.filter && !/^members$/i.test(p.attr)) {
        f.push({ severity: "info", title: `${n}: uses a filter path`, detail: `${path} means “the ${p.attr} entry whose ${p.filter.attr} is ${p.filter.value}”. Apps with partial PATCH support reject these (400 invalidPath).`, playbook: "scim-400" });
      }
    }
    if (isActivePath(o)) {
      const v = activeValue(o);
      if (typeof v === "string") {
        f.push({
          severity: "warn",
          title: `${n}: active is the text "${v}", not true/false`,
          detail: "Entra sends text here unless the Tenant URL has the feature flag ?aadOptscim062020. Strict apps reject it, and loose ones can read \"False\" as true, leaving a leaver enabled.",
          playbook: "scim-leaver",
        });
      }
      if (isFalse(v)) f.push({ severity: "warn", title: `${n}: disables the account`, detail: "This is how Entra removes access when a user is unassigned, disabled or deleted. Confirm afterwards that the app really shows the user as inactive.", playbook: "scim-leaver" });
      else if (isTrue(v)) f.push({ severity: "ok", title: `${n}: enables the account` });
    }
    if (path && /^userName$/i.test(path)) {
      f.push({ severity: "warn", title: `${n}: changes userName`, detail: `New value: ${o.value}. Sign-in keeps working only if the identifier sent at sign-in changes at the same time. Some apps forbid renames (400 mutability).`, playbook: "scim-identifier-mismatch" });
    }
    if (path && /^members\b/i.test(path)) {
      const vals = Array.isArray(o?.value) ? o.value : o?.value ? [o.value] : [];
      if (lower === "remove" && !vals.length && !/\[/.test(path)) {
        f.push({ severity: "warn", title: `${n}: removes every member of the group`, detail: "remove on members with no value and no filter clears the group." });
      } else {
        f.push({ severity: "ok", title: `${n}: ${lower === "remove" ? "removes" : "adds"} ${vals.length || 1} group member${(vals.length || 1) === 1 ? "" : "s"}`, detail: "Each value is the app's id for a user, which must already exist in the app." });
      }
      if (vals.length > 1) f.push({ severity: "info", title: `${n}: several members in one request`, detail: "Apps that only accept one member per PATCH reject this. Entra can be set to send one at a time.", playbook: "scim-group-members" });
    }
  });
  if (capital) {
    f.push({
      severity: "info",
      title: "Operation names are capitalised (Add, Replace, Remove)",
      detail: "Entra sends them this way unless the Tenant URL has the feature flag ?aadOptscim062020. Apps that compare exactly against add/replace/remove answer 400.",
      playbook: "scim-400",
    });
  }
}

function checkList(b: any, f: Finding[]) {
  const res: any[] = Array.isArray(b.Resources) ? b.Resources : [];
  const total = typeof b.totalResults === "number" ? b.totalResults : res.length;
  if (typeof b.totalResults !== "number") f.push({ severity: "warn", title: "totalResults is missing", detail: "Entra reads totalResults to decide whether the user exists." });
  if (total === 0) {
    f.push({ severity: "info", title: "No matching account in the app", detail: "For a lookup before create this is normal: Entra will create the user next. If the user should already exist, the matching attribute values differ.", playbook: "scim-identifier-mismatch" });
  } else if (total === 1) {
    f.push({ severity: "ok", title: "Exactly one matching account", detail: `Entra will link to it and update it${res[0]?.id ? ` (app id ${res[0].id})` : ""}.` });
    if (res[0] && isFalse(res[0].active)) f.push({ severity: "warn", title: "The matching account is disabled", playbook: "scim-leaver" });
  } else {
    f.push({ severity: "critical", title: `${total} accounts match one identifier`, detail: "A lookup on a unique attribute must return one account. Duplicates make provisioning fail for this user until all but one are removed.", playbook: "scim-409" });
  }
  if (res.length && total > res.length && !b.itemsPerPage) f.push({ severity: "info", title: "Results are paged", detail: `${res.length} of ${total} returned. Use startIndex and count to read the rest.` });
}

function checkError(b: any, m: ScimMessage, f: Finding[]) {
  const status = String(m.status ?? b.status ?? "");
  const h = ERROR_HELP[status];
  f.push({ severity: "critical", title: h?.title ?? `HTTP ${status || "error"}: the app refused the request`, detail: [h?.detail, b.detail ? `The app said: “${b.detail}”` : ""].filter(Boolean).join(" "), playbook: h?.playbook });
  if (b.scimType) {
    const t = SCIM_TYPE_HELP[String(b.scimType)];
    f.push({ severity: "info", title: `scimType: ${b.scimType}`, detail: t ?? "A non-standard error type defined by this app." });
  }
  if (b.status !== undefined && typeof b.status !== "string") f.push({ severity: "info", title: "status should be text", detail: 'The standard puts the HTTP status in the body as a string, for example "409".' });
}

export const SCIM_ATTR_HELP: Record<string, string> = {
  schemas: "Says what kind of SCIM message this is. Required on every message.",
  id: "The app's own unique ID for this record. The app assigns it; Entra stores it and uses it in later requests.",
  externalId: "The identity provider's ID for the same person. Stays the same when the user is renamed.",
  userName: "The sign-in name in the app. Required, unique, and what most apps match single sign-on against.",
  active: "true = the account can be used. false = disabled. Setting false is how leavers lose access.",
  displayName: "The name shown in the app. Required for groups.",
  "name.givenName": "First name.",
  "name.familyName": "Last name.",
  "name.formatted": "Full name as one string.",
  emails: "Email addresses. One should have primary = true.",
  title: "Job title.",
  userType: "A label such as Employee or Contractor, defined by your organisation.",
  preferredLanguage: "Language for the app's interface, for example en-US.",
  members: "The users in a group, each referenced by the app's id for that user.",
  meta: "Read-only details the app adds: resource type, created and last modified times, and location.",
  "meta.resourceType": "User or Group.",
  "meta.created": "When the app created the record.",
  "meta.lastModified": "When the app last changed the record.",
  Operations: "The list of changes in a PATCH. Each has op (add, replace or remove), usually a path, and a value.",
  totalResults: "How many records matched the search.",
  Resources: "The matching records.",
  startIndex: "Position of the first returned result, counting from 1.",
  itemsPerPage: "How many results are in this page.",
  status: "The HTTP status code, repeated in the body of an error.",
  scimType: "A standard keyword saying what kind of error occurred.",
  detail: "The app's own description of the error.",
  [`${URN.enterprise}.department`]: "Department (enterprise extension).",
  [`${URN.enterprise}.employeeNumber`]: "Employee number (enterprise extension).",
  [`${URN.enterprise}.manager`]: "The user's manager, referenced by the app's id (enterprise extension).",
};

/** Flattens a body into rows for display. Arrays of objects stay as one JSON value. */
export function flattenScim(body: any): { key: string; value: string }[] {
  const rows: { key: string; value: string }[] = [];
  const walk = (o: any, prefix: string) => {
    for (const [k, v] of Object.entries(o ?? {})) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (v && typeof v === "object" && !Array.isArray(v)) walk(v, key);
      else rows.push({ key, value: typeof v === "string" ? v : JSON.stringify(v) });
    }
  };
  if (body && typeof body === "object" && !Array.isArray(body)) walk(body, "");
  return rows;
}

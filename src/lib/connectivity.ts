/**
 * Agentless connectivity test. Federation 360 turns the inventory into a test plan, embeds it in the
 * PowerShell 5.1 script connectivity/Test-F360Connectivity.ps1, and Remediation 360 signs it and runs it
 * on devices as an Intune Remediations detection script. The results come back here as JSON files or as
 * the one-line summaries Intune shows, and are read on the Connectivity test page.
 */
import type { AppIntegration, Tenant } from "./types";

export const PLAN_SCHEMA = "f360.connectivity.plan/1";
export const RESULT_SCHEMA = "f360.connectivity.result/1";
export const PLAN_BEGIN = "# >>> F360 PLAN";
export const PLAN_END = "# <<< F360 PLAN";

export type TestType = "dns" | "tcp" | "tls" | "http" | "clock";

export interface PlanTest {
  id: string;
  type: TestType;
  label: string;
  host?: string;
  port?: number;
  url?: string;
  /** tls: regex the certificate issuer or root must match; a mismatch means TLS inspection. http: exact issuer in the JSON body. */
  expectIssuer?: string;
  expectStatus?: number[];
  expectContains?: string;
  /** Names of the inventory apps that depend on this target. */
  apps: string[];
}

export interface PlanSettings {
  timeoutMs: number;
  clockWarnSec: number;
  clockFailSec: number;
  certWarnDays: number;
}

export interface ConnectivityPlan {
  schema: typeof PLAN_SCHEMA;
  id: string;
  name: string;
  createdAt: string;
  settings: PlanSettings;
  tests: PlanTest[];
  /** True when no chosen app had a device-reachable endpoint and the plan is the Entra baseline. */
  fallback?: boolean;
}

export const DEFAULT_SETTINGS: PlanSettings = { timeoutMs: 8000, clockWarnSec: 60, clockFailSec: 300, certWarnDays: 30 };

/** Microsoft's public sign-in endpoints chain to DigiCert or Microsoft roots; anything else is a TLS inspection proxy. */
export const MICROSOFT_ISSUER = "Microsoft|DigiCert";
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** True for a host a managed device should be able to reach: not localhost, not a reserved example name. */
export function isTestableHost(host: string): boolean {
  const h = host.toLowerCase();
  if (!h || h === "localhost" || h.endsWith(".localhost") || /^127\.|^\[?::1\]?$/.test(h)) return false;
  if (/(^|\.)(example|invalid|test)$/.test(h) || /(^|\.)example\.(com|net|org)$/.test(h)) return false;
  return h.includes(".");
}

function parseHttps(u: string): URL | null {
  try {
    const url = new URL(u.trim());
    return url.protocol === "https:" && isTestableHost(url.hostname) ? url : null;
  } catch {
    return null;
  }
}

/** FNV-1a, so the same tests always give the same plan id and results can be matched to their plan. */
export function hashText(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

export interface BuildOptions {
  name?: string;
  now?: Date;
  settings?: Partial<PlanSettings>;
}

/**
 * Build a plan for the chosen apps. Every target is tested once; the apps that rely on it are listed on the test.
 * Only anonymous checks: DNS, TCP 443, TLS handshake, unauthenticated GET, and a clock comparison.
 */
export function buildPlan(tenants: Tenant[], apps: AppIntegration[], opts: BuildOptions = {}): ConnectivityPlan {
  const tests: PlanTest[] = [];
  const byKey = new Map<string, PlanTest>();
  const add = (key: string, t: Omit<PlanTest, "id" | "apps">, app?: string) => {
    let cur = byKey.get(key);
    if (!cur) {
      cur = { id: "", ...t, apps: [] };
      byKey.set(key, cur);
      tests.push(cur);
    }
    if (app && !cur.apps.includes(app)) cur.apps.push(app);
  };
  const hostChecks = (host: string, what: string, app?: string, expectIssuer?: string) => {
    add(`dns|${host}`, { type: "dns", host, label: `${what}: name resolves` }, app);
    add(`tcp|${host}|443`, { type: "tcp", host, port: 443, label: `${what}: port 443 is open` }, app);
    add(`tls|${host}|443`, { type: "tls", host, port: 443, label: `${what}: TLS is trusted${expectIssuer ? " and not inspected" : ""}`, ...(expectIssuer ? { expectIssuer } : {}) }, app);
  };
  const reachable = (url: URL, what: string, app?: string) => {
    hostChecks(url.hostname, what, app);
    add(`http|${url.href}`, { type: "http", url: url.href, label: `${what}: answers HTTPS` }, app);
  };

  const tenantById = new Map(tenants.map((t) => [t.id, t]));
  const usedTenants = new Set(apps.map((a) => a.tenantId));
  const entra = tenants.filter((t) => t.platform === "entra" && usedTenants.has(t.id));
  const appsFor = (t: Tenant) => apps.filter((a) => a.tenantId === t.id).map((a) => a.name);

  const entraBaseline = () => {
    hostChecks("login.microsoftonline.com", "Entra sign-in");
    add("clock|login", { type: "clock", url: "https://login.microsoftonline.com/", label: "Device clock matches Entra (5 minute limit)" });
    hostChecks("aadcdn.msftauth.net", "Entra sign-in page assets (CDN)");
    const tls = byKey.get("tls|login.microsoftonline.com|443")!;
    tls.expectIssuer = MICROSOFT_ISSUER;
    tls.label = "Entra sign-in: TLS is trusted and not inspected";
  };

  if (entra.length) {
    const names = entra.flatMap(appsFor);
    entraBaseline();
    for (const k of ["dns|login.microsoftonline.com", "tcp|login.microsoftonline.com|443", "tls|login.microsoftonline.com|443", "clock|login"]) {
      for (const n of names) if (!byKey.get(k)!.apps.includes(n)) byKey.get(k)!.apps.push(n);
    }
    for (const t of entra) {
      const ref = (t.tenantRef || t.domain || "").trim();
      if (!ref || (!GUID.test(ref) && !isTestableHost(ref))) continue;
      const tApps = apps.filter((a) => a.tenantId === t.id);
      const disc = `https://login.microsoftonline.com/${ref}/v2.0/.well-known/openid-configuration`;
      tApps.forEach((a) =>
        add(`http|${disc}`, {
          type: "http",
          url: disc,
          label: `${t.name}: OpenID Connect discovery`,
          expectStatus: [200],
          expectContains: "authorization_endpoint",
          ...(GUID.test(ref) ? { expectIssuer: `https://login.microsoftonline.com/${ref.toLowerCase()}/v2.0` } : {}),
        }, a.name),
      );
      for (const a of tApps.filter((x) => x.protocol === "saml")) {
        const md = `https://login.microsoftonline.com/${ref}/federationmetadata/2007-06/federationmetadata.xml`;
        add(`http|${md}`, { type: "http", url: md, label: `${t.name}: SAML federation metadata`, expectStatus: [200], expectContains: "EntityDescriptor" }, a.name);
      }
    }
  }

  for (const t of tenants.filter((x) => usedTenants.has(x.id) && x.platform !== "entra")) {
    const names = appsFor(t);
    const host = (t.domain || "").trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!isTestableHost(host)) continue;
    if (t.platform === "aws-idc" && host.endsWith(".awsapps.com")) {
      const u = new URL(`https://${host}/start`);
      names.forEach((n) => reachable(u, `${t.name} access portal`, n));
    } else if (t.platform === "okta") {
      const u = `https://${host}/.well-known/openid-configuration`;
      names.forEach((n) => {
        hostChecks(host, `${t.name} (Okta)`, n);
        add(`http|${u}`, { type: "http", url: u, label: `${t.name}: OpenID Connect discovery`, expectStatus: [200], expectContains: "authorization_endpoint" }, n);
      });
    } else {
      names.forEach((n) => hostChecks(host, t.name, n));
    }
  }

  for (const a of apps) {
    const tenant = tenantById.get(a.tenantId);
    if (a.protocol === "saml") {
      const acs = parseHttps(a.saml.acsUrl);
      if (acs) hostChecks(acs.hostname, `${a.name} reply URL host`, a.name);
      const so = parseHttps(a.saml.signOnUrl);
      if (so) reachable(so, `${a.name} sign-on URL`, a.name);
    } else {
      for (const r of a.oidc.redirectUris.split(/\s+/).filter(Boolean)) {
        const u = parseHttps(r);
        if (u) hostChecks(u.hostname, `${a.name} redirect URI host`, a.name);
      }
      const iss = parseHttps(a.oidc.issuer);
      // Entra issuers (v2 login.microsoftonline.com, v1 sts.windows.net) are covered by the tenant checks above.
      const isEntraIssuer = (iss?.hostname === "login.microsoftonline.com" || iss?.hostname === "sts.windows.net") && tenant?.platform === "entra";
      if (iss && !isEntraIssuer) {
        const u = iss.href.replace(/\/$/, "") + "/.well-known/openid-configuration";
        hostChecks(iss.hostname, `${a.name} issuer`, a.name);
        add(`http|${u}`, { type: "http", url: u, label: `${a.name}: issuer discovery document`, expectStatus: [200], expectIssuer: a.oidc.issuer.trim() }, a.name);
      }
    }
    if (a.provisioning === "scim" && a.scim?.endpoint) {
      // SCIM traffic goes from the identity provider's cloud to the app, not from devices. Testing it from a
      // device still proves the endpoint is up and its certificate is good; a 401 without a token is expected.
      const u = parseHttps(a.scim.endpoint);
      if (u) reachable(u, `${a.name} SCIM endpoint`, a.name);
    }
  }

  // Nothing device-testable chosen (no apps yet, or only localhost/example URLs): test the Microsoft Entra sign-in
  // baseline instead, so there is always a plan to run.
  const fallback = tests.length === 0;
  if (fallback) {
    entraBaseline();
    const common = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";
    add(`http|${common}`, { type: "http", url: common, label: "Entra OpenID Connect discovery document", expectStatus: [200], expectContains: "authorization_endpoint" });
  }

  tests.forEach((t, i) => (t.id = `t${i + 1}`));
  const settings = { ...DEFAULT_SETTINGS, ...(opts.settings ?? {}) };
  const id = hashText(JSON.stringify({ settings, tests }));
  return {
    schema: PLAN_SCHEMA,
    id,
    name: opts.name?.trim() || (fallback ? "Microsoft Entra sign-in baseline" : `Federation 360 connectivity (${apps.length} app${apps.length === 1 ? "" : "s"})`),
    createdAt: (opts.now ?? new Date()).toISOString(),
    settings,
    tests,
    ...(fallback ? { fallback: true } : {}),
  };
}

/** Put the plan into the script between the F360 PLAN markers. Throws if the markers are missing. */
export function embedPlan(script: string, plan: ConnectivityPlan): string {
  const nl = script.includes("\r\n") ? "\r\n" : "\n";
  const lines = script.split(/\r?\n/);
  const b = lines.findIndex((l) => l.startsWith(PLAN_BEGIN));
  const e = lines.findIndex((l) => l.startsWith(PLAN_END));
  if (b < 0 || e < b) throw new Error("The script has no F360 PLAN markers.");
  const json = JSON.stringify(plan, null, 2);
  // A single-quoted here-string ends at a line starting with '@; JSON.stringify output never has one.
  if (/^'@/m.test(json)) throw new Error("The plan can't be embedded safely.");
  const block = [lines[b], "$F360EmbeddedPlan = @'", ...json.split("\n"), "'@", lines[e]];
  return [...lines.slice(0, b), ...block, ...lines.slice(e + 1)].join(nl);
}

/** Read the plan back out of a script (used by tests and to show what a downloaded script will run). */
export function extractPlan(script: string): ConnectivityPlan | null {
  const m = script.match(/\$F360EmbeddedPlan = @'\r?\n([\s\S]*?)\r?\n'@/);
  if (!m) return null;
  try {
    return JSON.parse(m[1]);
  } catch {
    return null;
  }
}

/** The remediate.ps1 r360 needs alongside detect.ps1. It never runs ("Run remediation script" is off) and changes nothing. */
export { default as REMEDIATE_SCRIPT } from "../../connectivity/Remediate-F360Connectivity.ps1?raw";

/** Values for Remediation 360's New remediation form. The server picks the canary group itself. */
export function r360Fields(plan: ConnectivityPlan) {
  return {
    folder: "f360-connectivity",
    displayName: "F360 Connectivity test",
    description: `Federation 360 agentless connectivity test, plan ${plan.id} (${plan.tests.length} checks). Report only; changes nothing.`,
    publisher: "Federation 360",
    runAs: "system" as const,
    runAs32Bit: false,
    enforceSignatureCheck: true,
    schedule: { type: "daily" as const, interval: 1, time: "09:00:00", useUtc: false },
    runRemediationScript: false,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------------------------------------------

export type ResultStatus = "pass" | "warn" | "fail";

export interface TestResult {
  id: string;
  type: string;
  label: string;
  target: string;
  status: ResultStatus;
  ms: number;
  detail: string;
  data?: Record<string, unknown>;
  apps?: string[];
}

export interface DeviceReport {
  device: string;
  planId: string;
  planName?: string;
  runAs?: string;
  os?: string;
  startedAt?: string;
  proxy?: { user?: string | null; winhttp?: string | null; pac?: string | null };
  counts: { pass: number; warn: number; fail: number };
  results: TestResult[];
  /** "file" = full JSON result; "summary" = only the Intune detection output line. */
  source: "file" | "summary";
}

const asStatus = (s: unknown): ResultStatus => (s === "pass" || s === "warn" || s === "fail" ? s : "fail");

function fromJson(o: any): DeviceReport | null {
  if (!o || o.schema !== RESULT_SCHEMA || !Array.isArray(o.results)) return null;
  // PowerShell 5.1 ConvertTo-Json writes a one-element array as an object in some places; normalise.
  const list = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : v == null || v === "" ? [] : [String(v)]);
  const results: TestResult[] = o.results.map((r: any) => ({
    id: String(r.id ?? ""),
    type: String(r.type ?? ""),
    label: String(r.label ?? ""),
    target: String(r.target ?? ""),
    status: asStatus(r.status),
    ms: Number(r.ms ?? 0),
    detail: String(r.detail ?? ""),
    data: r.data && typeof r.data === "object" ? r.data : undefined,
    apps: list(r.apps),
  }));
  return {
    device: String(o.device ?? "unknown"),
    planId: String(o.planId ?? ""),
    planName: o.planName,
    runAs: o.runAs,
    os: o.os,
    startedAt: o.startedAt,
    proxy: o.proxy,
    counts: {
      pass: results.filter((r) => r.status === "pass").length,
      warn: results.filter((r) => r.status === "warn").length,
      fail: results.filter((r) => r.status === "fail").length,
    },
    results,
    source: "file",
  };
}

/** Parse one F360|v1|... summary line, as copied from Intune's detection output column or an export CSV. */
export function parseSummaryLine(line: string, plan?: ConnectivityPlan | null): DeviceReport | null {
  const m = line.match(/F360\|v1\|plan=([^|]*)\|device=([^|]*)\|pass=(\d+)\|warn=(\d+)\|fail=(\d+)\|([^"\r\n]*)/);
  if (!m) return null;
  const [, planId, device, pass, warn, fail, rest] = m;
  const byId = new Map((plan?.id === planId ? plan.tests : []).map((t) => [t.id, t]));
  const results: TestResult[] = rest
    .split(",")
    .map((x) => x.trim())
    .filter((x) => /^(warn|fail):t\d+:/.test(x))
    .map((x) => {
      const [status, id, ...target] = x.split(":");
      const t = byId.get(id);
      return { id, type: t?.type ?? "", label: t?.label ?? id, target: target.join(":"), status: asStatus(status), ms: 0, detail: "Only the summary line is available. Collect the result file from the device for details.", apps: t?.apps ?? [] };
    });
  return { device, planId, counts: { pass: +pass, warn: +warn, fail: +fail }, results, source: "summary" };
}

/**
 * Read whatever was pasted or dropped: one or more JSON result files (an object, an array, or objects back to back)
 * or any text holding F360| summary lines (Intune detection output, a CSV export). Newest run per device wins.
 */
export function parseResults(texts: string[], plan?: ConnectivityPlan | null): { reports: DeviceReport[]; errors: string[] } {
  const reports: DeviceReport[] = [];
  const errors: string[] = [];
  for (const raw of texts) {
    const text = raw.replace(/^﻿/, "").trim();
    if (!text) continue;
    let parsed = false;
    if (text.startsWith("{") || text.startsWith("[")) {
      for (const chunk of splitJson(text)) {
        try {
          const v = JSON.parse(chunk);
          for (const o of Array.isArray(v) ? v : [v]) {
            const r = fromJson(o);
            if (r) {
              reports.push(r);
              parsed = true;
            }
          }
        } catch {
          /* fall through to summary lines */
        }
      }
    }
    if (!parsed) {
      for (const line of text.split(/\r?\n/)) {
        const r = parseSummaryLine(line, plan);
        if (r) {
          reports.push(r);
          parsed = true;
        }
      }
    }
    if (!parsed) errors.push(`Nothing recognisable in: ${text.slice(0, 60)}${text.length > 60 ? "…" : ""}`);
  }
  const latest = new Map<string, DeviceReport>();
  for (const r of reports) {
    const key = r.device.toLowerCase();
    const cur = latest.get(key);
    const better = !cur || (r.source === "file" && cur.source === "summary") || (r.source === cur.source && (r.startedAt ?? "") >= (cur.startedAt ?? ""));
    if (better) latest.set(key, r);
  }
  return { reports: [...latest.values()].sort((a, b) => b.counts.fail - a.counts.fail || b.counts.warn - a.counts.warn || a.device.localeCompare(b.device)), errors };
}

/** Split concatenated JSON documents ({..}{..} or one per line) by brace depth, ignoring braces in strings. */
export function splitJson(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = -1;
  let inStr = false;
  let esc = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === "{" || c === "[") {
      if (depth === 0) start = i;
      depth++;
    } else if (c === "}" || c === "]") {
      depth--;
      if (depth === 0 && start >= 0) {
        out.push(text.slice(start, i + 1));
        start = -1;
      }
    }
  }
  return out.length ? out : [text];
}

/** Per-test roll-up across devices: which targets fail where. */
export function summarizeByTest(reports: DeviceReport[]) {
  const map = new Map<string, { key: string; label: string; target: string; apps: string[]; pass: string[]; warn: string[]; fail: string[] }>();
  for (const r of reports) {
    for (const t of r.results) {
      const key = `${t.id}|${t.target}`;
      let row = map.get(key);
      if (!row) {
        row = { key, label: t.label, target: t.target, apps: t.apps ?? [], pass: [], warn: [], fail: [] };
        map.set(key, row);
      }
      row[t.status].push(r.device);
    }
  }
  return [...map.values()].sort((a, b) => b.fail.length - a.fail.length || b.warn.length - a.warn.length || a.key.localeCompare(b.key, undefined, { numeric: true }));
}

/** Plain-language advice for the commonest failures, keyed on what the script reports. */
export function adviceFor(t: TestResult): string | null {
  const d = t.detail.toLowerCase();
  if (t.type === "clock" && t.status !== "pass") return "Fix time sync: w32tm /resync /force as admin, and check the device's time source. Entra rejects tokens and SAML assertions more than 5 minutes out.";
  if (t.type === "tls" && t.data && (t.data as any).inspected) return "Exclude this host from TLS inspection on the proxy or security product. Microsoft does not support inspecting Entra sign-in traffic, and token binding and certificate-based sign-in break under it.";
  if (t.type === "tls" && d.includes("not trusted")) return "The device does not trust the certificate chain. Either a proxy is re-signing traffic with a root this device lacks, or the server sends an incomplete chain.";
  if (t.type === "dns" && t.status === "fail") return "The name does not resolve here. Check the device's DNS servers, split-brain DNS zones and any DNS filtering service.";
  if (t.type === "tcp" && t.status === "fail") return "Port 443 is blocked. Check the firewall or proxy allow list for this host; with a proxy, check that this device's run-as account (SYSTEM uses the WinHTTP proxy) is configured.";
  if (t.type === "http" && d.includes("does not contain")) return "Something answered in place of the real server, usually a proxy block page or captive portal. Allow-list the URL.";
  if (t.type === "http" && d.includes("issuer")) return "The issuer does not match what the app expects. Check the tenant ID or authority configured in the app.";
  return null;
}

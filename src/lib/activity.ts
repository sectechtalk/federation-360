// Activity import: who signed in to which app, when, and how (interactively or by a silent token refresh), what
// provisioning (SCIM) sent to each app, and the audit events that matter when someone leaves. Everything is read from
// files or a read-only Graph scan and folded into a small per-user, per-app summary that User lookup reads. Raw logs
// are never kept; only the summary is saved in this browser.
//
// Accepted inputs (all read in the browser, nothing is uploaded):
//   - Entra admin center Sign-in logs > Download > JSON, from any of the four tabs: User sign-ins (interactive),
//     User sign-ins (non-interactive), Service principal sign-ins, Managed identity sign-ins. Free tenants keep 7 days.
//   - Graph auditLogs/signIns (v1.0 or beta), auditLogs/directoryAudits, auditLogs/provisioning (provisioning needs P1)
//   - Log Analytics SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs,
//     AADManagedIdentitySignInLogs, AuditLogs and AADProvisioningLogs exported as JSON
//   - the f360-activity file Export-F360Activity.ps1 writes, and the f360-signins file Export-F360SignIns.ps1 writes
//   - Entity 360's timeline CSV export (entity-360-<view>-<user id>-<date>.csv): its Sign-ins rows
//
// Refresh cadence: an app that keeps a refresh token asks Entra for a new access token shortly before the old one
// expires. Those requests are the non-interactive sign-ins, so the gap between one person's non-interactive
// sign-ins to one app shows how often that app really goes back to Entra.

export const ACTIVITY_FORMAT = "f360-activity";
export const ACTIVITY_EXPORT_FORMAT = "f360-activity-export";

export type SignInKind = "interactive" | "nonInteractive" | "servicePrincipal" | "managedIdentity";

export interface ActivitySignIn {
  time: number;
  kind: SignInKind;
  /** Lower-case UPN; for service principal and managed identity sign-ins, the principal's name. */
  user: string;
  userId: string;
  userName: string;
  app: string;
  appId: string;
  resource: string;
  success: boolean;
  errorCode: number;
  /** oAuth2, saml20, wsFed, deviceCode, ropc, none, or "" when the log doesn't say. */
  protocol: string;
  /** primaryRefreshToken, refreshToken, saml11, ... (beta and Log Analytics), or "". */
  tokenType: string;
  device: string;
  ip: string;
}

export interface ActivityProvisioning {
  time: number;
  /** create, update, delete, disable, stagedDelete, other. */
  action: string;
  /** success, failure, skipped, warning. */
  status: string;
  app: string;
  spId: string;
  user: string;
  userId: string;
  error: string;
}

export interface ActivityAudit {
  time: number;
  activity: string;
  actor: string;
  user: string;
  userId: string;
  target: string;
  /** The user target's changed properties as "Name=new value" pairs, e.g. "AccountEnabled=[false]". */
  changes: string;
}

export interface ParsedActivity {
  signIns: ActivitySignIn[];
  provisioning: ActivityProvisioning[];
  audits: ActivityAudit[];
  /** One line per file, for the page to show. */
  sources: string[];
}

// ------------------------------------------------------------------ summary (what is saved)

export interface UserAppActivity {
  app: string;
  appId: string;
  lastInteractive?: number;
  lastSilent?: number;
  lastFailure?: { time: number; code: number };
  interactive: number;
  silent: number;
  protocols: string[];
  /** Devices seen on sign-ins (name or ID). */
  devices: string[];
  /** Devices that signed in with a Primary Refresh Token (device SSO). */
  prtDevices: string[];
  lastIp?: string;
  provisioning?: { time: number; action: string; status: string; error?: string };
}

export interface UserActivity {
  /** Lower-case UPN, or "id:<object id>" / "name:<display name>" when the source had no UPN. */
  key: string;
  upn: string;
  id: string;
  name: string;
  apps: Record<string, UserAppActivity>;
  disabledAt?: number;
  enabledAt?: number;
  sessionsRevokedAt?: number;
  passwordChangedAt?: number;
  removedFrom: { app: string; time: number }[];
  consents: { app: string; time: number }[];
}

export interface AppCadence {
  app: string;
  appId: string;
  /** Minutes between silent refreshes, one sample per gap (capped). */
  samples: number[];
  users: number;
}

export interface WorkloadActivity {
  name: string;
  kind: "servicePrincipal" | "managedIdentity";
  appId: string;
  last: number;
  count: number;
  resources: string[];
}

export interface ActivitySummary {
  format: typeof ACTIVITY_FORMAT;
  version: 1;
  updatedAt: string;
  from?: number;
  to?: number;
  sources: string[];
  counts: Record<SignInKind | "provisioning" | "audit", number>;
  users: Record<string, UserActivity>;
  cadence: Record<string, AppCadence>;
  workloads: Record<string, WorkloadActivity>;
  example?: boolean;
}

export const emptySummary = (): ActivitySummary => ({
  format: ACTIVITY_FORMAT,
  version: 1,
  updatedAt: new Date(0).toISOString(),
  sources: [],
  counts: { interactive: 0, nonInteractive: 0, servicePrincipal: 0, managedIdentity: 0, provisioning: 0, audit: 0 },
  users: {},
  cadence: {},
  workloads: {},
});

// ------------------------------------------------------------------ reading rows

const lower = (v: unknown) => String(v ?? "").trim().toLowerCase();
const str = (v: unknown) => String(v ?? "").trim();
const obj = (v: unknown): any => {
  if (!v) return {};
  if (typeof v === "string") {
    try {
      return JSON.parse(v);
    } catch {
      return {};
    }
  }
  return v;
};

function rowsOf(j: any): any[] {
  if (Array.isArray(j)) return j;
  if (Array.isArray(j?.value)) return j.value;
  if (Array.isArray(j?.Tables?.[0]?.Rows) && Array.isArray(j.Tables[0].Columns)) {
    const cols = j.Tables[0].Columns.map((c: any) => c.ColumnName ?? c.name);
    return j.Tables[0].Rows.map((r: any[]) => Object.fromEntries(cols.map((c: string, i: number) => [c, r[i]])));
  }
  return [];
}

const LA_KIND: Record<string, SignInKind> = {
  SigninLogs: "interactive",
  NonInteractiveUserSignInLogs: "nonInteractive",
  AADNonInteractiveUserSignInLogs: "nonInteractive",
  ServicePrincipalSignInLogs: "servicePrincipal",
  AADServicePrincipalSignInLogs: "servicePrincipal",
  ManagedIdentitySignInLogs: "managedIdentity",
  AADManagedIdentitySignInLogs: "managedIdentity",
};

/** Which of the four tabs a Graph sign-in came from. Beta has signInEventTypes; v1.0 and portal downloads don't. */
function graphKind(r: any, hint?: SignInKind): SignInKind {
  const types: string[] = r.signInEventTypes ?? [];
  // A tagged export array or a file named after its tab wins over guessing.
  if (hint && hint !== "interactive") return hint;
  if (types.includes("managedIdentity") || r.managedIdentityType && r.managedIdentityType !== "none") return "managedIdentity";
  if (types.includes("servicePrincipal") || (!r.userPrincipalName && r.servicePrincipalId)) return "servicePrincipal";
  if (types.includes("nonInteractiveUser") || r.isInteractive === false) return "nonInteractive";
  if (types.includes("interactiveUser")) return "interactive";
  return hint ?? "interactive";
}

const isGraphSignIn = (r: any) => r && "createdDateTime" in r && ("appDisplayName" in r || "appId" in r) && !("activityDisplayName" in r);
const isLaSignIn = (r: any) => r && ("ResultType" in r || "IPAddress" in r) && ("AppDisplayName" in r || "AppId" in r || "ServicePrincipalName" in r);
const isGraphAudit = (r: any) => r && "activityDisplayName" in r;
const isLaAudit = (r: any) => r && "OperationName" in r && "TargetResources" in r && !("ProvisioningAction" in r);
const isGraphProv = (r: any) => r && "provisioningAction" in r;
const isLaProv = (r: any) => r && ("ProvisioningAction" in r || r.Category === "ProvisioningLogs");

export function toActivitySignIn(r: any, hint?: SignInKind): ActivitySignIn | null {
  if (isGraphSignIn(r)) {
    const t = Date.parse(r.createdDateTime);
    if (!Number.isFinite(t)) return null;
    const kind = graphKind(r, hint);
    const workload = kind === "servicePrincipal" || kind === "managedIdentity";
    const code = Number(r.status?.errorCode ?? 0) || 0;
    return {
      time: t,
      kind,
      user: workload ? str(r.servicePrincipalName || r.appDisplayName) : lower(r.userPrincipalName),
      userId: str(workload ? r.servicePrincipalId : r.userId),
      userName: str(workload ? r.servicePrincipalName || r.appDisplayName : r.userDisplayName),
      app: str(r.appDisplayName),
      appId: lower(r.appId),
      resource: str(r.resourceDisplayName),
      success: code === 0,
      errorCode: code,
      protocol: str(r.authenticationProtocol === "none" ? "" : r.authenticationProtocol),
      tokenType: str(r.incomingTokenType === "none" ? "" : r.incomingTokenType),
      device: str(r.deviceDetail?.displayName || r.deviceDetail?.deviceId),
      ip: str(r.ipAddress),
    };
  }
  if (isLaSignIn(r)) {
    const t = Date.parse(r.TimeGenerated ?? r.CreatedDateTime);
    if (!Number.isFinite(t)) return null;
    const kind = LA_KIND[r.Category] ?? LA_KIND[r.Type] ?? (r.IsInteractive === false || r.IsInteractive === "false" ? "nonInteractive" : hint ?? "interactive");
    const workload = kind === "servicePrincipal" || kind === "managedIdentity";
    const dev = obj(r.DeviceDetail);
    const code = Number(r.ResultType ?? 0) || 0;
    return {
      time: t,
      kind,
      user: workload ? str(r.ServicePrincipalName || r.AppDisplayName) : lower(r.UserPrincipalName),
      userId: str(workload ? r.ServicePrincipalId : r.UserId),
      userName: str(workload ? r.ServicePrincipalName : r.UserDisplayName),
      app: str(r.AppDisplayName ?? r.ServicePrincipalName),
      appId: lower(r.AppId),
      resource: str(r.ResourceDisplayName),
      success: code === 0,
      errorCode: code,
      protocol: str(r.AuthenticationProtocol === "none" ? "" : r.AuthenticationProtocol),
      tokenType: str(r.IncomingTokenType === "none" ? "" : r.IncomingTokenType),
      device: str(dev.displayName || dev.deviceId),
      ip: str(r.IPAddress),
    };
  }
  return null;
}

export function toActivityAudit(r: any): ActivityAudit | null {
  const graph = isGraphAudit(r);
  const t = Date.parse(graph ? r.activityDateTime : r.TimeGenerated);
  if (!Number.isFinite(t)) return null;
  const by = obj(graph ? r.initiatedBy : r.InitiatedBy);
  const targets: any[] = (graph ? r.targetResources : obj(r.TargetResources)) ?? [];
  const u = targets.find((x) => x?.userPrincipalName) ?? targets.find((x) => lower(x?.type) === "user");
  const other = targets.find((x) => lower(x?.type) !== "user" && x?.displayName) ?? targets.find((x) => x !== u);
  return {
    time: t,
    activity: str(graph ? r.activityDisplayName : r.OperationName),
    actor: lower(by?.user?.userPrincipalName) || str(by?.app?.displayName),
    user: lower(u?.userPrincipalName),
    userId: str(u?.id),
    target: str(other?.displayName),
    changes: (u?.modifiedProperties ?? []).map((m: any) => `${m?.displayName}=${m?.newValue ?? ""}`).join("; "),
  };
}

export function toActivityProvisioning(r: any): ActivityProvisioning | null {
  if (isGraphProv(r)) {
    const t = Date.parse(r.activityDateTime);
    if (!Number.isFinite(t)) return null;
    const src = r.sourceIdentity ?? {};
    const details = src.details ?? {};
    return {
      time: t,
      action: str(r.provisioningAction),
      status: str(r.provisioningStatusInfo?.status),
      app: str(r.servicePrincipal?.displayName),
      spId: str(r.servicePrincipal?.id),
      user: lower(details.UserPrincipalName ?? details.userPrincipalName ?? (String(src.displayName ?? "").includes("@") ? src.displayName : "")),
      userId: str(src.id),
      error: str(r.provisioningStatusInfo?.errorInformation?.reason || r.provisioningStatusInfo?.errorInformation?.errorCode),
    };
  }
  const t = Date.parse(r.TimeGenerated ?? r.ActivityDateTime);
  if (!Number.isFinite(t)) return null;
  const src = obj(r.SourceIdentity);
  const sp = obj(r.ServicePrincipal);
  const status = obj(r.ProvisioningStatusInfo);
  return {
    time: t,
    action: str(r.ProvisioningAction),
    status: str(status.status ?? r.ResultType),
    app: str(sp.displayName ?? r.ServicePrincipalName),
    spId: str(sp.id),
    user: lower(String(src.displayName ?? "").includes("@") ? src.displayName : ""),
    userId: str(src.id),
    error: str(status.errorInformation?.reason),
  };
}

/** Entity 360's timeline CSV. The user isn't a column; it's in the file name (entity-360-<view>-<id>-<date>.csv). */
export function readEntity360Csv(name: string, text: string): ActivitySignIn[] {
  const rows = parseCsv(text.replace(/^﻿/, ""));
  const head = rows.shift()?.map((h) => h.trim()) ?? [];
  const col = (h: string) => head.indexOf(h);
  const [ti, ai, ci, ri, ac] = [col("Time UTC"), col("Activity"), col("Category"), col("Result"), col("Actor")];
  if (ti < 0 || ai < 0 || ci < 0) return [];
  const id = /entity-360-[a-z]+-([0-9a-f-]{36})-/i.exec(name)?.[1] ?? "";
  const ipi = col("IP");
  return rows
    .filter((r) => /sign-?in/i.test(r[ci] ?? ""))
    .map((r) => {
      const time = Date.parse(r[ti]);
      const app = (r[ai] ?? "").replace(/\s+sign-in$/i, "").trim();
      const ok = /^success/i.test(r[ri] ?? "");
      return {
        time,
        kind: "interactive" as const,
        user: "",
        userId: id,
        userName: (r[ac] ?? "").trim(),
        app,
        appId: "",
        resource: "",
        success: ok,
        errorCode: ok ? 0 : -1,
        protocol: "",
        tokenType: "",
        device: "",
        ip: ipi >= 0 ? (r[ipi] ?? "").trim() : "",
      };
    })
    .filter((s) => Number.isFinite(s.time) && s.app);
}

function parseCsv(text: string): string[][] {
  const out: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (c === '"') q = false;
      else cell += c;
    } else if (c === '"') q = true;
    else if (c === ",") {
      row.push(cell);
      cell = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(cell);
      out.push(row);
      row = [];
      cell = "";
    } else cell += c;
  }
  if (cell || row.length) {
    row.push(cell);
    out.push(row);
  }
  return out.filter((r) => r.some((x) => x.trim()));
}

/** Guess the sign-in tab from a portal download's file name, e.g. NonInteractiveSignIns_2026-11-24.json. */
function hintFromName(name: string): SignInKind | undefined {
  const n = name.toLowerCase();
  if (/non-?interactive/.test(n)) return "nonInteractive";
  if (/service-?principal/.test(n)) return "servicePrincipal";
  if (/managed-?identit/.test(n) || /\bmsi\b/.test(n)) return "managedIdentity";
  if (/interactive/.test(n)) return "interactive";
  return undefined;
}

/** Reads one file. Throws a plain-words error when it found nothing usable. */
export function readActivityFile(name: string, text: string): ParsedActivity {
  if (/\.csv$/i.test(name) || /^﻿?"?Time UTC"?,/.test(text)) {
    const signIns = readEntity360Csv(name, text);
    if (!signIns.length) throw new Error(`${name} has no Entity 360 sign-in rows. Export the timeline from Entity 360 as CSV and load that file.`);
    return { signIns, provisioning: [], audits: [], sources: [`${name}: ${signIns.length} sign-ins from Entity 360`] };
  }
  let j: any;
  try {
    j = JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    throw new Error(`${name} isn't JSON or CSV. In the Entra admin center use Sign-in logs > Download > Download JSON, or run Export-F360Activity.ps1.`);
  }
  const hint = hintFromName(name);
  let signRows: [any, SignInKind | undefined][] = [];
  let auditRows: any[] = [];
  let provRows: any[] = [];
  let from = "";
  if (j?.format === ACTIVITY_EXPORT_FORMAT || j?.format === "f360-signins") {
    const tag = (rows: any[] | undefined, k: SignInKind | undefined) => (rows ?? []).map((r): [any, SignInKind | undefined] => [r, k]);
    const exp = j.format === ACTIVITY_EXPORT_FORMAT;
    signRows = [...tag(j.signIns, exp ? "interactive" : undefined), ...tag(j.nonInteractive, "nonInteractive"), ...tag(j.servicePrincipal, "servicePrincipal"), ...tag(j.managedIdentity, "managedIdentity")];
    auditRows = j.audits ?? [];
    provRows = j.provisioning ?? [];
    from = j.collector === "sample" ? ", made-up sample" : j.format === "f360-signins" ? ", from Export-F360SignIns.ps1" : ", from Export-F360Activity.ps1";
  } else {
    const rows = rowsOf(j);
    signRows = rows.filter((r) => isGraphSignIn(r) || isLaSignIn(r)).map((r): [any, SignInKind | undefined] => [r, hint]);
    auditRows = rows.filter((r) => isGraphAudit(r) || isLaAudit(r));
    provRows = rows.filter((r) => isGraphProv(r) || isLaProv(r));
  }
  const signIns = signRows.map(([r, k]) => toActivitySignIn(r, k)).filter(Boolean) as ActivitySignIn[];
  const audits = auditRows.map(toActivityAudit).filter(Boolean) as ActivityAudit[];
  const provisioning = provRows.map(toActivityProvisioning).filter(Boolean) as ActivityProvisioning[];
  if (!signIns.length && !audits.length && !provisioning.length)
    throw new Error(`${name} has no sign-in, audit or provisioning events Federation 360 recognises. It expects Entra logs as JSON (Graph or Log Analytics columns).`);
  const byKind = (k: SignInKind) => signIns.filter((s) => s.kind === k).length;
  const parts = [
    byKind("interactive") && `${byKind("interactive")} interactive sign-ins`,
    byKind("nonInteractive") && `${byKind("nonInteractive")} silent refreshes`,
    byKind("servicePrincipal") && `${byKind("servicePrincipal")} service principal sign-ins`,
    byKind("managedIdentity") && `${byKind("managedIdentity")} managed identity sign-ins`,
    provisioning.length && `${provisioning.length} provisioning events`,
    audits.length && `${audits.length} audit events`,
  ].filter(Boolean);
  return { signIns, audits, provisioning, sources: [`${name}: ${parts.join(", ")}${from}`] };
}

// ------------------------------------------------------------------ folding into the summary

const MAX_SAMPLES = 400;
const MAX_LIST = 8;
/** Silent sign-ins closer together than this are one refresh (an app often asks for several resources at once). */
const BURST_MINUTES = 2;

const push = (list: string[], v: string) => {
  if (v && !list.includes(v) && list.length < MAX_LIST) list.push(v);
};

function userKey(s: { user: string; userId: string; userName?: string }): string {
  if (s.user && s.user.includes("@")) return s.user;
  if (s.userId) return `id:${s.userId.toLowerCase()}`;
  if (s.userName) return `name:${s.userName.toLowerCase()}`;
  return "";
}

function getUser(sum: ActivitySummary, key: string, s: { user: string; userId: string; userName?: string }): UserActivity {
  // A user first seen by ID (Entity 360) is joined to their UPN entry once a log shows both.
  const idKey = s.userId ? `id:${s.userId.toLowerCase()}` : "";
  if (key !== idKey && idKey && sum.users[idKey] && !sum.users[key]) {
    sum.users[key] = { ...sum.users[idKey], key, upn: s.user };
    delete sum.users[idKey];
  }
  const u = (sum.users[key] ??= { key, upn: s.user.includes("@") ? s.user : "", id: s.userId, name: s.userName ?? "", apps: {}, removedFrom: [], consents: [] });
  if (!u.upn && s.user.includes("@")) u.upn = s.user;
  if (!u.id && s.userId) u.id = s.userId;
  if (!u.name && s.userName) u.name = s.userName;
  return u;
}

const appKey = (app: string, appId: string) => (appId ? appId.toLowerCase() : `name:${app.toLowerCase()}`);
const max = (a: number | undefined, b: number) => (a === undefined || b > a ? b : a);

const DISABLE = /^(disable account|update user)$/i;
const REVOKE = /revoke.*(sign-?in|session)|invalidate.*refresh/i;

export function foldActivity(prev: ActivitySummary, add: ParsedActivity, now = new Date()): ActivitySummary {
  const sum: ActivitySummary = JSON.parse(JSON.stringify(prev));
  sum.sources = [...sum.sources, ...add.sources];
  sum.updatedAt = now.toISOString();
  const times: number[] = [];

  const silentByUserApp = new Map<string, number[]>();
  for (const s of add.signIns) {
    times.push(s.time);
    sum.counts[s.kind]++;
    if (s.kind === "servicePrincipal" || s.kind === "managedIdentity") {
      const k = `${s.kind}:${s.appId || s.user.toLowerCase()}`;
      const w = (sum.workloads[k] ??= { name: s.userName || s.app, kind: s.kind, appId: s.appId, last: s.time, count: 0, resources: [] });
      w.last = Math.max(w.last, s.time);
      w.count++;
      push(w.resources, s.resource);
      continue;
    }
    const key = userKey(s);
    if (!key) continue;
    const u = getUser(sum, key, s);
    const ak = appKey(s.app, s.appId);
    const a = (u.apps[ak] ??= { app: s.app, appId: s.appId, interactive: 0, silent: 0, protocols: [], devices: [], prtDevices: [] });
    if (!a.app && s.app) a.app = s.app;
    if (!s.success) {
      if (!a.lastFailure || s.time > a.lastFailure.time) a.lastFailure = { time: s.time, code: s.errorCode };
      continue;
    }
    if (s.kind === "interactive") {
      a.interactive++;
      a.lastInteractive = max(a.lastInteractive, s.time);
    } else {
      a.silent++;
      a.lastSilent = max(a.lastSilent, s.time);
      const k = `${key}|${ak}`;
      (silentByUserApp.get(k) ?? silentByUserApp.set(k, []).get(k)!).push(s.time);
    }
    push(a.protocols, s.protocol);
    push(a.devices, s.device);
    if (/primaryRefreshToken/i.test(s.tokenType)) push(a.prtDevices, s.device || "a device");
    if (s.ip) a.lastIp = s.ip;
  }

  // Refresh cadence per app, from the gaps between one person's silent refreshes.
  for (const [k, list] of silentByUserApp) {
    const [, ak] = k.split("|");
    const sorted = [...new Set(list)].sort((x, y) => x - y);
    const gaps: number[] = [];
    let last = sorted[0];
    for (const t of sorted.slice(1)) {
      const g = (t - last) / 60000;
      if (g >= BURST_MINUTES) {
        gaps.push(Math.round(g));
        last = t;
      }
    }
    const any = Object.values(sum.users).find((u) => u.apps[ak])?.apps[ak];
    const c = (sum.cadence[ak] ??= { app: any?.app ?? ak, appId: any?.appId ?? "", samples: [], users: 0 });
    c.users++;
    c.samples = [...c.samples, ...gaps].slice(-MAX_SAMPLES);
  }

  for (const p of add.provisioning) {
    times.push(p.time);
    sum.counts.provisioning++;
    const key = userKey({ user: p.user, userId: p.userId });
    if (!key) continue;
    const u = getUser(sum, key, { user: p.user, userId: p.userId });
    const ak = Object.keys(u.apps).find((k) => u.apps[k].app.toLowerCase() === p.app.toLowerCase()) ?? `name:${p.app.toLowerCase()}`;
    const a = (u.apps[ak] ??= { app: p.app, appId: "", interactive: 0, silent: 0, protocols: [], devices: [], prtDevices: [] });
    if (!a.provisioning || p.time > a.provisioning.time) a.provisioning = { time: p.time, action: p.action, status: p.status, error: p.error || undefined };
  }

  for (const e of add.audits) {
    times.push(e.time);
    sum.counts.audit++;
    const key = userKey({ user: e.user, userId: e.userId });
    if (!key) continue;
    const u = getUser(sum, key, { user: e.user, userId: e.userId });
    const act = e.activity;
    if (/^disable account$/i.test(act) || (DISABLE.test(act) && /accountenabled=\W*false/i.test(e.changes))) u.disabledAt = max(u.disabledAt, e.time);
    else if (/^enable account$/i.test(act)) u.enabledAt = max(u.enabledAt, e.time);
    else if (REVOKE.test(act)) u.sessionsRevokedAt = max(u.sessionsRevokedAt, e.time);
    else if (/(reset|change) (user )?password/i.test(act)) u.passwordChangedAt = max(u.passwordChangedAt, e.time);
    else if (/^remove app role assignment from user$/i.test(act)) u.removedFrom = [...u.removedFrom, { app: e.target, time: e.time }].slice(-20);
    else if (/^consent to application$/i.test(act)) u.consents = [...u.consents, { app: e.target, time: e.time }].slice(-20);
  }

  if (times.length) {
    const lo = Math.min(...times);
    const hi = Math.max(...times);
    sum.from = sum.from === undefined ? lo : Math.min(sum.from, lo);
    sum.to = sum.to === undefined ? hi : Math.max(sum.to, hi);
  }
  return sum;
}

// ------------------------------------------------------------------ reading the summary

export function median(xs: number[]): number | undefined {
  if (!xs.length) return undefined;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : Math.round((s[m - 1] + s[m]) / 2);
}

export function percentile(xs: number[], p: number): number | undefined {
  if (!xs.length) return undefined;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)];
}

export interface CadenceRow {
  key: string;
  app: string;
  appId: string;
  medianMinutes?: number;
  p90Minutes?: number;
  samples: number;
  users: number;
  /** Plain words about what the number means. */
  reading: string;
}

export function cadenceRows(sum: ActivitySummary): CadenceRow[] {
  return Object.entries(sum.cadence)
    .map(([key, c]) => {
      const med = median(c.samples);
      const p90 = percentile(c.samples, 90);
      const reading =
        med === undefined
          ? "Only one silent refresh per person in these logs; load a longer period to measure it."
          : med <= 100
            ? "Refreshes about once per access token lifetime: it keeps going back to Entra, so a disable is noticed within about an hour."
            : med <= 24 * 60
              ? "Refreshes less often than its token lifetime, likely only while someone is using it."
              : "Rarely goes back to Entra. Its own session decides how long access lasts.";
      return { key, app: c.app, appId: c.appId, medianMinutes: med, p90Minutes: p90, samples: c.samples.length, users: c.users, reading };
    })
    .sort((a, b) => b.samples - a.samples || a.app.localeCompare(b.app));
}

/** Find people by UPN, name or object ID (partial, case-insensitive). */
export function findUsers(sum: ActivitySummary, q: string): UserActivity[] {
  const n = q.trim().toLowerCase();
  if (!n) return [];
  return Object.values(sum.users)
    .filter((u) => [u.upn, u.name, u.id, u.key].some((v) => v && v.toLowerCase().includes(n)))
    .sort((a, b) => (a.upn || a.name).localeCompare(b.upn || b.name));
}

export function parseSummary(text: string): ActivitySummary {
  const j = JSON.parse(text);
  if (j?.format !== ACTIVITY_FORMAT) throw new Error("That isn't a saved activity summary.");
  return { ...emptySummary(), ...j };
}

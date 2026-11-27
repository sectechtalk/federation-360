// Turns sign-in and audit log files into one simple shape the detection rules read.
//
// Accepted inputs (all read in the browser, nothing is uploaded):
//   - Graph sign-ins (v1.0 or beta): Get-MgAuditLogSignIn | ConvertTo-Json, Graph Explorer ({ value: [...] }),
//     or the Entra admin center's Sign-in logs > Download > JSON (works on Entra ID Free, last 7 days)
//   - Log Analytics / Sentinel SigninLogs and AADNonInteractiveUserSignInLogs exported as JSON (PascalCase columns)
//   - Graph directory audits (auditLogs/directoryAudits) and Log Analytics AuditLogs, for the rules that need them
//   - the f360-signins file Export-F360SignIns.ps1 writes, which holds both
//   - Entity 360's timeline CSV export (entity-360-<view>-<user id>-<date>.csv): its sign-in rows, which have time, app,
//     result, IP and the person's display name, but no country, error code or risk level
//   - one sign-in copied from Entity 360's "Raw source evidence" (a single Graph sign-in object)
//   - sign-ins and audits read from the tenant through Graph on the Detections page (live.ts)
export const SIGNINS_FORMAT = "f360-signins";

export interface SignInEvent {
  time: number;
  /** Lower-case user principal name. */
  user: string;
  ip: string;
  /** Two-letter country code, or "" when the log has none. */
  country: string;
  city: string;
  interactive: boolean;
  app: string;
  client: string;
  /** 0 = success. 50126 = wrong password. 500121 = MFA not completed (denied, no answer, fraud reported). */
  errorCode: number;
  details: string;
  /** Sign-in session ID (Graph beta and Log Analytics have it; Graph v1.0 doesn't). */
  session: string;
  /** Entra ID Protection's risk level during sign-in: none, low, medium, high, hidden, or "" when the log has none (needs P2). */
  risk?: string;
  /** The device's display name from deviceDetail, when Entra knows the device (joined, registered or compliant). */
  device?: string;
  /** Where the event came from, e.g. "Entity 360" or "Graph", for the evidence trail. */
  from?: string;
}

export interface AuditEvent {
  time: number;
  activity: string;
  /** Who did it (lower-case UPN), or the app name when an app did it. */
  actor: string;
  /** The user it was done to (lower-case UPN), when there is one. */
  targetUser: string;
  /** The app or object it was done to, e.g. the app name for "Consent to application". */
  target: string;
}

export interface LoadedLogs {
  signIns: SignInEvent[];
  audits: AuditEvent[];
  /** What each file turned out to be, for the page to show. */
  sources: string[];
}

const lower = (v: unknown) => String(v ?? "").trim().toLowerCase();
const parseLoc = (v: unknown): any => {
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
  if (j && typeof j === "object" && ("createdDateTime" in j || "activityDisplayName" in j)) return [j]; // one record pasted from Entity 360
  if (Array.isArray(j?.value)) return j.value;
  if (Array.isArray(j?.Tables?.[0]?.Rows) && Array.isArray(j.Tables[0].Columns)) {
    // Log Analytics API shape: { Tables: [{ Columns: [{ ColumnName }], Rows: [[...]] }] }
    const cols = j.Tables[0].Columns.map((c: any) => c.ColumnName ?? c.name);
    return j.Tables[0].Rows.map((r: any[]) => Object.fromEntries(cols.map((c: string, i: number) => [c, r[i]])));
  }
  return [];
}

const isSignIn = (r: any) => r && (("userPrincipalName" in r && ("createdDateTime" in r || "status" in r)) || ("UserPrincipalName" in r && ("ResultType" in r || "IPAddress" in r)));
const isAudit = (r: any) => r && ("activityDisplayName" in r || ("OperationName" in r && "TargetResources" in r));

export function toSignIn(r: any): SignInEvent | null {
  if ("createdDateTime" in r || "status" in r) {
    const t = Date.parse(r.createdDateTime);
    if (!Number.isFinite(t)) return null;
    return {
      time: t,
      user: lower(r.userPrincipalName),
      ip: String(r.ipAddress ?? ""),
      country: String(r.location?.countryOrRegion ?? "").toUpperCase(),
      city: String(r.location?.city ?? ""),
      interactive: r.isInteractive !== false,
      app: String(r.appDisplayName ?? ""),
      client: String(r.clientAppUsed ?? ""),
      errorCode: Number(r.status?.errorCode ?? 0) || 0,
      details: [r.status?.failureReason, r.status?.additionalDetails].filter(Boolean).join(" · "),
      session: String(r.sessionId ?? ""),
      risk: lower(r.riskLevelDuringSignIn),
      device: String(r.deviceDetail?.displayName ?? ""),
    };
  }
  const t = Date.parse(r.TimeGenerated ?? r.CreatedDateTime);
  if (!Number.isFinite(t)) return null;
  const loc = parseLoc(r.LocationDetails);
  const status = parseLoc(r.Status);
  return {
    time: t,
    user: lower(r.UserPrincipalName),
    ip: String(r.IPAddress ?? ""),
    country: String(loc.countryOrRegion ?? r.Location ?? "").toUpperCase(),
    city: String(loc.city ?? ""),
    interactive: r.IsInteractive === undefined ? r.Category !== "NonInteractiveUserSignInLogs" : r.IsInteractive === true || r.IsInteractive === "true",
    app: String(r.AppDisplayName ?? ""),
    client: String(r.ClientAppUsed ?? ""),
    errorCode: Number(r.ResultType ?? 0) || 0,
    details: [r.ResultDescription, status.additionalDetails].filter(Boolean).join(" · "),
    session: String(r.SessionId ?? ""),
    risk: lower(r.RiskLevelDuringSignIn),
    device: String(parseLoc(r.DeviceDetail).displayName ?? ""),
  };
}

export function toAudit(r: any): AuditEvent | null {
  const graph = "activityDisplayName" in r;
  const t = Date.parse(graph ? r.activityDateTime : r.TimeGenerated);
  if (!Number.isFinite(t)) return null;
  const by = parseLoc(graph ? r.initiatedBy : r.InitiatedBy);
  const targets: any[] = (graph ? r.targetResources : parseLoc(r.TargetResources)) ?? [];
  const userTarget = targets.find((x) => x?.userPrincipalName) ?? targets.find((x) => lower(x?.type) === "user");
  const other = targets.find((x) => lower(x?.type) !== "user") ?? targets[0];
  return {
    time: t,
    activity: String(graph ? r.activityDisplayName : r.OperationName),
    actor: lower(by?.user?.userPrincipalName) || String(by?.app?.displayName ?? ""),
    targetUser: lower(userTarget?.userPrincipalName),
    target: String(other?.displayName ?? ""),
  };
}

/** Reads one file's JSON. Returns what it found; throws a plain-words error when it found nothing usable. */
export function readLogFile(name: string, text: string): LoadedLogs {
  const clean = text.replace(/^﻿/, "");
  if (/\.csv$/i.test(name) || /^"?Time UTC"?,/.test(clean)) {
    const signIns = readEntity360Timeline(name, clean);
    if (!signIns.length) throw new Error(`${name} has no Entity 360 sign-in rows. In Entity 360, open the user, then export the timeline as CSV and load that file.`);
    return { signIns, audits: [], sources: [`${name}: ${signIns.length} sign-ins from Entity 360 (its CSV has no country, error code or risk level, so rules that need those can't use these rows)`] };
  }
  let j: any;
  try {
    j = JSON.parse(clean);
  } catch {
    throw new Error(`${name} isn't JSON or an Entity 360 CSV. In the Entra admin center use Sign-in logs > Download > JSON, or run Export-F360SignIns.ps1.`);
  }
  if (j?.format === SIGNINS_FORMAT) {
    const signIns = (j.signIns ?? []).map(toSignIn).filter(Boolean) as SignInEvent[];
    const audits = (j.audits ?? []).map(toAudit).filter(Boolean) as AuditEvent[];
    const from = j.collector === "sample" ? "made-up sample" : "from Export-F360SignIns.ps1";
    return { signIns, audits, sources: [`${name}: ${signIns.length} sign-ins and ${audits.length} audit events, ${from}`] };
  }
  const rows = rowsOf(j);
  const signIns = rows.filter(isSignIn).map(toSignIn).filter(Boolean) as SignInEvent[];
  const audits = rows.filter(isAudit).map(toAudit).filter(Boolean) as AuditEvent[];
  if (!signIns.length && !audits.length)
    throw new Error(`${name} has no sign-in or audit events Federation 360 recognises. It expects Entra sign-in logs or audit logs as JSON (Graph or Log Analytics columns).`);
  const parts = [signIns.length && `${signIns.length} sign-ins`, audits.length && `${audits.length} audit events`].filter(Boolean).join(" and ");
  return { signIns, audits, sources: [`${name}: ${parts}`] };
}

export function mergeLogs(a: LoadedLogs, b: LoadedLogs): LoadedLogs {
  return { signIns: [...a.signIns, ...b.signIns].sort((x, y) => x.time - y.time), audits: [...a.audits, ...b.audits].sort((x, y) => x.time - y.time), sources: [...a.sources, ...b.sources] };
}

export const EMPTY_LOGS: LoadedLogs = { signIns: [], audits: [], sources: [] };

/** CSV rows, with quoted fields (Entity 360 quotes every cell and prefixes a ' to cells that look like formulas). */
export function parseCsvRows(text: string): string[][] {
  const rows: string[][] = [];
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
      if (row.some((x) => x !== "")) rows.push(row);
      row = [];
      cell = "";
    } else cell += c;
  }
  row.push(cell);
  if (row.some((x) => x !== "")) rows.push(row);
  return rows.map((r) => r.map((x) => x.replace(/^'(?=[=+@\-])/, "")));
}

/**
 * Entity 360's timeline CSV: Time UTC, Activity, Category, Result, Source, Actor, Target, Direction, IP, Record ID.
 * Sign-in rows have no UPN column; the person is the Actor (a display name), so they're keyed by that, lower-cased.
 * The CSV has no error code, so a failure is -1 ("failed, reason not in the file"), which no password rule counts.
 */
export function readEntity360Timeline(name: string, text: string): SignInEvent[] {
  const rows = parseCsvRows(text);
  const head = rows.shift()?.map((h) => h.trim()) ?? [];
  const col = (h: string) => head.indexOf(h);
  const [ti, ai, ci, ri, ac, ipi, idi] = [col("Time UTC"), col("Activity"), col("Category"), col("Result"), col("Actor"), col("IP"), col("Record ID")];
  if (ti < 0 || ai < 0 || ci < 0) return [];
  const fileUser = /entity-360-[a-z]+-([0-9a-f-]{36})-/i.exec(name)?.[1] ?? "";
  return rows
    .filter((r) => /sign-?in/i.test(r[ci] ?? ""))
    .map((r): SignInEvent => {
      const ok = /^success/i.test(r[ri] ?? "");
      return {
        time: Date.parse(r[ti]),
        user: lower(ac >= 0 ? r[ac] : "") || fileUser,
        ip: ipi >= 0 ? (r[ipi] ?? "").trim() : "",
        country: "",
        city: "",
        interactive: true,
        app: (r[ai] ?? "").replace(/\s+sign-in$/i, "").trim(),
        client: "",
        errorCode: ok ? 0 : -1,
        details: [r[ri], idi >= 0 && r[idi] ? `Entity 360 record ${r[idi]}` : ""].filter(Boolean).join(" · "),
        session: "",
        from: "Entity 360",
      };
    })
    .filter((s) => Number.isFinite(s.time) && s.app);
}

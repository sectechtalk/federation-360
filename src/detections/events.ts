// Turns sign-in and audit log files into one simple shape the detection rules read.
//
// Accepted inputs (all read in the browser, nothing is uploaded):
//   - Graph sign-ins (v1.0 or beta): Get-MgAuditLogSignIn | ConvertTo-Json, Graph Explorer ({ value: [...] }),
//     or the Entra admin center's Sign-in logs > Download > JSON (works on Entra ID Free, last 7 days)
//   - Log Analytics / Sentinel SigninLogs and AADNonInteractiveUserSignInLogs exported as JSON (PascalCase columns)
//   - Graph directory audits (auditLogs/directoryAudits) and Log Analytics AuditLogs, for the rules that need them
//   - the f360-signins file Export-F360SignIns.ps1 writes, which holds both
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
  let j: any;
  try {
    j = JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    throw new Error(`${name} isn't JSON. In the Entra admin center use Sign-in logs > Download > JSON, or run Export-F360SignIns.ps1.`);
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

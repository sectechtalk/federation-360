// Reads activity from Microsoft Graph with a delegated token (browser sign-in on the Activity page). GET requests only.
// activity/Export-F360Activity.ps1 makes the same file from PowerShell.
//
// Delegated permissions, read-only: AuditLog.Read.All (sign-in, audit and provisioning logs) and Directory.Read.All
// (Graph requires it alongside AuditLog.Read.All for sign-in logs). Reading sign-in and provisioning logs through
// Graph needs Entra ID P1 or higher; audit logs work on Free. Non-interactive, service principal and managed identity
// sign-ins come from the Graph beta endpoint, the only one that returns them.
import { ACTIVITY_EXPORT_FORMAT, readActivityFile, type ParsedActivity } from "./activity";

export const ACTIVITY_SCOPES = ["AuditLog.Read.All", "Directory.Read.All"];

/** Stop after this many rows of each kind, so a big tenant doesn't run for an hour in the browser. */
export const ROW_LIMIT = 20000;

/** Audit activities the summary uses. Everything else is skipped. */
export const AUDIT_ACTIVITIES = [
  "Disable account",
  "Enable account",
  "Update user",
  "Revoke sign-in sessions",
  "Invalidate all refresh tokens for user",
  "Reset user password",
  "Change user password",
  "Remove app role assignment from user",
  "Consent to application",
];

type Get = (path: string) => Promise<any>;

async function all(get: Get, path: string, max = ROW_LIMIT): Promise<{ rows: any[]; capped: boolean }> {
  const rows: any[] = [];
  let next: string | undefined = path;
  while (next && rows.length < max) {
    const j = await get(next);
    rows.push(...(j.value ?? []));
    next = j["@odata.nextLink"];
  }
  return { rows: rows.slice(0, max), capped: !!next };
}

export interface ActivityScan {
  file: Record<string, unknown>;
  parsed: ParsedActivity;
  warnings: string[];
}

export async function collectActivity(get: Get, days: number, progress: (m: string) => void = () => {}, now = new Date()): Promise<ActivityScan> {
  const since = new Date(now.getTime() - days * 86400000).toISOString().replace(/\.\d+Z$/, "Z");
  const warnings: string[] = [];
  const beta = (p: string) => `https://graph.microsoft.com/beta/${p}`;
  const kinds: [string, string][] = [
    ["signIns", "interactiveUser"],
    ["nonInteractive", "nonInteractiveUser"],
    ["servicePrincipal", "servicePrincipal"],
    ["managedIdentity", "managedIdentity"],
  ];
  const file: Record<string, any> = { format: ACTIVITY_EXPORT_FORMAT, version: 1, collector: "browser", collectedAt: now.toISOString(), days };
  let licensed = true;
  for (const [key, type] of kinds) {
    if (!licensed) {
      file[key] = [];
      continue;
    }
    progress(`Reading ${type === "interactiveUser" ? "interactive" : type === "nonInteractiveUser" ? "non-interactive (silent refresh)" : type === "servicePrincipal" ? "service principal" : "managed identity"} sign-ins…`);
    try {
      const filter = encodeURIComponent(`createdDateTime ge ${since} and signInEventTypes/any(t: t eq '${type}')`);
      const r = await all(get, beta(`auditLogs/signIns?$filter=${filter}&$top=999`));
      file[key] = r.rows;
      if (r.capped) warnings.push(`Stopped at ${ROW_LIMIT} ${type} sign-ins. Run Export-F360Activity.ps1 for the rest.`);
    } catch (e: any) {
      file[key] = [];
      if (e.status === 403) {
        licensed = false;
        warnings.push(`Sign-in logs couldn't be read through Graph (${e.message}). That needs Entra ID P1, AuditLog.Read.All and a reader role. On a Free tenant, download each sign-in tab from the admin center as JSON and drop the files here.`);
      } else warnings.push(`${type} sign-ins couldn't be read (${e.message}).`);
    }
  }

  progress("Reading provisioning logs…");
  try {
    const r = await all(get, `auditLogs/provisioning?$filter=${encodeURIComponent(`activityDateTime ge ${since}`)}&$top=999`);
    file.provisioning = r.rows;
    if (r.capped) warnings.push(`Stopped at ${ROW_LIMIT} provisioning events.`);
  } catch (e: any) {
    file.provisioning = [];
    warnings.push(`Provisioning logs couldn't be read (${e.message}). They need Entra ID P1.`);
  }

  progress("Reading audit events…");
  try {
    const acts = AUDIT_ACTIVITIES.map((a) => `activityDisplayName eq '${a}'`).join(" or ");
    const r = await all(get, `auditLogs/directoryAudits?$filter=${encodeURIComponent(`activityDateTime ge ${since} and (${acts})`)}&$top=999`);
    file.audits = r.rows;
  } catch (e: any) {
    file.audits = [];
    warnings.push(`Audit events couldn't be read (${e.message}).`);
  }

  const total = ["signIns", "nonInteractive", "servicePrincipal", "managedIdentity", "provisioning", "audits"].reduce((n, k) => n + (file[k]?.length ?? 0), 0);
  const parsed: ParsedActivity = total
    ? readActivityFile(`Graph scan, last ${days} day${days === 1 ? "" : "s"}`, JSON.stringify(file))
    : { signIns: [], audits: [], provisioning: [], sources: [] };
  return { file, parsed, warnings };
}

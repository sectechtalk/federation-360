// Reads sign-ins and audit events straight from a tenant through Microsoft Graph, for the Detections page.
//
// Read-only and delegated: it uses the same "Federation 360 sign-in logs" app registration and browser sign-in as
// Entra's verdict on the Flow tracer (lib/entraLogs.ts, set up once per tenant by Connect-F360SignInLogs.ps1).
// Graph serves sign-in logs only on Entra ID P1 or higher; the risk level is filled in only with Entra ID P2
// (Microsoft 365 E5 and E7 include it). Interactive and non-interactive sign-ins come from Graph beta, which carries
// session IDs, so the stolen-token rule can run. Nothing is stored outside this browser tab.
import { LogsError, classifyGraphError, tokenScopes } from "../lib/entraLogs";
import { toAudit, toSignIn, type AuditEvent, type LoadedLogs, type SignInEvent } from "./events";

const GRAPH = "https://graph.microsoft.com";
/** Per kind of record. Enough for a week in a small or medium tenant; the page says when it stopped early. */
export const MAX_ROWS = 5000;

const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

async function getAll(token: string, url: string, max: number, fetcher: typeof fetch): Promise<{ rows: any[]; capped: boolean }> {
  const rows: any[] = [];
  let next: string | undefined = url;
  while (next && rows.length < max) {
    const r = await fetcher(next, { headers: { Authorization: `Bearer ${token}` } });
    const j: any = await r.json().catch(() => ({}));
    if (!r.ok) {
      const code = j?.error?.code ?? "";
      const msg = j?.error?.message ?? `Graph returned ${r.status}`;
      throw new LogsError(classifyGraphError(r.status, code, msg), msg);
    }
    rows.push(...(j.value ?? []));
    next = j["@odata.nextLink"];
  }
  return { rows: rows.slice(0, max), capped: Boolean(next) || rows.length > max };
}

export interface TenantRead {
  logs: LoadedLogs;
  /** Kinds of record that hit MAX_ROWS, so the page can say the read stopped early. */
  capped: string[];
}

/** The last `days` days of sign-ins (interactive and non-interactive) and audit events, optionally for one user. */
export async function readTenantLogs(token: string, opts: { days: number; user?: string; label?: string }, fetcher: typeof fetch = fetch): Promise<TenantRead> {
  const scp = tokenScopes(token);
  if (scp && !scp.includes("AuditLog.Read.All")) throw new LogsError("no-consent", "The sign-in token doesn't include AuditLog.Read.All.");
  const since = iso(Date.now() - Math.max(1, Math.min(30, opts.days)) * 86_400_000);
  const upn = opts.user?.trim().toLowerCase().replace(/'/g, "''");
  const who = upn ? ` and userPrincipalName eq '${upn}'` : "";
  const q = (f: string) => encodeURIComponent(f);
  const [inter, non, aud] = await Promise.all([
    getAll(token, `${GRAPH}/beta/auditLogs/signIns?$filter=${q(`createdDateTime ge ${since}${who} and signInEventTypes/any(t: t eq 'interactiveUser')`)}&$top=500`, MAX_ROWS, fetcher),
    getAll(token, `${GRAPH}/beta/auditLogs/signIns?$filter=${q(`createdDateTime ge ${since}${who} and signInEventTypes/any(t: t eq 'nonInteractiveUser')`)}&$top=500`, MAX_ROWS, fetcher).catch((e) => {
      if (e instanceof LogsError && e.problem !== "other") throw e;
      return { rows: [] as any[], capped: false }; // non-interactive sign-ins add coverage; never fail the read over them
    }),
    getAll(token, `${GRAPH}/v1.0/auditLogs/directoryAudits?$filter=${q(`activityDateTime ge ${since}`)}&$top=500`, MAX_ROWS, fetcher),
  ]);
  const signIns = [...inter.rows, ...non.rows.map((r) => ({ ...r, isInteractive: false }))]
    .map(toSignIn)
    .filter(Boolean)
    .map((e) => ({ ...(e as SignInEvent), from: "Graph" }))
    .sort((a, b) => a.time - b.time);
  let audits = aud.rows.map(toAudit).filter(Boolean) as AuditEvent[];
  if (upn) audits = audits.filter((a) => a.actor === upn || a.targetUser === upn);
  audits.sort((a, b) => a.time - b.time);
  const capped = [inter.capped && "interactive sign-ins", non.capped && "non-interactive sign-ins", aud.capped && "audit events"].filter(Boolean) as string[];
  const label = opts.label ?? "Your tenant";
  const withRisk = signIns.filter((s) => s.risk && s.risk !== "none" && s.risk !== "hidden").length;
  return {
    logs: {
      signIns,
      audits,
      sources: [`${label} (read through Graph, last ${opts.days} day${opts.days === 1 ? "" : "s"}${upn ? `, ${upn} only` : ""}): ${signIns.length} sign-ins, ${audits.length} audit events, ${withRisk} sign-in${withRisk === 1 ? "" : "s"} with a risk level${capped.length ? `. Stopped at ${MAX_ROWS.toLocaleString()} ${capped.join(" and ")}; pick fewer days or one user` : ""}`],
    },
    capped,
  };
}

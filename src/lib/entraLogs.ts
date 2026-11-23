/**
 * Entra's verdict: the sign-in log entry that matches a captured flow, read from Microsoft Graph.
 *
 * Read-only. Needs, per tenant, a one-time setup (signin-logs/Connect-F360SignInLogs.ps1) that creates a
 * single-page-app registration with delegated AuditLog.Read.All, Directory.Read.All and Policy.Read.ConditionalAccess
 * and grants admin consent. The person reading also needs a role that can read sign-in logs (Security Reader shows
 * everything, Reports Reader shows everything except Conditional Access policy names). Graph serves sign-in logs only
 * on tenants with Entra ID P1 or higher.
 *
 * Sign-in is OAuth 2.0 authorization code with PKCE in a popup, so the Flow tracer page never navigates away.
 * Tokens are kept in this browser's localStorage for this site; a single-page app's refresh token lasts 24 hours.
 */
import type { EntraHints, FlowCapture } from "./flow";

const CONFIG_KEY = "f360:signinlogs:tenants";
const TOKEN_KEY = "f360:signinlogs:tokens";
const PENDING_KEY = "f360:signinlogs:pending";
const RESULT_KEY = "f360:signinlogs:result";
const LOGIN = "https://login.microsoftonline.com";
const GRAPH = "https://graph.microsoft.com";
export const LOG_SCOPES = ["AuditLog.Read.All", "Directory.Read.All", "Policy.Read.ConditionalAccess"];
const scopeParam = () => [...LOG_SCOPES.map((s) => `${GRAPH}/${s}`), "openid", "profile", "offline_access"].join(" ");

/** clientId "free": the setup script found Entra ID Free, so there's nothing to read. */
export interface TenantLogsConfig { tenantId: string; clientId: string; name?: string }

const read = <T,>(k: string, d: T): T => {
  try {
    return JSON.parse(localStorage.getItem(k) || "null") ?? d;
  } catch {
    return d;
  }
};
const write = (k: string, v: unknown) => {
  try {
    localStorage.setItem(k, JSON.stringify(v));
  } catch {
    /* storage blocked: works for this page load only */
  }
};

export const tenantConfigs = (): Record<string, TenantLogsConfig> => read(CONFIG_KEY, {});
export function saveTenantConfig(c: TenantLogsConfig) {
  write(CONFIG_KEY, { ...tenantConfigs(), [c.tenantId.toLowerCase()]: c });
}
export function forgetTenant(tenantId: string) {
  const all = tenantConfigs();
  delete all[tenantId.toLowerCase()];
  write(CONFIG_KEY, all);
  const t = read<Record<string, unknown>>(TOKEN_KEY, {});
  delete t[tenantId.toLowerCase()];
  write(TOKEN_KEY, t);
}

/**
 * The setup script ends by opening #flowtracer&f360logs=<tenantId>.<clientId> (or .free).
 * Call once at startup: it saves the setting and cleans the address bar.
 */
export function consumeSetupLink(): TenantLogsConfig | null {
  const m = location.hash.match(/[#&]f360logs=([0-9a-f-]{36})\.([0-9a-f-]{36}|free)(?:\.([^&]*))?/i);
  if (!m) return null;
  const c: TenantLogsConfig = { tenantId: m[1].toLowerCase(), clientId: m[2].toLowerCase(), name: m[3] ? decodeURIComponent(m[3]) : undefined };
  saveTenantConfig(c);
  history.replaceState(null, "", location.pathname + location.search + "#flowtracer");
  return c;
}

// ---------------------------------------------------------------- tenant names to IDs

const tenantIdCache = new Map<string, string | null>();
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A tenant domain to its ID, from Entra's public sign-in metadata. */
export async function tenantIdOf(tenant: string): Promise<string | null> {
  if (GUID.test(tenant)) return tenant.toLowerCase();
  const k = tenant.toLowerCase();
  if (tenantIdCache.has(k)) return tenantIdCache.get(k)!;
  let id: string | null = null;
  try {
    const r = await fetch(`${LOGIN}/${encodeURIComponent(tenant)}/v2.0/.well-known/openid-configuration`);
    const j = await r.json();
    id = String(j.issuer ?? "").match(/[0-9a-f-]{36}/i)?.[0]?.toLowerCase() ?? null;
  } catch {
    id = null;
  }
  tenantIdCache.set(k, id);
  return id;
}

// ---------------------------------------------------------------- sign-in (popup)

interface Tokens { access: string; expiresAt: number; refresh?: string; refreshBy?: number; user?: string }

const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const random = (n = 48) => b64url(crypto.getRandomValues(new Uint8Array(n)));
const challenge = async (v: string) => b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v))));
export const logsRedirectUri = () => location.origin + location.pathname;

function userOf(idToken?: string) {
  try {
    const p = JSON.parse(atob((idToken ?? "").split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return (p.preferred_username || p.upn || p.name) as string | undefined;
  } catch {
    return undefined;
  }
}

async function tokenCall(tenantId: string, body: Record<string, string>): Promise<Tokens> {
  const r = await fetch(`${LOGIN}/${tenantId}/oauth2/v2.0/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new Error(j.error_description || j.error || `Token request failed (${r.status})`);
  const prev = read<Record<string, Tokens>>(TOKEN_KEY, {})[tenantId];
  return {
    access: j.access_token,
    expiresAt: Date.now() + (Number(j.expires_in) || 3600) * 1000 - 60_000,
    refresh: j.refresh_token ?? prev?.refresh,
    refreshBy: j.refresh_token ? Date.now() + 23 * 3600_000 : prev?.refreshBy,
    user: userOf(j.id_token) ?? prev?.user,
  };
}

function saveTokens(tenantId: string, t: Tokens | null) {
  const all = read<Record<string, Tokens>>(TOKEN_KEY, {});
  if (t) all[tenantId] = t;
  else delete all[tenantId];
  write(TOKEN_KEY, all);
}

/** The signed-in account for a tenant, if a usable token or refresh token is saved. */
export function signedInUser(tenantId: string): string | null {
  const t = read<Record<string, Tokens>>(TOKEN_KEY, {})[tenantId.toLowerCase()];
  if (!t) return null;
  return t.expiresAt > Date.now() || (t.refresh && (t.refreshBy ?? 0) > Date.now()) ? t.user ?? "signed in" : null;
}

export function signOut(tenantId: string) {
  saveTokens(tenantId.toLowerCase(), null);
}

/** A Graph token for the tenant, renewed silently while the refresh token lasts. Null means sign in. */
export async function graphToken(cfg: TenantLogsConfig): Promise<string | null> {
  const id = cfg.tenantId.toLowerCase();
  const t = read<Record<string, Tokens>>(TOKEN_KEY, {})[id];
  if (!t) return null;
  if (t.expiresAt > Date.now()) return t.access;
  if (!t.refresh || (t.refreshBy ?? 0) < Date.now()) return null;
  try {
    const n = await tokenCall(id, { client_id: cfg.clientId, grant_type: "refresh_token", refresh_token: t.refresh, scope: scopeParam() });
    saveTokens(id, n);
    return n.access;
  } catch {
    saveTokens(id, null);
    return null;
  }
}

/**
 * Opens the Microsoft sign-in popup. Call it straight from a button click (popup blockers allow only that).
 * Resolves with the signed-in account.
 */
export function signInForLogs(cfg: TenantLogsConfig, loginHint?: string): Promise<string> {
  const popup = window.open("about:blank", "f360-signin-logs", "width=520,height=680");
  if (!popup) return Promise.reject(new Error("The browser blocked the sign-in window. Allow pop-ups for this page, then click the button again."));
  return new Promise((resolve, reject) => {
    (async () => {
      const verifier = random();
      const state = random(16);
      write(PENDING_KEY, { state, verifier, tenantId: cfg.tenantId, clientId: cfg.clientId, redirectUri: logsRedirectUri() });
      localStorage.removeItem(RESULT_KEY);
      const q = new URLSearchParams({
        client_id: cfg.clientId, response_type: "code", redirect_uri: logsRedirectUri(), response_mode: "query",
        scope: scopeParam(), state, code_challenge: await challenge(verifier), code_challenge_method: "S256", prompt: "select_account",
        ...(loginHint ? { login_hint: loginHint } : {}),
      });
      popup.location.href = `${LOGIN}/${cfg.tenantId}/oauth2/v2.0/authorize?${q}`;
      const done = (fn: () => void) => {
        window.removeEventListener("storage", onStorage);
        clearInterval(closed);
        fn();
      };
      const onStorage = async (e: StorageEvent) => {
        if (e.key !== RESULT_KEY || !e.newValue) return;
        const r = JSON.parse(e.newValue) as { state: string; code?: string; error?: string };
        localStorage.removeItem(RESULT_KEY);
        if (r.state !== state) return;
        if (r.error || !r.code) return done(() => reject(new Error(r.error || "Sign-in was cancelled.")));
        try {
          const t = await tokenCall(cfg.tenantId.toLowerCase(), { client_id: cfg.clientId, grant_type: "authorization_code", code: r.code, redirect_uri: logsRedirectUri(), code_verifier: verifier, scope: scopeParam() });
          saveTokens(cfg.tenantId.toLowerCase(), t);
          done(() => resolve(t.user ?? "signed in"));
        } catch (err) {
          done(() => reject(err));
        }
      };
      window.addEventListener("storage", onStorage);
      const closed = setInterval(() => {
        if (popup.closed && !localStorage.getItem(RESULT_KEY)) setTimeout(() => popup.closed && done(() => reject(new Error("The sign-in window was closed before sign-in finished."))), 1500);
      }, 1000);
    })().catch(reject);
  });
}

/**
 * Runs first in main.tsx. In the sign-in popup, hands the code to the Flow tracer page and closes the popup.
 * Returns true when this page load was that popup.
 */
export function consumeLogsPopup(): boolean {
  const q = new URLSearchParams(location.search);
  const state = q.get("state");
  if (!state) return false;
  const pending = read<{ state?: string } | null>(PENDING_KEY, null);
  if (!pending || pending.state !== state) return false;
  localStorage.removeItem(PENDING_KEY);
  write(RESULT_KEY, { state, code: q.get("code") ?? undefined, error: q.get("error") ? `${q.get("error")}: ${q.get("error_description") ?? ""}` : undefined });
  history.replaceState(null, "", location.pathname);
  document.body.textContent = "Signed in. You can close this window.";
  setTimeout(() => window.close(), 300);
  return true;
}

// ---------------------------------------------------------------- reading the log

export interface SignInRecord {
  id: string;
  createdDateTime: string;
  userPrincipalName?: string;
  userDisplayName?: string;
  appId?: string;
  appDisplayName?: string;
  resourceDisplayName?: string;
  correlationId?: string;
  ipAddress?: string;
  clientAppUsed?: string;
  isInteractive?: boolean;
  conditionalAccessStatus?: "success" | "failure" | "notApplied" | "unknownFutureValue" | string;
  authenticationRequirement?: string;
  status?: { errorCode?: number; failureReason?: string | null; additionalDetails?: string | null };
  appliedConditionalAccessPolicies?: { id: string; displayName: string; result: string; enforcedGrantControls?: string[]; enforcedSessionControls?: string[] }[];
  deviceDetail?: { operatingSystem?: string; browser?: string; isCompliant?: boolean | null; isManaged?: boolean | null };
  location?: { city?: string; countryOrRegion?: string };
}

export type Problem = "unlicensed" | "no-consent" | "no-role" | "signed-out" | "other";
export class LogsError extends Error {
  constructor(public problem: Problem, message: string) {
    super(message);
  }
}

/** Sorts Graph's refusals into the few problems a person can fix. */
export function classifyGraphError(status: number, code: string, message: string): Problem {
  const t = `${code} ${message}`;
  if (/NonPremiumTenant|premium license|B2C/i.test(t)) return "unlicensed";
  if (/MSGraphPermissionMissing|missing .*permission|Read all audit log data/i.test(t)) return "no-consent";
  if (/allowed roles|UnsupportedUserRole|RequestDenied|Forbidden/i.test(t) || status === 403) return "no-role";
  if (status === 401 || /InvalidAuthenticationToken|expired/i.test(t)) return "signed-out";
  return "other";
}

async function graphGet(token: string, path: string): Promise<SignInRecord[]> {
  const r = await fetch(`${GRAPH}${path}`, { headers: { Authorization: `Bearer ${token}` } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    const code = j?.error?.code ?? "";
    const msg = j?.error?.message ?? `Graph returned ${r.status}`;
    throw new LogsError(classifyGraphError(r.status, code, msg), msg);
  }
  return (j.value ?? []) as SignInRecord[];
}

/** The delegated permissions in an access token (its scp claim), or null if it can't be read. */
export function tokenScopes(token: string): string[] | null {
  try {
    const p = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return typeof p.scp === "string" ? p.scp.split(" ") : null;
  } catch {
    return null;
  }
}

const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

/** Interactive and non-interactive sign-ins around the flow, for the app when the flow names one. */
export async function fetchCandidates(token: string, h: EntraHints): Promise<SignInRecord[]> {
  // The token says which permissions were granted, so a missing consent is known before Graph refuses.
  const scp = tokenScopes(token);
  if (scp && !scp.includes("AuditLog.Read.All")) throw new LogsError("no-consent", "The sign-in token doesn't include AuditLog.Read.All.");
  const from = Date.parse(h.from ?? "") || Date.now() - 30 * 60_000;
  const to = Math.min(Date.parse(h.to ?? "") || Date.now(), Date.now());
  const time = `createdDateTime ge ${iso(from - 5 * 60_000)} and createdDateTime le ${iso(Math.min(to + 20 * 60_000, Date.now() + 60_000))}`;
  const app = h.clientIds.length === 1 ? ` and appId eq '${h.clientIds[0]}'` : "";
  const corr = h.correlationIds.slice(0, 3).map((c) => `correlationId eq '${c}'`);
  const calls = [
    graphGet(token, `/v1.0/auditLogs/signIns?$filter=${encodeURIComponent(time + app)}&$top=200`),
    graphGet(token, `/beta/auditLogs/signIns?$filter=${encodeURIComponent(`${time}${app} and signInEventTypes/any(t: t eq 'nonInteractiveUser')`)}&$top=200`).catch((e) => {
      if (e instanceof LogsError && e.problem !== "other") throw e;
      return [] as SignInRecord[]; // non-interactive sign-ins are a bonus; never fail the verdict over them
    }),
    ...corr.map((c) => graphGet(token, `/v1.0/auditLogs/signIns?$filter=${encodeURIComponent(c)}&$top=20`)),
  ];
  const seen = new Map<string, SignInRecord>();
  for (const list of await Promise.all(calls)) for (const r of list) seen.set(r.id, r);
  return [...seen.values()];
}

export interface Match { records: SignInRecord[]; how: "exact" | "likely" }

/** The log entries that belong to this flow, newest last. */
export function matchSignIns(h: EntraHints, all: SignInRecord[]): Match | null {
  const ids = new Set(h.requestIds.map((x) => x.toLowerCase()));
  const corr = new Set(h.correlationIds.map((x) => x.toLowerCase()));
  const byTime = (a: SignInRecord, b: SignInRecord) => Date.parse(a.createdDateTime) - Date.parse(b.createdDateTime);
  const exact = all.filter((r) => ids.has(r.id.toLowerCase()) || (r.correlationId && corr.has(r.correlationId.toLowerCase())));
  if (exact.length) {
    // Everything else in the same correlation (the MFA prompt before the success, for example).
    const ec = new Set(exact.map((r) => r.correlationId?.toLowerCase()).filter(Boolean));
    return { records: all.filter((r) => exact.includes(r) || (r.correlationId && ec.has(r.correlationId.toLowerCase()))).sort(byTime), how: "exact" };
  }
  if (!h.clientIds.length) return null;
  const apps = new Set(h.clientIds.map((x) => x.toLowerCase()));
  const target = Date.parse(h.to ?? h.from ?? "") || Date.now();
  const near = all.filter((r) => r.appId && apps.has(r.appId.toLowerCase()) && Math.abs(Date.parse(r.createdDateTime) - target) < 10 * 60_000).sort(byTime);
  if (!near.length) return null;
  const last = near.reduce((a, b) => (Math.abs(Date.parse(b.createdDateTime) - target) < Math.abs(Date.parse(a.createdDateTime) - target) ? b : a));
  return { records: near.filter((r) => r.correlationId && r.correlationId === last.correlationId).sort(byTime), how: "likely" };
}

// ---------------------------------------------------------------- plain words

/** Codes where Entra pauses a sign-in to ask the user something. They appear in the log but aren't the failure. */
const INTERRUPTS: Record<number, string> = {
  50074: "Entra asked for multifactor authentication (MFA).",
  50076: "Entra asked for multifactor authentication (MFA).",
  50079: "Entra asked the user to register for MFA.",
  50072: "Entra asked the user to register for MFA.",
  50140: "Entra asked “Stay signed in?”.",
  50125: "Entra asked the user to reset their password or finish registration.",
  50158: "Entra sent the user to an external check (a third-party MFA or device check).",
  50199: "Entra asked the user to confirm the app.",
  16000: "Entra asked the user to pick an account.",
  16001: "Entra asked the user to pick an account.",
  50097: "Entra asked the device to prove its identity.",
  81010: "Seamless single sign-on didn't apply, so Entra fell back to a normal sign-in.",
  81012: "Seamless single sign-on didn't apply, so Entra fell back to a normal sign-in.",
};

const PLAIN: Record<number, { what: string; fix: string }> = {
  50126: { what: "The user name or password was wrong.", fix: "Have the user check their password, or reset it in the Entra admin center under Users." },
  50053: { what: "The account is locked after too many failed attempts.", fix: "Wait for the lockout to end, or check Entra ID > Protection > Authentication methods > Password protection for the lockout settings." },
  50057: { what: "The user account is disabled.", fix: "Enable the account: Entra admin center > Users > the user > Edit properties > Account enabled." },
  50034: { what: "That user doesn't exist in this tenant.", fix: "Check the sign-in name for a typo or a different domain." },
  50105: { what: "The user isn't assigned to this app, and the app requires assignment.", fix: "Enterprise applications > the app > Users and groups > Add user/group, or turn off Assignment required." },
  53003: { what: "A Conditional Access policy blocked the sign-in.", fix: "Read the policy named above. Change the policy, or meet what it asks (for example a compliant device or a trusted location)." },
  53000: { what: "Conditional Access requires a compliant or managed device.", fix: "Sign in from a managed device, or enroll this one in Intune." },
  530003: { what: "Conditional Access requires a managed device.", fix: "Sign in from a managed device, or enroll this one in Intune." },
  700016: { what: "Entra doesn't know this app in this tenant.", fix: "Check the client ID or SAML Identifier (Entity ID), and that the app was added to this tenant." },
  50011: { what: "The app asked Entra to send the user back to an address that isn't registered for the app.", fix: "Add the exact address to the app's Reply URLs (SAML) or Redirect URIs (OIDC)." },
  65001: { what: "Nobody has consented to the permissions this app asks for.", fix: "Enterprise applications > the app > Permissions > Grant admin consent." },
  7000215: { what: "The app sent a wrong client secret.", fix: "Create a new secret under App registrations > the app > Certificates & secrets, and update the app." },
  7000222: { what: "The app's client secret has expired.", fix: "Create a new secret under App registrations > the app > Certificates & secrets, and update the app." },
  50020: { what: "The user is from another tenant and isn't a guest here.", fix: "Invite them as a guest, or use the app's multi-tenant settings." },
  90072: { what: "The user is from another tenant and isn't a guest here.", fix: "Invite them as a guest, or use the app's multi-tenant settings." },
  500011: { what: "The resource (API) the app asked for isn't in this tenant.", fix: "Check the scope or resource the app requests, and that the API's enterprise app exists here." },
  50055: { what: "The password has expired.", fix: "Have the user change their password." },
  50173: { what: "The sign-in used an old session from before a password change or a revoked session.", fix: "Have the user sign out and sign in again." },
  50133: { what: "The session ended because the password changed.", fix: "Have the user sign in again." },
  70043: { what: "The refresh token or session expired because of a Conditional Access sign-in frequency setting.", fix: "Normal: the user signs in again. Check the sign-in frequency in the policy if it happens too often." },
};

export interface Verdict {
  tone: "ok" | "fail" | "warn";
  headline: string;
  lines: string[];
  fix?: string;
  playbook?: string;
}

const CONTROL: Record<string, string> = {
  mfa: "multifactor authentication",
  compliantDevice: "a compliant device",
  domainJoinedDevice: "a hybrid-joined device",
  approvedApplication: "an approved client app",
  compliantApplication: "an app protection policy",
  passwordChange: "a password change",
  block: "nothing: it blocks access",
};

/** The log entries for one flow, in plain words. The last entry decides the outcome. */
export function explain(records: SignInRecord[], knownPlaybooks: (code: string) => boolean = () => false): Verdict {
  const last = records[records.length - 1];
  const who = last.userPrincipalName || last.userDisplayName || "the user";
  const app = last.appDisplayName || last.appId || "the app";
  const code = last.status?.errorCode ?? 0;
  const lines: string[] = [];
  for (const r of records.slice(0, -1)) {
    const c = r.status?.errorCode ?? 0;
    if (INTERRUPTS[c]) lines.push(`${new Date(r.createdDateTime).toLocaleTimeString()}: ${INTERRUPTS[c]} That's a normal step, not the failure.`);
  }
  const pols = last.appliedConditionalAccessPolicies;
  const failed = pols?.filter((p) => p.result === "failure") ?? [];
  const passed = pols?.filter((p) => p.result === "success") ?? [];
  if (last.conditionalAccessStatus === "notApplied") lines.push("No Conditional Access policy applied to this sign-in.");
  else if (passed.length) lines.push(`Conditional Access: ${passed.map((p) => `“${p.displayName}”`).join(", ")} applied and ${passed.length === 1 ? "was" : "were"} satisfied.`);
  if (last.authenticationRequirement === "multiFactorAuthentication") lines.push("Multifactor authentication was required.");
  if (pols === undefined && last.conditionalAccessStatus && last.conditionalAccessStatus !== "notApplied")
    lines.push("Conditional Access policy names are hidden from your account. The Security Reader role shows them.");

  if (code === 0) {
    return { tone: "ok", headline: `Entra signed ${who} in to ${app}.`, lines };
  }
  if (INTERRUPTS[code]) {
    return { tone: "warn", headline: `Entra paused the sign-in: ${INTERRUPTS[code]}`, lines: [...lines, "The user didn't finish this step, or the app gave up before they did."], fix: "Have the user finish the prompt. If they never saw it, the app may not be able to show Entra's prompts (for example inside a frame)." };
  }
  const aadsts = `AADSTS${code}`;
  const plain = PLAIN[code];
  for (const p of failed) {
    const needs = (p.enforcedGrantControls ?? []).map((g) => CONTROL[g] ?? g);
    lines.unshift(`Blocked by Conditional Access policy “${p.displayName}”${needs.length ? `, which requires ${needs.join(" and ")}` : ""}.`);
  }
  return {
    tone: "fail",
    headline: `Entra stopped ${who} signing in to ${app}: ${plain?.what ?? last.status?.failureReason ?? "see the details"} (${aadsts})`,
    lines: last.status?.additionalDetails ? [...lines, last.status.additionalDetails] : lines,
    fix: plain?.fix ?? (failed.length ? "Review the policy above in Entra ID > Conditional Access > Policies." : undefined),
    playbook: knownPlaybooks(aadsts) ? aadsts : undefined,
  };
}

/** Whether a flow can be looked up at all: it went through Entra and names its tenant. */
export const canLookUp = (c: FlowCapture) => !!c.entra;

/**
 * Sign in to Entra from the browser (Federation 360 only). The read-only Graph collection itself is
 * collectEntraExport from @sectechtalk/f360-collector, shared with certificates-360.
 *
 * OAuth 2.0 authorization code flow with PKCE, as a single-page app (no secret, no library):
 * the page redirects to Entra, Entra redirects back with ?code=..., and the page redeems the code
 * at the token endpoint. The access token lives only in memory for this page load.
 *
 * Needs an app registration with this page's address as a "Single-page application" redirect URI
 * and delegated Microsoft Graph Application.Read.All + Directory.Read.All. The lab kit's
 * F360-Discovery app is exactly that.
 */
import { GRAPH_SCOPES } from "@sectechtalk/f360-collector";

const PENDING_KEY = "f360:discovery:pending";

export interface SignInConfig {
  tenantId: string;
  clientId: string;
  redirectUri: string;
}

interface Pending extends SignInConfig {
  verifier: string;
  state: string;
}

/** Where this page would ask Entra to send the user back. */
export const currentRedirectUri = () => location.origin + location.pathname;

/** Sign-in can't work inside a sandboxed frame (the Claude artifact) or from a file:// page. */
export function browserSignInBlocker(): string | null {
  let framed = true;
  try {
    framed = window.self !== window.top;
  } catch {
    framed = true;
  }
  if (framed) return "This page is running inside a frame (for example the Claude artifact), and Microsoft's sign-in page refuses to load in frames.";
  if (!/^https?:$/.test(location.protocol)) return "This page was opened from a file. Run it with npm run dev or from a website.";
  return null;
}

const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function randomString(n = 48) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return b64url(a);
}

async function challenge(verifier: string) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return b64url(new Uint8Array(d));
}

const scopeParam = () => [...GRAPH_SCOPES.map((s) => `https://graph.microsoft.com/${s}`), "openid", "profile"].join(" ");

export async function startSignIn(cfg: SignInConfig) {
  const p: Pending = { ...cfg, verifier: randomString(), state: randomString(16) };
  sessionStorage.setItem(PENDING_KEY, JSON.stringify(p));
  const q = new URLSearchParams({
    client_id: cfg.clientId,
    response_type: "code",
    redirect_uri: cfg.redirectUri,
    response_mode: "query",
    scope: scopeParam(),
    state: p.state,
    code_challenge: await challenge(p.verifier),
    code_challenge_method: "S256",
    prompt: "select_account",
  });
  location.assign(`https://login.microsoftonline.com/${encodeURIComponent(cfg.tenantId)}/oauth2/v2.0/authorize?${q}`);
}

let returned: { code?: string; error?: string; pending?: Pending } | null = null;

/**
 * Call once before the app renders. If Entra just sent us back, remember the result,
 * clean the address bar and route to the Discover page.
 */
export function consumeRedirect() {
  const q = new URLSearchParams(location.search);
  const state = q.get("state");
  if (!state || (!q.get("code") && !q.get("error"))) return;
  let pending: Pending | undefined;
  try {
    pending = JSON.parse(sessionStorage.getItem(PENDING_KEY) || "null") ?? undefined;
    sessionStorage.removeItem(PENDING_KEY);
  } catch {
    /* ignore */
  }
  if (!pending || pending.state !== state) returned = { error: "The sign-in response didn't match a sign-in started from this page. Start again." };
  else if (q.get("error")) returned = { error: `${q.get("error")}: ${q.get("error_description") ?? ""}`, pending };
  else returned = { code: q.get("code")!, pending };
  history.replaceState(null, "", location.pathname + "#discover");
}

export const takeRedirectResult = () => {
  const r = returned;
  returned = null;
  return r;
};

export async function redeemCode(code: string, p: Pending): Promise<string> {
  const body = new URLSearchParams({
    client_id: p.clientId,
    grant_type: "authorization_code",
    code,
    redirect_uri: p.redirectUri,
    code_verifier: p.verifier,
    scope: scopeParam(),
  });
  const r = await fetch(`https://login.microsoftonline.com/${encodeURIComponent(p.tenantId)}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new Error(j.error_description || j.error || `Token request failed (${r.status})`);
  return j.access_token as string;
}

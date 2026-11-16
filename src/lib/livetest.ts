/**
 * Live test: talks to the lab test app (lab/testapp) and runs the OpenID Connect sign-in itself.
 *
 * In the OIDC test Federation 360 is the client: it sends you to Entra (authorization code + PKCE, as a
 * single-page app), redeems the code, then hands the access token to the test app's API, which checks it.
 * Every hop is recorded as an f360.capture.
 *
 * The test app runs in one of two places:
 *   - on your PC in Docker (http://localhost:5174), which keeps the captures itself;
 *   - on Azure Static Web Apps Free, which keeps nothing ("stateless"). Its captures come back in the response, or
 *     in the URL fragment after a SAML sign-in, and are kept in this browser instead.
 */
import { CAPTURE_FORMAT, newCaptureId, type FlowCapture, type FlowStep } from "./flow";

export const DEFAULT_TESTAPP_URL = "http://localhost:5174";
const PENDING_KEY = "f360:livetest:pending";
const LOCAL_CAPTURES_KEY = "f360:livetest:captures";
const TESTAPP_PREF_KEY = "f360:pref:testAppUrl";
/** Must match CAPTURE_FRAGMENT in lab/testapp/core.mjs. */
export const CAPTURE_FRAGMENT = "f360capture";
const MAX_LOCAL_CAPTURES = 30;
const LOGIN = "https://login.microsoftonline.com";

export interface TestAppConfig {
  configured: boolean;
  tenantId: string | null;
  publicUrl: string;
  f360Url: string;
  /** Where the test app runs. Older test apps don't say, and run on your PC. */
  host?: "local" | "azure";
  /** True when the test app keeps no captures (Azure), so this browser keeps them. */
  stateless?: boolean;
  /** Test accounts in the lab tenant (full sign-in names). */
  labUsers?: string[];
  saml: { entityId: string; acsUrl: string; loginUrl: string } | null;
  oidc: { clientId: string; scope: string; apiAudience: string } | null;
  clientCredentials: { clientId: string; scope: string } | null;
}

export interface CaptureSummary {
  id: string;
  kind: FlowCapture["kind"];
  title: string;
  startedAt: string;
  source: FlowCapture["source"];
  steps: number;
}

const base = (u: string) => u.replace(/\/+$/, "");

async function getJson<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((j as any)?.error ?? `HTTP ${r.status}`);
  return j as T;
}

/** Addresses the Live test page will accept from a link: your PC, or a site on Azure Static Web Apps. */
export function isAllowedTestAppUrl(u: string): boolean {
  try {
    const x = new URL(u);
    if (x.pathname !== "/" || x.search || x.hash || x.username || x.password) return false;
    if (x.protocol === "http:" && (x.hostname === "localhost" || x.hostname === "127.0.0.1")) return true;
    return x.protocol === "https:" && /^([a-z0-9-]+\.)+azurestaticapps\.net$/.test(x.hostname);
  } catch {
    return false;
  }
}

/**
 * Call before the app renders. A link like http://localhost:5173/?testapp=https://….azurestaticapps.net#livetest
 * (printed by the Azure deploy script) points the Live test page at that test app.
 */
export function acceptTestAppParam() {
  const q = new URLSearchParams(location.search);
  const u = q.get("testapp");
  if (!u) return;
  q.delete("testapp");
  if (isAllowedTestAppUrl(u)) {
    try {
      localStorage.setItem(TESTAPP_PREF_KEY, JSON.stringify(base(u)));
    } catch {
      /* ignore */
    }
  }
  const rest = q.toString();
  history.replaceState(null, "", location.pathname + (rest ? "?" + rest : "") + (location.hash || "#livetest"));
}

// ------------------------------------------------------------------ captures kept in this browser (Azure test app)

const readLocal = (): FlowCapture[] => {
  try {
    const v = JSON.parse(localStorage.getItem(LOCAL_CAPTURES_KEY) || "[]");
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
};
const writeLocal = (list: FlowCapture[]) => {
  // A SAML capture is tens of KB; drop the oldest until it fits.
  for (let keep = Math.min(list.length, MAX_LOCAL_CAPTURES); keep >= 0; keep--) {
    try {
      localStorage.setItem(LOCAL_CAPTURES_KEY, JSON.stringify(list.slice(0, keep)));
      return;
    } catch {
      /* quota: try with fewer */
    }
  }
};
const summary = (c: FlowCapture): CaptureSummary => ({ id: c.id, kind: c.kind, title: c.title, startedAt: c.startedAt, source: c.source, steps: c.steps.length });

export const browserCaptures = {
  captures: async (): Promise<CaptureSummary[]> => readLocal().map(summary).sort((a, b) => b.startedAt.localeCompare(a.startedAt)),
  capture: async (id: string): Promise<FlowCapture> => {
    const c = readLocal().find((x) => x.id === id);
    if (!c) throw new Error("This capture isn't in this browser any more.");
    return c;
  },
  save: async (c: FlowCapture) => {
    writeLocal([c, ...readLocal().filter((x) => x.id !== c.id)]);
    return { id: c.id };
  },
  clear: async () => {
    try {
      localStorage.removeItem(LOCAL_CAPTURES_KEY);
    } catch {
      /* ignore */
    }
    return { ok: true };
  },
};

/** Where captures live for this test app: the test app itself on your PC, this browser for the Azure one. */
export const captureStore = (url: string, stateless: boolean | undefined) => (stateless ? browserCaptures : testApp(url));

// ------------------------------------------------------------------ capture handed back in the URL fragment (Azure SAML)

let returnedFragment: string | null = null;

/** Call before the app renders: takes #livetest&f360capture=… off the address bar so the router sees #livetest. */
export function consumeCaptureFragment() {
  const h = location.hash.replace(/^#/, "");
  if (!h.startsWith("livetest&")) return;
  const v = new URLSearchParams(h.slice("livetest&".length)).get(CAPTURE_FRAGMENT);
  history.replaceState(null, "", location.pathname + location.search + "#livetest");
  if (v) returnedFragment = v;
}

export const hasReturnedCapture = () => returnedFragment !== null;

/** Unpacks a capture packed by the test app: base64url of raw DEFLATE of the JSON. */
export async function unpackCapture(packed: string): Promise<FlowCapture> {
  const b64 = packed.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  const bytes = Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  const c = JSON.parse(await new Response(stream).text());
  if (c?.format !== CAPTURE_FORMAT || !Array.isArray(c.steps)) throw new Error("The test app sent back something that isn't a capture.");
  return c as FlowCapture;
}

/** The capture an Azure test app handed back after a SAML sign-in, saved in this browser. */
export async function takeReturnedCapture(): Promise<FlowCapture | null> {
  const v = returnedFragment;
  returnedFragment = null;
  if (!v) return null;
  const c = await unpackCapture(v);
  await browserCaptures.save(c);
  return c;
}

export const testApp = (url: string) => ({
  config: () => getJson<TestAppConfig>(`${base(url)}/api/config`),
  captures: () => getJson<CaptureSummary[]>(`${base(url)}/api/captures`),
  capture: (id: string) => getJson<FlowCapture>(`${base(url)}/api/captures/${encodeURIComponent(id)}`),
  save: (c: FlowCapture) => getJson<{ id: string }>(`${base(url)}/api/captures`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(c) }),
  clear: () => getJson<{ ok: boolean }>(`${base(url)}/api/captures`, { method: "DELETE" }),
  runClientCredentials: () => getJson<FlowCapture>(`${base(url)}/api/run/client-credentials`, { method: "POST" }),
  /**
   * The API answers 401 with the same checks when it rejects a token, so both outcomes come back as a step.
   * The token goes as a form field rather than an Authorization header: that keeps it a "simple" cross-origin
   * request, so the browser sends no CORS preflight, which matters for the test app on Azure.
   */
  whoami: async (token: string): Promise<{ step: FlowStep }> => {
    const r = await fetch(`${base(url)}/api/whoami`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ access_token: token }) });
    const j = await r.json().catch(() => null);
    if (j?.step) return j;
    throw new Error(j?.error ?? `HTTP ${r.status}`);
  },
});

// ------------------------------------------------------------------ OIDC run

interface Pending {
  tenantId: string;
  clientId: string;
  scope: string;
  apiAudience: string;
  redirectUri: string;
  verifier: string;
  state: string;
  nonce: string;
  captureId: string;
  startedAt: string;
  testAppUrl: string;
  /** The test app keeps no captures (Azure), so the result is saved in this browser. */
  stateless?: boolean;
  authorizeUrl: string;
}

const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const random = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));

export async function startOidcTest(cfg: { tenantId: string; clientId: string; scope: string; apiAudience: string; loginHint?: string }, testAppUrl: string, stateless = false) {
  const verifier = random(48);
  const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  const redirectUri = location.origin + "/";
  const state = random(16);
  const nonce = random(16);
  const q = new URLSearchParams({
    client_id: cfg.clientId,
    response_type: "code",
    redirect_uri: redirectUri,
    response_mode: "query",
    scope: cfg.scope,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account",
    ...(cfg.loginHint ? { login_hint: cfg.loginHint } : {}),
  });
  const authorizeUrl = `${LOGIN}/${encodeURIComponent(cfg.tenantId)}/oauth2/v2.0/authorize?${q}`;
  const { loginHint: _hint, ...rest } = cfg;
  const p: Pending = { ...rest, redirectUri, verifier, state, nonce, captureId: newCaptureId(), startedAt: new Date().toISOString(), testAppUrl, stateless, authorizeUrl };
  sessionStorage.setItem(PENDING_KEY, JSON.stringify(p));
  location.assign(authorizeUrl);
}

let returned: { pending: Pending; params: URLSearchParams; at: string } | null = null;

/** Call before the app renders. Picks up only sign-ins started from Live test (matched by state). */
export function consumeLiveTestRedirect() {
  const q = new URLSearchParams(location.search);
  const state = q.get("state");
  if (!state || (!q.get("code") && !q.get("error"))) return;
  let pending: Pending | null = null;
  try {
    pending = JSON.parse(sessionStorage.getItem(PENDING_KEY) || "null");
  } catch {
    pending = null;
  }
  if (!pending || pending.state !== state) return; // not ours: leave it for the Discover page
  sessionStorage.removeItem(PENDING_KEY);
  returned = { pending, params: q, at: new Date().toISOString() };
  history.replaceState(null, "", location.pathname + "#livetest");
}

export const hasLiveTestResult = () => returned !== null;

/** Finishes the OIDC run: redeems the code, calls the test API, and saves the capture. */
export async function finishOidcTest(): Promise<FlowCapture | null> {
  const r = returned;
  returned = null;
  if (!r) return null;
  const { pending: p, params: q } = r;
  const steps: FlowStep[] = [
    {
      at: p.startedAt, from: "f360", to: "idp", method: "302", url: `${LOGIN}/${p.tenantId}/oauth2/v2.0/authorize`,
      label: "Federation 360 sends you to Entra to sign in (authorization code with PKCE)",
      params: { client_id: p.clientId, response_type: "code", response_mode: "query", redirect_uri: p.redirectUri, scope: p.scope, state: p.state, nonce: p.nonce, code_challenge_method: "S256", prompt: "select_account" },
    },
  ];
  const code = q.get("code");
  steps.push({
    at: r.at, from: "idp", to: "f360", method: "302", url: p.redirectUri,
    label: code ? "Entra sends you back to Federation 360 with a code" : "Entra sends you back to Federation 360 with an error",
    tokens: code ? [{ name: "code", value: code }] : undefined,
    params: { state: q.get("state") ?? "", ...(q.get("session_state") ? { session_state: q.get("session_state")! } : {}) },
    error: q.get("error") ? { code: q.get("error")!, description: q.get("error_description") ?? undefined } : undefined,
  });

  let accessToken: string | undefined;
  if (code) {
    const tokenUrl = `${LOGIN}/${p.tenantId}/oauth2/v2.0/token`;
    const step: FlowStep = {
      at: new Date().toISOString(), from: "f360", to: "idp", method: "POST", url: tokenUrl,
      label: "Federation 360 exchanges the code for tokens",
      params: { grant_type: "authorization_code", client_id: p.clientId, redirect_uri: p.redirectUri, scope: p.scope, code: "(present)", code_verifier: "(present)" },
      note: "No client secret: a single-page app proves it started the sign-in with the PKCE code_verifier instead.",
    };
    try {
      const res = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ client_id: p.clientId, grant_type: "authorization_code", code, redirect_uri: p.redirectUri, code_verifier: p.verifier, scope: p.scope }),
      });
      step.status = res.status;
      const j = await res.json().catch(() => ({}));
      step.tokens = (["id_token", "access_token"] as const).filter((n) => typeof j[n] === "string").map((n) => ({ name: n, value: j[n] }));
      if (j.refresh_token) step.params!.refresh_token = "(issued, not kept)";
      if (j.error) step.error = { code: j.error, description: j.error_description };
      accessToken = j.access_token;
    } catch (e: any) {
      step.error = { code: "request_failed", description: e?.message };
    }
    steps.push(step);
  }

  if (accessToken) {
    try {
      steps.push((await testApp(p.testAppUrl).whoami(accessToken)).step);
    } catch (e: any) {
      steps.push({ at: new Date().toISOString(), from: "f360", to: "api", label: "Federation 360 calls the test API with the access token", error: { code: "test_app_unreachable", description: e?.message } });
    }
  }

  const capture: FlowCapture = {
    format: CAPTURE_FORMAT,
    version: 1,
    id: p.captureId,
    kind: "oidc",
    source: "f360",
    title: "OpenID Connect sign-in (Federation 360 as the client)",
    startedAt: p.startedAt,
    expect: { clientId: p.clientId, issuer: `${LOGIN}/${p.tenantId}/v2.0`, audience: p.apiAudience, nonce: p.nonce, state: p.state },
    steps,
  };
  try {
    await captureStore(p.testAppUrl, p.stateless).save(capture);
  } catch {
    /* still shown on the page even if the test app is down */
  }
  return capture;
}

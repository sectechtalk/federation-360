/**
 * Turns a HAR file (DevTools > Network > Save all as HAR with content) into a FlowCapture.
 *
 * It keeps only the hops that carry sign-in traffic: SAML messages, OAuth/OIDC authorize and token calls,
 * redirects that bring a code or token back, error pages with AADSTS codes, and API calls with a bearer token.
 * Cookies, other headers and page content are dropped, so the capture holds far less than the HAR did.
 */
import { CAPTURE_FORMAT, newCaptureId, type EntraHints, type FlowCapture, type FlowKind, type FlowStep } from "./flow";
import { b64urlJson } from "./encoding";

interface HarHeader { name: string; value: string }
export interface HarEntry {
  startedDateTime?: string;
  request: { method: string; url: string; headers?: HarHeader[]; postData?: { mimeType?: string; text?: string; params?: { name: string; value?: string }[] } };
  response: { status: number; headers?: HarHeader[]; redirectURL?: string; content?: { mimeType?: string; text?: string; encoding?: string } };
}

/** Kept in step with extension/capture-core.js (tests/browser-capture.test.ts checks). */
export const IDP_HOSTS = [
  /(^|\.)login\.microsoftonline\.com$/i,
  /(^|\.)login\.microsoft\.com$/i,
  /(^|\.)login\.windows\.net$/i,
  /(^|\.)sts\.windows\.net$/i,
  /(^|\.)login\.live\.com$/i,
  /\.b2clogin\.com$/i,
  /\.ciamlogin\.com$/i,
  /\.okta(preview)?\.com$/i,
  /\.oktapreview\.com$/i,
  /\.auth0\.com$/i,
  /(^|\.)accounts\.google\.com$/i,
  /(^|\.)oauth2\.googleapis\.com$/i,
  /\.awsapps\.com$/i,
  /(^|\.)portal\.sso\.[a-z0-9-]+\.amazonaws\.com$/i,
];

/**
 * Parameters worth showing. Secrets are replaced with "(present)". The capture extension holds only these fields of a
 * posted form (SHOWN_FIELDS and SECRET_FIELDS in extension/capture-core.js; tests/browser-capture.test.ts checks).
 */
export const KEEP = ["client_id", "response_type", "response_mode", "scope", "redirect_uri", "state", "nonce", "prompt", "login_hint", "domain_hint", "code_challenge_method", "grant_type", "resource", "RelayState", "SigAlg", "error", "error_description", "error_uri", "session_state"];
export const SECRET = ["code_verifier", "client_secret", "client_assertion", "refresh_token", "password", "code_challenge"];

const header = (hs: HarHeader[] | undefined, name: string) => hs?.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value;

function isIdp(u: URL) {
  return IDP_HOSTS.some((r) => r.test(u.hostname));
}

function formParams(e: HarEntry): URLSearchParams {
  const pd = e.request.postData;
  if (!pd) return new URLSearchParams();
  if (pd.params?.length) {
    const q = new URLSearchParams();
    for (const p of pd.params) q.append(decodeURIComponent(p.name), decodeURIComponent((p.value ?? "").replace(/\+/g, "%20")));
    return q;
  }
  if (pd.text && (!pd.mimeType || /x-www-form-urlencoded/i.test(pd.mimeType))) return new URLSearchParams(pd.text);
  return new URLSearchParams();
}

function bodyText(e: HarEntry): string {
  const c = e.response.content;
  if (!c?.text) return "";
  if (c.encoding === "base64") {
    try {
      return new TextDecoder().decode(Uint8Array.from(atob(c.text), (ch) => ch.charCodeAt(0)));
    } catch {
      return "";
    }
  }
  return c.text;
}

function pick(...sources: URLSearchParams[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const q of sources) {
    for (const k of KEEP) if (q.has(k) && !(k in out)) out[k] = q.get(k)!;
    for (const k of SECRET) if (q.has(k)) out[k] = "(present)";
  }
  return out;
}

const tokenNames = ["code", "id_token", "access_token"] as const;

function tokensFrom(...sources: URLSearchParams[]) {
  const out: { name: string; value: string }[] = [];
  for (const q of sources) for (const n of tokenNames) if (q.get(n)) out.push({ name: n, value: q.get(n)! });
  return out;
}

/** An identity provider page that shows an AADSTS error. */
function errorPage(e: HarEntry, base: Partial<FlowStep>): FlowStep | null {
  const m = bodyText(e).match(/AADSTS\d{4,}[^<"\\]{0,300}/);
  if (!m) return null;
  return { ...base, from: "idp", to: "browser", label: "The identity provider shows an error page", error: { code: m[0].match(/AADSTS\d+/)![0], description: m[0].replace(/\s+/g, " ").trim() } };
}

const shortHost = (u: URL) => (isIdp(u) ? "the identity provider" : u.host);

/** Throws a plain-language error when the text isn't a HAR file. */
export function parseHar(text: string, fileName = "recording.har"): FlowCapture {
  let har: any;
  try {
    har = JSON.parse(text);
  } catch {
    throw new Error("This isn't a HAR file. In DevTools > Network, right-click the request list and choose “Save all as HAR with content”.");
  }
  const entries: HarEntry[] = har?.log?.entries;
  if (!Array.isArray(entries)) throw new Error("This JSON file has no log.entries, so it isn't a HAR file.");
  return parseHarEntries(entries, { title: fileName });
}

export interface HarParseOptions {
  title: string;
  /** "extension": hops recorded live by the Federation 360 Capture browser extension. */
  source?: "har" | "extension";
  id?: string;
}

/** Builds a FlowCapture from HAR entries, whether they came from a saved file or the capture extension. */
export function parseHarEntries(entries: HarEntry[], opts: HarParseOptions): FlowCapture {
  const source = opts.source ?? "har";
  const noBody = source === "extension"
    ? "The browser made this token call, but its reply couldn't be read (for example it came from a background service worker, or the extension is older than 0.2.0). Entra's verdict shows whether it succeeded."
    : "The response body isn't in this HAR. Save it with “Save all as HAR with content”.";
  const steps: FlowStep[] = [];
  let saml = false, oidc = false, oauth = false, cc = false;

  for (const e of entries) {
    let u: URL;
    try {
      u = new URL(e.request.url);
    } catch {
      continue;
    }
    const at = e.startedDateTime;
    const method = e.request.method?.toUpperCase();
    const q = u.searchParams;
    const form = method === "POST" ? formParams(e) : new URLSearchParams();
    const idp = isIdp(u);
    const base = { at, method, url: u.origin + u.pathname + u.search, status: e.response.status };

    // 1. SAML messages, in the query (Redirect binding) or a form post (POST binding).
    const samlParam = (["SAMLRequest", "SAMLResponse"] as const).find((p) => q.has(p) || form.has(p));
    if (samlParam) {
      saml = true;
      const inQuery = q.has(samlParam);
      const value = (inQuery ? q.get(samlParam) : form.get(samlParam))!;
      const toIdp = idp;
      steps.push({
        ...base,
        from: toIdp ? "app" : "idp",
        to: toIdp ? "idp" : "app",
        label: samlParam === "SAMLRequest"
          ? `The app sends a SAML request to ${shortHost(u)}`
          : toIdp ? `A SAML response is sent to ${shortHost(u)}` : `The identity provider posts the SAML response to the app (${u.host})`,
        saml: { param: samlParam, value, binding: inQuery ? "redirect" : "post" },
        params: pick(q, form),
      });
      const errStep = idp && errorPage(e, base);
      if (errStep) steps.push(errStep);
      continue;
    }

    // 2. OAuth / OIDC authorize request.
    if (idp && /\/authorize\/?$/i.test(u.pathname) && q.has("client_id")) {
      const scope = q.get("scope") ?? "";
      if (/\bopenid\b/.test(scope)) oidc = true;
      else oauth = true;
      steps.push({ ...base, from: "app", to: "idp", label: `The app sends the user to sign in (${/\bopenid\b/.test(scope) ? "OpenID Connect" : "OAuth"} authorize request)`, params: pick(q, form) });
      // fall through: the same entry may also redirect straight back (silent sign-in)
    }

    // 3. Token endpoint.
    if (idp && method === "POST" && /\/token\/?$/i.test(u.pathname)) {
      const params = pick(form, q);
      const grant = params.grant_type ?? "";
      if (grant === "client_credentials") cc = true;
      let tokens: { name: string; value: string }[] = [];
      let error: FlowStep["error"];
      let note: string | undefined;
      const txt = bodyText(e);
      try {
        const j = JSON.parse(txt);
        tokens = tokenNames.filter((n) => typeof j[n] === "string").map((n) => ({ name: n, value: j[n] }));
        if (j.refresh_token) params.refresh_token = "(issued)";
        if (j.error) error = { code: String(j.error), description: j.error_description };
      } catch {
        if (!txt) note = noBody;
      }
      steps.push({
        ...base,
        from: grant === "client_credentials" ? "app" : e.request.headers && header(e.request.headers, "origin") ? "browser" : "app",
        to: "idp",
        label: grant === "authorization_code" ? "The code is exchanged for tokens" : grant === "refresh_token" ? "Tokens are refreshed" : grant === "client_credentials" ? "The app gets a token for itself (client credentials)" : `Token request (${grant || "unknown grant"})`,
        params,
        tokens,
        error,
        note,
      });
      continue;
    }

    // 4. The identity provider sends the browser back with a code, tokens or an error.
    const loc = e.response.redirectURL || header(e.response.headers, "location");
    if (idp && loc) {
      let back: URL | undefined;
      try {
        back = new URL(loc, u);
      } catch {
        back = undefined;
      }
      if (back && !isIdp(back)) {
        const frag = new URLSearchParams(back.hash.replace(/^#/, ""));
        const tokens = tokensFrom(back.searchParams, frag);
        const err = back.searchParams.get("error") ?? frag.get("error");
        if (tokens.length || err) {
          steps.push({
            at, method: "302", url: back.origin + back.pathname, status: e.response.status,
            from: "idp", to: "app",
            label: err ? `The identity provider sends the user back to the app with an error` : `The identity provider sends the user back to the app with ${tokens.map((t) => (t.name === "code" ? "a code" : t.name)).join(" and ")}`,
            tokens,
            params: pick(back.searchParams, frag),
            error: err ? { code: err, description: back.searchParams.get("error_description") ?? frag.get("error_description") ?? undefined } : undefined,
          });
          continue;
        }
      }
    }

    // 5. form_post: the browser posts the code or tokens to the app.
    if (!idp && method === "POST" && (form.has("id_token") || form.has("code") || form.has("error")) && form.has("state")) {
      oidc = oidc || form.has("id_token");
      steps.push({
        ...base,
        from: "idp", to: "app",
        label: form.has("error") ? "The identity provider posts an error to the app" : `The identity provider posts ${tokensFrom(form).map((t) => t.name).join(" and ")} to the app (form_post)`,
        tokens: tokensFrom(form),
        params: pick(form),
        error: form.get("error") ? { code: form.get("error")!, description: form.get("error_description") ?? undefined } : undefined,
      });
      continue;
    }

    // 6. Error pages from the identity provider (AADSTS codes).
    if (idp) {
      const errStep = errorPage(e, base);
      if (errStep) {
        steps.push(errStep);
        continue;
      }
    }

    // 7. API calls with a bearer token.
    const auth = header(e.request.headers, "authorization");
    if (!idp && auth && /^Bearer\s+ey/i.test(auth)) {
      oauth = oauth || !oidc;
      steps.push({ ...base, from: "app", to: "api", label: `An API call to ${u.host} with an access token`, tokens: [{ name: "access_token", value: auth.replace(/^Bearer\s+/i, "") }] });
    }
  }

  const entra = entraHints(entries, steps);
  const kind: FlowKind = saml ? "saml" : oidc ? "oidc" : cc ? "client-credentials" : oauth ? "oauth" : "unknown";
  return {
    format: CAPTURE_FORMAT,
    version: 1,
    id: opts.id ?? newCaptureId(),
    kind,
    source,
    title: opts.title,
    startedAt: steps[0]?.at ?? entries[0]?.startedDateTime ?? new Date().toISOString(),
    ...(entra ? { entra } : {}),
    steps,
  };
}

const ENTRA_HOST = /(^|\.)(login\.microsoftonline\.com|login\.microsoft\.com|login\.windows\.net|sts\.windows\.net)$/i;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NOT_A_TENANT = new Set(["common", "organizations", "consumers", "favicon.ico", "error", "kmsi", "appverify"]);

function jwtTid(token: string): string | undefined {
  try {
    const tid = (b64urlJson(token.split(".")[1] ?? "") as { tid?: unknown })?.tid;
    return typeof tid === "string" && GUID.test(tid) ? tid : undefined;
  } catch {
    return undefined;
  }
}

/** The IDs and names Federation 360 uses to find a flow in Entra's sign-in log. Undefined when Entra wasn't involved. */
export function entraHints(entries: HarEntry[], steps: FlowStep[]): EntraHints | undefined {
  const requestIds = new Set<string>(), correlationIds = new Set<string>(), clientIds = new Set<string>();
  let tenant: string | undefined, tokenTid: string | undefined, from: string | undefined, to: string | undefined;
  for (const e of entries) {
    let u: URL;
    try {
      u = new URL(e.request.url);
    } catch {
      continue;
    }
    if (!ENTRA_HOST.test(u.hostname)) continue;
    from ??= e.startedDateTime;
    to = e.startedDateTime ?? to;
    const seg = decodeURIComponent(u.pathname.split("/")[1] ?? "");
    if (!tenant && seg && !NOT_A_TENANT.has(seg.toLowerCase()) && (GUID.test(seg) || /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(seg))) tenant = seg;
    const rid = header(e.response.headers, "x-ms-request-id");
    if (rid && GUID.test(rid)) requestIds.add(rid.toLowerCase());
    const crid = header(e.request.headers, "client-request-id");
    if (crid && GUID.test(crid)) correlationIds.add(crid.toLowerCase());
    const cid = u.searchParams.get("client_id") ?? formParams(e).get("client_id");
    if (cid) clientIds.add(cid);
  }
  if (!from) return undefined;
  for (const s of steps) {
    for (const t of s.tokens ?? []) tokenTid ??= t.name !== "code" ? jwtTid(t.value) : undefined;
    if (s.params?.client_id) clientIds.add(s.params.client_id);
    const m = s.error?.description?.match(/Correlation Id\s*:?\s*([0-9a-f-]{36})/i);
    if (m) correlationIds.add(m[1].toLowerCase());
  }
  // A token's tid is the tenant that actually signed the user in, even when the URL said "common".
  if (tokenTid) tenant = tokenTid;
  return { tenant, requestIds: [...requestIds], correlationIds: [...correlationIds], clientIds: [...clientIds], from, to };
}

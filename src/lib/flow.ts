/**
 * A sign-in flow as a list of hops, and the checks Federation 360 runs on it.
 *
 * The same shape comes from three places:
 *   - the Flow Tracer, which builds it from a HAR file recorded in the browser's developer tools
 *   - the lab test app (lab/testapp/server.mjs), which records the SAML and client credentials runs it takes part in
 *   - the Live test page, which records the OIDC sign-ins it runs itself
 *
 * Every check reuses the SAML and JWT checkers the decoder pages use.
 */
import { checkSaml, decodeSamlInput, parseSaml, type ParsedSaml, type SamlExpectations } from "./saml";
import { checkJwt, decodeJwt, guessKind, type DecodedJwt } from "./jwt";
import { parseCertificate } from "./x509";
import { playbookById } from "../data/playbooks";
import type { Finding } from "./types";

export const CAPTURE_FORMAT = "f360.capture";

export type Actor = "browser" | "app" | "idp" | "api" | "f360";

export const ACTOR_LABEL: Record<Actor, string> = {
  browser: "Browser",
  app: "App",
  idp: "Identity provider",
  api: "API",
  f360: "Federation 360",
};

export interface ApiCheck {
  accepted: boolean;
  checks: { name: string; ok: boolean; detail: string }[];
}

export interface FlowStep {
  /** ISO time of the hop. */
  at?: string;
  from: Actor;
  to: Actor;
  label: string;
  method?: string;
  url?: string;
  status?: number;
  /** A SAML message carried by this hop. value is what was on the wire (base64, deflated base64) or plain XML. */
  saml?: { param: "SAMLRequest" | "SAMLResponse"; value: string; binding: "redirect" | "post" };
  /** Tokens and codes carried by this hop. */
  tokens?: { name: string; value: string }[];
  /** Interesting protocol parameters (client_id, scope, state, grant_type ...). Secrets are never kept, only "(present)". */
  params?: Record<string, string>;
  error?: { code: string; description?: string };
  note?: string;
  /** How an API judged the access token it was given. */
  apiCheck?: ApiCheck;
}

export interface FlowExpectations {
  spEntityId?: string;
  acsUrl?: string;
  idpEntityId?: string;
  /** Base64 certificates published in the identity provider's metadata. */
  idpCerts?: string[];
  clientId?: string;
  audience?: string;
  issuer?: string;
  nonce?: string;
  state?: string;
}

export type FlowKind = "saml" | "oidc" | "oauth" | "client-credentials" | "unknown";

export interface FlowCapture {
  format: typeof CAPTURE_FORMAT;
  version: 1;
  id: string;
  kind: FlowKind;
  source: "testapp" | "f360" | "har";
  title: string;
  startedAt: string;
  expect?: FlowExpectations;
  steps: FlowStep[];
}

export const KIND_LABEL: Record<FlowKind, string> = {
  saml: "SAML sign-in",
  oidc: "OpenID Connect sign-in",
  oauth: "OAuth authorization",
  "client-credentials": "OAuth client credentials",
  unknown: "Sign-in flow",
};

export interface DecodedStep {
  findings: Finding[];
  saml?: { xml: string; parsed: ParsedSaml };
  jwts: { name: string; jwt: DecodedJwt }[];
}

export interface FlowAnalysis {
  steps: DecodedStep[];
  /** Findings about the flow as a whole: did it finish, do the hops agree with each other. */
  overall: Finding[];
}

const OPAQUE_TOKENS = new Set(["code", "refresh_token"]);
const looksLikeJwt = (v: string) => /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(v.trim());

/** Finds AADSTS codes and OAuth error codes and links them to a playbook when there is one. */
export function errorFindings(code: string, description = ""): Finding[] {
  const text = `${code} ${description}`;
  const aadsts = [...new Set(text.match(/AADSTS\d{4,}/g) ?? [])];
  const out: Finding[] = [];
  for (const c of aadsts) {
    out.push({
      severity: "critical",
      title: `Entra stopped the sign-in with ${c}`,
      detail: description || undefined,
      playbook: playbookById(c) ? c : undefined,
    });
  }
  if (!aadsts.length) {
    const oauth = code.replace(/[^a-z_]/gi, "");
    const pb = oauth === "invalid_grant" ? "invalid-grant" : oauth === "invalid_client" ? "invalid-client" : undefined;
    out.push({ severity: "critical", title: `Error: ${code || "unknown"}`, detail: description || undefined, playbook: pb });
  }
  return out;
}

async function thumbprints(certs: string[]): Promise<string[]> {
  const out: string[] = [];
  for (const c of certs) {
    try {
      out.push((await parseCertificate(c)).sha1);
    } catch {
      /* skip unreadable certificate */
    }
  }
  return out;
}

/** Runs every check on every hop. Time checks use the moment of each hop, so old captures don't show as expired. */
export async function analyzeCapture(c: FlowCapture): Promise<FlowAnalysis> {
  const exp: FlowExpectations = { ...(c.expect ?? {}) };
  const overall: Finding[] = [];
  const steps: DecodedStep[] = c.steps.map(() => ({ findings: [], jwts: [] }));

  // Pass 1: decode SAML and read what the app asked for, so the answer can be checked against the question.
  let request: ParsedSaml | undefined;
  for (let i = 0; i < c.steps.length; i++) {
    const s = c.steps[i];
    if (!s.saml) continue;
    try {
      const { xml } = await decodeSamlInput(s.saml.value);
      const parsed = await parseSaml(xml);
      steps[i].saml = { xml, parsed };
      if (parsed.kind === "AuthnRequest" && !request) request = parsed;
    } catch (e: any) {
      steps[i].findings.push({ severity: "warn", title: `The ${s.saml.param} couldn't be decoded`, detail: e?.message });
    }
  }
  if (request) {
    exp.spEntityId ??= request.issuer || undefined;
    exp.acsUrl ??= request.request?.acsUrl || undefined;
  }
  const idpThumbs = await thumbprints(exp.idpCerts ?? []);

  // OIDC: what the app asked for on the authorize request.
  const authorize = c.steps.find((s) => s.params?.response_type);
  if (authorize?.params) {
    exp.clientId ??= authorize.params.client_id;
    exp.nonce ??= authorize.params.nonce;
    exp.state ??= authorize.params.state;
  }

  for (let i = 0; i < c.steps.length; i++) {
    const s = c.steps[i];
    const d = steps[i];
    const at = s.at ? new Date(s.at) : new Date();

    if (d.saml) {
      const p = d.saml.parsed;
      const cert = p.signatures.find((x) => x.cert)?.cert;
      const samlExp: SamlExpectations = {
        spEntityId: exp.spEntityId,
        acsUrl: exp.acsUrl,
        idpEntityId: exp.idpEntityId,
        certThumbprint: cert && idpThumbs.includes(cert.sha1) ? cert.sha1 : idpThumbs[0],
      };
      // A request is checked against nothing but itself; the response is checked against the request.
      d.findings.push(...checkSaml(p, p.kind === "AuthnRequest" ? {} : samlExp, { at: new Date(at.getTime() + 1000), skewSeconds: 300 }));
      if (p.kind === "Response" && !p.statusCode.endsWith(":Success") && /AADSTS\d+/.test(p.statusMessage))
        d.findings.push(...errorFindings("", p.statusMessage).filter((f) => f.playbook).map((f) => ({ ...f, detail: undefined })));
      if (p.kind === "Response" && request) {
        const irt = p.inResponseTo || p.assertion?.subjectInResponseTo;
        if (irt && irt !== request.id)
          d.findings.push({ severity: "critical", title: "InResponseTo doesn't match the request in this flow", detail: `The response answers request ${irt}, but the app sent ${request.id}. The app will reject it.`, playbook: "saml-inresponseto" });
        else if (irt) d.findings.push({ severity: "ok", title: "The response answers the request in this flow", detail: `InResponseTo ${irt}` });
      }
    }

    for (const t of s.tokens ?? []) {
      // Authorization codes and refresh tokens are opaque to the client. Entra's codes even contain dots, so
      // they can look like a JWT; never try to decode them.
      if (OPAQUE_TOKENS.has(t.name) || !looksLikeJwt(t.value)) continue;
      try {
        const jwt = decodeJwt(t.value);
        d.jwts.push({ name: t.name, jwt });
        const kind = t.name === "id_token" ? "id_token" : t.name === "access_token" ? "access_token" : guessKind(jwt.payload);
        const f = checkJwt(
          jwt,
          kind === "id_token" ? { clientId: exp.clientId, issuer: exp.issuer } : { audience: exp.audience, issuer: exp.issuer },
          new Date(at.getTime() + 1000),
          300,
        );
        d.findings.push(...f.map((x) => ({ ...x, title: `${t.name}: ${x.title}` })));
        if (kind === "id_token" && exp.nonce) {
          if (jwt.payload.nonce === exp.nonce) d.findings.push({ severity: "ok", title: "id_token: nonce matches the sign-in request" });
          else d.findings.push({ severity: "critical", title: "id_token: nonce doesn't match the sign-in request", detail: `Sent ${exp.nonce}, got ${jwt.payload.nonce ?? "none"}. The app must reject this token (possible replay).`, playbook: "state-nonce" });
        }
      } catch (e: any) {
        d.findings.push({ severity: "warn", title: `${t.name} couldn't be decoded`, detail: e?.message });
      }
    }

    if (s.params?.state && exp.state && s !== authorize && s.params.state !== exp.state)
      d.findings.push({ severity: "critical", title: "state doesn't match the sign-in request", detail: `Sent ${exp.state}, got back ${s.params.state}. The app must reject this response.`, playbook: "state-nonce" });

    if (s === authorize && s.params) {
      const rt = s.params.response_type ?? "";
      if (/\btoken\b/.test(rt)) d.findings.push({ severity: "warn", title: "Implicit flow (tokens in the address bar)", detail: "response_type includes token. Move to authorization code with PKCE." });
      if (/\bcode\b/.test(rt) && !s.params.code_challenge_method)
        d.findings.push({ severity: "info", title: "No PKCE on this authorization request", detail: "Public clients (single-page and mobile apps) must use PKCE. Confidential web apps should use it too." });
      else if (s.params.code_challenge_method) d.findings.push({ severity: "ok", title: `PKCE in use (${s.params.code_challenge_method})` });
    }

    if (s.error) d.findings.push(...errorFindings(s.error.code, s.error.description));
    else if (s.status && s.status >= 400 && !s.apiCheck)
      d.findings.push({ severity: "warn", title: `HTTP ${s.status}`, detail: "This hop failed. Open its details to see what came back." });

    if (s.apiCheck) {
      d.findings.push({
        severity: s.apiCheck.accepted ? "ok" : "critical",
        title: s.apiCheck.accepted ? "The API accepted the access token" : "The API rejected the access token",
      });
      for (const ch of s.apiCheck.checks) d.findings.push({ severity: ch.ok ? "ok" : "critical", title: ch.name, detail: ch.detail });
    }
  }

  // Overall
  const anyError = c.steps.some((s) => s.error) || steps.some((d) => d.findings.some((f) => f.severity === "critical"));
  const samlDone = steps.some((d) => d.saml?.parsed.kind === "Response" && d.saml.parsed.statusCode.endsWith(":Success"));
  const tokensDone = c.steps.some((s) => s.tokens?.some((t) => (t.name === "id_token" || t.name === "access_token") && looksLikeJwt(t.value)));
  const apiDone = c.steps.some((s) => s.apiCheck?.accepted);
  if (!c.steps.length) overall.push({ severity: "warn", title: "No sign-in traffic found", detail: "Nothing in this capture looks like SAML, OpenID Connect or OAuth. Record again with Preserve log ticked, from before you click Sign in." });
  else if (anyError) overall.push({ severity: "critical", title: "The flow has problems", detail: "Look for the hops marked Problem below. Each one links to a playbook when there is one." });
  else if (samlDone || tokensDone || apiDone) overall.push({ severity: "ok", title: "The flow completed", detail: samlDone ? "The identity provider returned a successful SAML response." : apiDone ? "Tokens were issued and the API accepted them." : "The identity provider issued tokens." });
  else overall.push({ severity: "info", title: "The flow didn't reach the end in this capture", detail: "No successful SAML response or token was seen. The recording may have stopped early, or the sign-in is still waiting on the user." });
  if (request && !steps.some((d) => d.saml?.parsed.kind === "Response"))
    overall.push({ severity: "info", title: "The app sent a SAML request but no response came back in this capture" });
  return { steps, overall };
}

const REDACTED = "REDACTED";

/** Removes what could be replayed: JWT signatures, codes and SAML signature values. What's left still decodes. */
export async function redactCapture(c: FlowCapture): Promise<FlowCapture> {
  const steps: FlowStep[] = [];
  for (const s of c.steps) {
    const n: FlowStep = { ...s };
    if (s.tokens)
      n.tokens = s.tokens.map((t) => ({
        name: t.name,
        value: looksLikeJwt(t.value) ? t.value.split(".").slice(0, 2).join(".") + "." + REDACTED : REDACTED,
      }));
    if (s.saml) {
      try {
        const { xml } = await decodeSamlInput(s.saml.value);
        n.saml = { ...s.saml, value: xml.replace(/(<(?:\w+:)?SignatureValue[^>]*>)[\s\S]*?(<\/(?:\w+:)?SignatureValue>)/g, `$1${REDACTED}$2`) };
      } catch {
        n.saml = { ...s.saml, value: REDACTED };
      }
    }
    if (s.params) {
      n.params = { ...s.params };
      for (const k of ["code", "code_verifier", "client_secret", "client_assertion", "refresh_token", "password"]) if (k in n.params) n.params[k] = "(present)";
    }
    if (s.url) n.url = redactUrl(s.url);
    steps.push(n);
  }
  return { ...c, steps };
}

/** Hides code, tokens and SAML payloads in a URL; keeps everything else readable. */
export function redactUrl(u: string): string {
  return u.replace(/([?&#](?:code|id_token|access_token|refresh_token|SAMLResponse|client_assertion)=)[^&#]*/g, `$1${REDACTED}`);
}

export const newCaptureId = () => new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14) + "-" + Math.random().toString(36).slice(2, 8);

// Federation 360 lab test app: the part that runs the same everywhere.
//
// It plays three parts in real sign-ins against the free lab tenant and records every hop, so Federation 360's
// Live test page can show and check them:
//
//   SAML service provider   saml/login sends a SAML request to Entra; saml/acs receives Entra's SAML response.
//   OAuth daemon            /api/run/client-credentials gets an app-only token with a certificate (no secret).
//   Protected API           /api/whoami checks an access token the way a real API must: signature, issuer,
//                           audience, lifetime, tenant and permission. Federation 360's OIDC test calls it.
//
// Two hosts wrap it, and neither adds behaviour of its own:
//   lab/testapp/server.mjs         Docker on your PC (http://localhost:5174). Keeps captures in lab/testapp/captures.
//   lab/testapp/azure/api/testapp  Azure Static Web Apps Free (managed Functions). Keeps nothing: each capture goes
//                                  back to Federation 360 in the response, or in the URL fragment after a SAML
//                                  sign-in, and Federation 360 stores it in your browser.
//
// No dependencies. Node 18 or later.

import { createHash, createPrivateKey, createPublicKey, randomUUID, sign, verify, X509Certificate, constants } from "node:crypto";
import { deflateRawSync, inflateRawSync } from "node:zlib";

export const CAPTURE_FORMAT = "f360.capture";
/** Fragment parameter that carries a capture back to Federation 360 from a test app that keeps no captures. */
export const CAPTURE_FRAGMENT = "f360capture";
const LOGIN = "https://login.microsoftonline.com";
const SAML_COOKIE = "f360_saml";
export const MAX_BODY = 2 * 1024 * 1024;

const b64url = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64url = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
const now = () => new Date().toISOString();
export const xmlEscape = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const ID_RE = /^[\w-]{6,64}$/;

export const newCaptureId = () => new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14) + "-" + randomUUID().slice(0, 6);

/** Packs JSON small enough for a cookie or a URL: raw DEFLATE, then base64url. */
export const pack = (obj) => b64url(deflateRawSync(Buffer.from(JSON.stringify(obj), "utf8")));
export const unpack = (s) => JSON.parse(inflateRawSync(fromB64url(s)).toString("utf8"));

// ------------------------------------------------------------------ SAML

/** Builds a Redirect-binding AuthnRequest. fault "issuer" or "acs" breaks it on purpose. */
export function buildAuthnRequest({ tenantId, entityId, acsUrl, fault, forceAuthn }) {
  const id = "_" + randomUUID().replace(/-/g, "");
  const issuer = fault === "issuer" ? entityId + "-wrong" : entityId;
  const acs = fault === "acs" ? acsUrl.replace(/\/saml\/acs$/, "/saml/acs-wrong") : acsUrl;
  const destination = `${LOGIN}/${tenantId}/saml2`;
  const xml =
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
    ` ID="${id}" Version="2.0" IssueInstant="${now().replace(/\.\d{3}Z$/, "Z")}" Destination="${destination}"` +
    ` AssertionConsumerServiceURL="${xmlEscape(acs)}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"${forceAuthn ? ' ForceAuthn="true"' : ""}>` +
    `<saml:Issuer>${xmlEscape(issuer)}</saml:Issuer>` +
    `<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"/>` +
    `</samlp:AuthnRequest>`;
  const value = deflateRawSync(Buffer.from(xml, "utf8")).toString("base64");
  return { id, xml, value, destination };
}

/** Signing certificates from Entra's federation metadata for one SAML app. */
export function metadataCerts(xml) {
  const idp = xml.match(/<(?:\w+:)?IDPSSODescriptor[\s\S]*?<\/(?:\w+:)?IDPSSODescriptor>/)?.[0] ?? xml;
  return [...new Set([...idp.matchAll(/<(?:\w+:)?X509Certificate>\s*([A-Za-z0-9+/=\s]+?)\s*<\/(?:\w+:)?X509Certificate>/g)].map((m) => m[1].replace(/\s+/g, "")))];
}

// ------------------------------------------------------------------ tokens

export function decodeJwt(token) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new Error(`A JWT has three parts; this has ${parts.length}.`);
  return { header: JSON.parse(fromB64url(parts[0]).toString("utf8")), payload: JSON.parse(fromB64url(parts[1]).toString("utf8")), signingInput: `${parts[0]}.${parts[1]}`, signature: fromB64url(parts[2]) };
}

/**
 * Checks an access token the way an API must before trusting it. Returns every check, not just the first failure,
 * so you can see all that's wrong at once.
 */
export async function validateAccessToken(token, { tenantId, audience, scope, role, getJwks, at = Date.now(), skewSeconds = 300 }) {
  const checks = [];
  const add = (name, ok, detail) => checks.push({ name, ok, detail });
  let t;
  try {
    t = decodeJwt(token.replace(/^Bearer\s+/i, ""));
  } catch (e) {
    add("Token format", false, `Not a readable JWT: ${e.message}`);
    return { accepted: false, checks, claims: null };
  }
  const { header: h, payload: p } = t;

  // Signature
  if (h.nonce) add("Signature", false, "This is a Microsoft Graph token (its header has a nonce). Graph tokens are only for Graph and never verify anywhere else. The client asked for the wrong scope.");
  else if (h.alg !== "RS256") add("Signature", false, `Unexpected algorithm ${h.alg}. Entra signs access tokens with RS256.`);
  else {
    let jwks = await getJwks(false);
    let jwk = jwks.keys?.find((k) => k.kid === h.kid);
    if (!jwk) {
      jwks = await getJwks(true); // keys roll; refetch once before failing
      jwk = jwks.keys?.find((k) => k.kid === h.kid);
    }
    if (!jwk) add("Signature", false, `No published key has kid ${h.kid}. The token wasn't issued by this tenant, or it was tampered with.`);
    else {
      const ok = verify("RSA-SHA256", Buffer.from(t.signingInput), createPublicKey({ key: { kty: jwk.kty, n: jwk.n, e: jwk.e }, format: "jwk" }), t.signature);
      add("Signature", ok, ok ? `Verified with Entra's published key ${h.kid}.` : "The signature doesn't match. The token was changed after Entra signed it.");
    }
  }

  // Issuer
  const issuers = [`${LOGIN}/${tenantId}/v2.0`, `https://sts.windows.net/${tenantId}/`];
  add("Issuer", issuers.includes(p.iss), issuers.includes(p.iss) ? p.iss : `iss is "${p.iss}". This API only trusts ${issuers.join(" or ")}.`);

  // Audience
  const auds = [audience, `api://${audience}`];
  const aud = [].concat(p.aud ?? []);
  const audOk = aud.some((a) => auds.includes(a));
  add("Audience", audOk, audOk ? `Token is for this API (${aud.join(", ")}).` : `Token is for "${aud.join(", ") || "nobody"}", not this API (${auds.join(" or ")}). The client must ask for a scope of this API, such as api://${audience}/${scope}.`);

  // Lifetime
  const s = at / 1000;
  if (typeof p.exp !== "number") add("Lifetime", false, "No exp claim.");
  else if (s - skewSeconds >= p.exp) add("Lifetime", false, `Expired at ${new Date(p.exp * 1000).toISOString()}.`);
  else if (typeof p.nbf === "number" && s + skewSeconds < p.nbf) add("Lifetime", false, `Not valid until ${new Date(p.nbf * 1000).toISOString()}. Check the clocks.`);
  else add("Lifetime", true, `Valid until ${new Date(p.exp * 1000).toISOString()} (${Math.round((p.exp - s) / 60)} min left).`);

  // Tenant
  add("Tenant", p.tid === tenantId, p.tid === tenantId ? `Issued by the lab tenant ${tenantId}.` : `tid is ${p.tid}, not the lab tenant.`);

  // Permission
  const scopes = String(p.scp ?? "").split(" ").filter(Boolean);
  const roles = [].concat(p.roles ?? []);
  if (scopes.length) add("Permission", scopes.includes(scope), scopes.includes(scope) ? `Delegated scope ${scope} (a signed-in user is present).` : `Token has scopes "${scopes.join(" ")}" but this API needs ${scope}.`);
  else if (roles.length) add("Permission", roles.includes(role), roles.includes(role) ? `Application role ${role} (app-only, no user).` : `Token has roles "${roles.join(", ")}" but this API needs ${role}.`);
  else add("Permission", false, `No scp or roles claim. The client has no permission on this API: grant ${scope} (delegated) or ${role} (application) and consent.`);

  return { accepted: checks.every((c) => c.ok), checks, claims: p };
}

/** A private_key_jwt client assertion (PS256, x5t#S256 and x5t), as Microsoft documents. */
export function clientAssertion({ clientId, tenantId, keyPem, certPem }) {
  const der = new X509Certificate(certPem).raw;
  const header = { alg: "PS256", typ: "JWT", "x5t#S256": b64url(createHash("sha256").update(der).digest()), x5t: b64url(createHash("sha1").update(der).digest()) };
  const iat = Math.floor(Date.now() / 1000);
  const payload = { aud: `${LOGIN}/${tenantId}/oauth2/v2.0/token`, iss: clientId, sub: clientId, jti: randomUUID(), nbf: iat, iat, exp: iat + 300 };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = sign("sha256", Buffer.from(input), { key: createPrivateKey(keyPem), padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
  return `${input}.${b64url(sig)}`;
}

// ------------------------------------------------------------------ the app

/**
 * Builds the test app as one function: request in, response out. The hosts translate to and from it.
 *
 * options:
 *   config      { tenantId, f360Url, publicUrl, labUsers, saml: { entityId, appId }, liveTest: { clientId },
 *                 api: { clientId, scope, role }, daemon: { clientId } }
 *   store       { get(id), put(capture), list(), clear() }, or null for a test app that keeps no captures
 *   daemonKeys  () => ({ keyPem, certPem }) or null when the client credentials certificate isn't there
 *   samlPrefix  "" on your PC (/saml/acs) or "/api" on Azure, where every function lives under /api
 *   fetch, log
 *
 * request:  { method, path, query: URLSearchParams, headers: { lower-case name: value }, body: string }
 * response: { status, headers, body: string }
 */
export function createHandler({ config, store = null, daemonKeys = () => null, samlPrefix = "", fetch: fetchImpl = globalThis.fetch, log = () => {} } = {}) {
  const cfg = config ?? {};
  const stateless = !store;
  const publicUrl = (cfg.publicUrl || "http://localhost:5174").replace(/\/+$/, "");
  const f360 = (cfg.f360Url || "http://localhost:5173").replace(/\/+$/, "");
  const f360Origin = new URL(f360).origin;
  const acsUrl = `${publicUrl}${samlPrefix}/saml/acs`;
  const loginUrl = `${publicUrl}${samlPrefix}/saml/login`;
  const cookiePath = `${samlPrefix}/saml`;
  const secure = publicUrl.startsWith("https:");
  const api = { scope: "Jobs.Read", role: "Jobs.Read.All", ...(cfg.api ?? {}) };

  let jwksCache = null;
  const getJwks = async (refresh) => {
    if (!refresh && jwksCache && Date.now() - jwksCache.at < 3600_000) return jwksCache.keys;
    const r = await fetchImpl(`${LOGIN}/${cfg.tenantId}/discovery/v2.0/keys`);
    if (!r.ok) throw new Error(`Couldn't read Entra's signing keys (HTTP ${r.status})`);
    jwksCache = { at: Date.now(), keys: await r.json() };
    return jwksCache.keys;
  };

  const keys = () => {
    try {
      return cfg.daemon?.clientId ? daemonKeys() : null;
    } catch {
      return null;
    }
  };

  const publicConfig = () => ({
    configured: !!cfg.tenantId,
    tenantId: cfg.tenantId ?? null,
    publicUrl,
    f360Url: f360,
    host: stateless ? "azure" : "local",
    /** True when this test app keeps no captures, so Federation 360 stores them in the browser. */
    stateless,
    labUsers: Array.isArray(cfg.labUsers) ? cfg.labUsers.filter((u) => typeof u === "string") : [],
    saml: cfg.saml?.entityId ? { entityId: cfg.saml.entityId, acsUrl, loginUrl } : null,
    oidc: cfg.liveTest?.clientId && api.clientId ? { clientId: cfg.liveTest.clientId, scope: `openid profile email api://${api.clientId}/${api.scope}`, apiAudience: api.clientId } : null,
    clientCredentials: keys() && api.clientId ? { clientId: cfg.daemon.clientId, scope: `api://${api.clientId}/.default` } : null,
  });

  const respond = (status, body, headers = {}) => {
    const isJson = typeof body !== "string";
    return { status, headers: { "Content-Type": isJson ? "application/json" : "text/html; charset=utf-8", "Cache-Control": "no-store", ...headers }, body: isJson ? JSON.stringify(body) : body };
  };
  const redirect = (status, location, headers = {}) => ({ status, headers: { Location: location, "Cache-Control": "no-store", ...headers }, body: "" });

  const validate = (token) => validateAccessToken(token, { tenantId: cfg.tenantId, audience: api.clientId, scope: api.scope, role: api.role, getJwks });

  const cookie = (headers, name) => {
    for (const part of String(headers.cookie ?? "").split(";")) {
      const i = part.indexOf("=");
      if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
    }
    return null;
  };
  const setCookie = (value, maxAge) => `${SAML_COOKIE}=${value}; Path=${cookiePath}; Max-Age=${maxAge}; HttpOnly${secure ? "; Secure; SameSite=None" : "; SameSite=Lax"}`;

  function samlLogin(query) {
    if (!cfg.saml?.entityId) return respond(409, { error: "SAML isn't set up. Run lab/testapp/Start-F360TestApp.ps1 (or the Azure deploy script)." });
    const fault = ["issuer", "acs"].includes(query.get("fault")) ? query.get("fault") : undefined;
    const r = buildAuthnRequest({ tenantId: cfg.tenantId, entityId: cfg.saml.entityId, acsUrl, fault, forceAuthn: query.get("force") === "1" });
    const id = newCaptureId();
    const location = `${r.destination}?${new URLSearchParams({ SAMLRequest: r.value, RelayState: id })}`;
    const c = {
      format: CAPTURE_FORMAT, version: 1, id, kind: "saml", source: "testapp",
      title: fault === "issuer" ? "SAML sign-in with a wrong Issuer (on purpose)" : fault === "acs" ? "SAML sign-in with a wrong reply URL (on purpose)" : "SAML sign-in (started by the app)",
      startedAt: now(),
      expect: { spEntityId: cfg.saml.entityId, acsUrl, idpEntityId: `https://sts.windows.net/${cfg.tenantId}/` },
      steps: [{
        at: now(), from: "app", to: "idp", method: "302", url: r.destination,
        label: "The test app sends a SAML request to Entra (Redirect binding)",
        saml: { param: "SAMLRequest", value: r.value, binding: "redirect" },
        params: { RelayState: id },
        note: fault ? `Broken on purpose (${fault === "issuer" ? `Issuer is ${cfg.saml.entityId}-wrong` : "the reply URL isn't registered"}). Entra should refuse it with ${fault === "issuer" ? "AADSTS700016" : "AADSTS50011"} and never come back here.` : undefined,
      }],
    };
    log(`SAML request ${r.id} -> Entra${fault ? ` (fault: ${fault})` : ""}`);
    if (store) {
      store.put(c);
      return redirect(302, location);
    }
    // Nothing is kept on Azure: the first hop rides in a short-lived cookie until Entra posts back.
    return redirect(302, location, { "Set-Cookie": setCookie(pack(c), 900) });
  }

  async function samlAcs(headers, body) {
    const form = new URLSearchParams(body);
    const value = form.get("SAMLResponse");
    if (!value) return respond(400, "<p>No SAMLResponse in this post.</p>");
    const relay = form.get("RelayState") || "";
    let c = null;
    if (ID_RE.test(relay)) {
      if (store) c = store.get(relay);
      else {
        try {
          const saved = cookie(headers, SAML_COOKIE);
          const fromCookie = saved ? unpack(saved) : null;
          if (fromCookie?.id === relay) c = fromCookie;
        } catch {
          c = null;
        }
      }
    }
    if (!c) {
      c = {
        format: CAPTURE_FORMAT, version: 1, id: newCaptureId(), kind: "saml", source: "testapp",
        title: "SAML sign-in (started from My Apps)", startedAt: now(),
        expect: { spEntityId: cfg.saml?.entityId, acsUrl, idpEntityId: `https://sts.windows.net/${cfg.tenantId}/` },
        steps: [],
      };
    }
    const step = { at: now(), from: "idp", to: "app", method: "POST", url: acsUrl, label: "Entra posts the SAML response to the test app (POST binding)", saml: { param: "SAMLResponse", value, binding: "post" } };
    try {
      const r = await fetchImpl(`${LOGIN}/${cfg.tenantId}/federationmetadata/2007-06/federationmetadata.xml?appid=${cfg.saml?.appId ?? ""}`);
      c.expect.idpCerts = metadataCerts(await r.text());
    } catch (e) {
      step.note = `Couldn't read Entra's federation metadata to compare the signing certificate: ${e.message}`;
    }
    c.steps.push(step);
    log(`SAML response received -> capture ${c.id}`);
    if (store) {
      store.put(c);
      return redirect(303, `${f360}/?capture=${encodeURIComponent(c.id)}#livetest`);
    }
    // The fragment never leaves the browser, so the SAML response isn't sent to any server on the way back.
    return redirect(303, `${f360}/#livetest&${CAPTURE_FRAGMENT}=${pack(c)}`, { "Set-Cookie": setCookie("", 0) });
  }

  async function clientCredentials() {
    const k = keys();
    if (!k) return respond(409, { error: "Client credentials aren't set up. Run lab/testapp/Start-F360TestApp.ps1 to create the certificate (and the Azure deploy script to copy it to Azure)." });
    const tokenUrl = `${LOGIN}/${cfg.tenantId}/oauth2/v2.0/token`;
    const c = { format: CAPTURE_FORMAT, version: 1, id: newCaptureId(), kind: "client-credentials", source: "testapp", title: "Client credentials with a certificate", startedAt: now(), expect: { audience: api.clientId }, steps: [] };
    const scope = `api://${api.clientId}/.default`;
    const step = {
      at: now(), from: "app", to: "idp", method: "POST", url: tokenUrl,
      label: "The test app (as LAB-Daemon) asks Entra for a token for itself",
      params: { grant_type: "client_credentials", client_id: cfg.daemon.clientId, scope, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: "(present)" },
      note: stateless
        ? "The app proves who it is with a short-lived JWT signed by its certificate's private key. The key is in this lab test app's Azure settings, and it only works for LAB-Daemon in the lab tenant."
        : "The app proves who it is with a short-lived JWT signed by its certificate's private key. The private key never leaves your PC.",
    };
    let token;
    try {
      const assertion = clientAssertion({ clientId: cfg.daemon.clientId, tenantId: cfg.tenantId, keyPem: k.keyPem, certPem: k.certPem });
      const r = await fetchImpl(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "client_credentials", client_id: cfg.daemon.clientId, scope, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion }),
      });
      step.status = r.status;
      const j = await r.json().catch(() => ({}));
      if (j.access_token) {
        token = j.access_token;
        step.tokens = [{ name: "access_token", value: token }];
      } else step.error = { code: j.error || `HTTP ${r.status}`, description: j.error_description };
    } catch (e) {
      step.error = { code: "request_failed", description: e.message };
    }
    c.steps.push(step);
    if (token) c.steps.push(await apiStep(token, "The test app calls the test API with the token"));
    store?.put(c);
    log(`Client credentials -> ${token ? "token issued" : step.error?.code} (capture ${c.id})`);
    return respond(200, c);
  }

  async function apiStep(token, label, method = "GET") {
    let apiCheck;
    try {
      apiCheck = await validate(token);
    } catch (e) {
      apiCheck = { accepted: false, checks: [{ name: "Signature", ok: false, detail: e.message }] };
    }
    return { at: now(), from: "app", to: "api", method, url: `${publicUrl}/api/whoami`, status: apiCheck.accepted ? 200 : 401, label, tokens: [{ name: "access_token", value: token }], apiCheck: { accepted: apiCheck.accepted, checks: apiCheck.checks } };
  }

  async function whoami(method, query, headers, body) {
    // Federation 360 posts the token as an access_token form field. That keeps the request "simple" (no CORS
    // preflight), and on Azure it is the only way the token arrives intact: Static Web Apps replaces the
    // Authorization header on every request it passes to its managed functions with its own short-lived internal
    // token (HS256, issued by <site>.scm.azurewebsites.net). So the form field wins, and on Azure the
    // Authorization header is never trusted.
    const field = method === "POST" ? new URLSearchParams(body).get("access_token") : null;
    const auth = String(headers.authorization ?? "");
    const bearer = /^Bearer\s+\S+/i.test(auth) ? auth.replace(/^Bearer\s+/i, "") : null;
    const token = field || (stateless ? null : bearer);
    if (!token) {
      const detail = stateless && bearer
        ? "On Azure Static Web Apps the Authorization header never reaches the API: the platform replaces it with its own internal token. Send the access token as an access_token form field (POST, application/x-www-form-urlencoded) instead."
        : "No access_token form field and no Authorization: Bearer header.";
      return respond(401, { accepted: false, checks: [{ name: "Token present", ok: false, detail }] }, { "WWW-Authenticate": "Bearer" });
    }
    const step = await apiStep(token, "Federation 360 calls the test API with the access token", field ? "POST" : "GET");
    const cid = query.get("capture");
    const existing = store && cid && ID_RE.test(cid) ? store.get(cid) : null;
    if (existing) {
      existing.steps.push(step);
      store.put(existing);
    }
    return respond(step.apiCheck.accepted ? 200 : 401, { ...step.apiCheck, step });
  }

  async function route({ method, path, query, headers, body }) {
    const p = path.replace(/\/+$/, "") || "/";
    // On Azure every function lives under /api, so the SAML endpoints are /api/saml/... there.
    const s = samlPrefix && p.startsWith(`${samlPrefix}/saml/`) ? p.slice(samlPrefix.length) : p;

    if (method === "OPTIONS") return respond(204, "");
    if (p === "/api/health") return respond(200, { ok: true, app: "f360-testapp", host: stateless ? "azure" : "local", configured: !!cfg.tenantId });
    if (p === "/api/config") return respond(200, publicConfig());
    if (s === "/saml/login" && method === "GET") return samlLogin(query);
    if (s === "/saml/acs" && method === "POST") return await samlAcs(headers, body);
    if (s === "/saml/acs-wrong") return respond(400, "<p>This reply URL isn't registered in Entra. If you got here, Entra accepted a reply URL it shouldn't have.</p>");
    if (p === "/api/run/client-credentials" && method === "POST") return await clientCredentials();
    if (p === "/api/whoami") return await whoami(method, query, headers, body);

    if (p === "/api/captures" || p.startsWith("/api/captures/")) {
      if (!store) return respond(404, { error: "This test app keeps no captures. Federation 360 stores them in your browser." });
      if (p === "/api/captures" && method === "GET") return respond(200, store.list());
      if (p === "/api/captures" && method === "DELETE") {
        store.clear();
        return respond(200, { ok: true });
      }
      if (p === "/api/captures" && method === "POST") {
        let c;
        try {
          c = JSON.parse(body);
        } catch {
          c = null;
        }
        if (c?.format !== CAPTURE_FORMAT || !Array.isArray(c.steps) || typeof c.id !== "string" || !ID_RE.test(c.id)) return respond(400, { error: "Not an f360.capture" });
        store.put(c);
        return respond(201, { id: c.id });
      }
      const m = p.match(/^\/api\/captures\/([\w-]+)$/);
      if (m && method === "GET") {
        const c = ID_RE.test(m[1]) ? store.get(m[1]) : null;
        return c ? respond(200, c) : respond(404, { error: "No such capture" });
      }
    }

    if (p === "/" || p === "/api")
      return respond(200, `<!doctype html><meta charset="utf-8"><title>F360 test app</title><body style="font-family:system-ui;max-width:640px;margin:40px auto;padding:0 16px"><h1>Federation 360 test app</h1><p>${cfg.tenantId ? `Set up for lab tenant <code>${xmlEscape(cfg.tenantId)}</code>${stateless ? ", running on Azure Static Web Apps (Free)" : ""}.` : "Not set up yet. Run lab/testapp/Start-F360TestApp.ps1."}</p><p>Run tests from Federation 360: <a href="${xmlEscape(f360)}/#livetest">${xmlEscape(f360)}/#livetest</a></p></body>`);
    return respond(404, { error: "Not found" });
  }

  return async function handle(req) {
    let res;
    try {
      res = await route({ method: req.method ?? "GET", path: req.path ?? "/", query: req.query ?? new URLSearchParams(), headers: req.headers ?? {}, body: req.body ?? "" });
    } catch (e) {
      log("Error:", e.message);
      res = respond(e.status ?? 500, { error: e.message });
    }
    if (req.headers?.origin === f360Origin) {
      Object.assign(res.headers, {
        "Access-Control-Allow-Origin": f360Origin,
        Vary: "Origin",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      });
    }
    return res;
  };
}

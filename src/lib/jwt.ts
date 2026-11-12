import { b64ToBytes, b64urlJson, toUtf8 } from "./encoding";
import type { Finding } from "./types";

export interface DecodedJwt {
  header: Record<string, any>;
  payload: Record<string, any>;
  signingInput: string;
  signature: Uint8Array;
  raw: string;
}

export function decodeJwt(input: string): DecodedJwt {
  let raw = input.trim().replace(/^Bearer\s+/i, "");
  const m = raw.match(/(?:id_token|access_token)=([^&\s]+)/);
  if (m) raw = m[1];
  raw = raw.replace(/^"|"$/g, "");
  const parts = raw.split(".");
  if (parts.length === 5) throw new Error("This is an encrypted token (JWE, five parts). Only the intended recipient can read it.");
  if (parts.length !== 3) throw new Error(`A JWT has three parts separated by dots. This has ${parts.length}. Check you copied the whole token.`);
  try {
    return {
      header: b64urlJson(parts[0]) as Record<string, any>,
      payload: b64urlJson(parts[1]) as Record<string, any>,
      signingInput: parts[0] + "." + parts[1],
      signature: b64ToBytes(parts[2] || ""),
      raw,
    };
  } catch {
    throw new Error("The header or payload isn't valid base64url JSON. The token may be truncated.");
  }
}

export type TokenKind = "id_token" | "access_token" | "unknown";

export function guessKind(p: Record<string, any>): TokenKind {
  if (p.scp || p.roles || p.scope || p.appid || p.azp && p.aud !== p.azp) return "access_token";
  if (p.nonce || p.at_hash || p.c_hash || (p.aud && p.sub && (p.email || p.preferred_username || p.name))) return "id_token";
  return "unknown";
}

export interface JwtExpectations {
  audience?: string;
  issuer?: string;
  clientId?: string;
}

const iso = (sec?: number) => (typeof sec === "number" ? new Date(sec * 1000).toISOString().replace(".000", "") : "missing");

export const CLAIM_HELP: Record<string, string> = {
  iss: "Issuer: who minted the token. Must exactly match the issuer your app trusts.",
  aud: "Audience: who the token is for. An API must reject tokens whose aud isn't its own ID.",
  sub: "Subject: stable ID for the user (pairwise per app in Entra).",
  oid: "Entra object ID of the user or service principal. Same across apps in a tenant.",
  tid: "Entra tenant ID the token was issued from.",
  exp: "Expiry time (seconds since 1970).",
  nbf: "Not valid before this time.",
  iat: "Issued at.",
  azp: "Authorized party: the client app that requested the token (v2).",
  appid: "Client app that requested the token (v1 tokens).",
  scp: "Delegated permissions (scopes) granted for the signed-in user.",
  roles: "App roles. In app-only tokens these are the application permissions.",
  nonce: "Random value from the sign-in request. The app must check it matches, to stop replay.",
  upn: "User principal name.",
  preferred_username: "Display username. Not stable, don't use it as a key.",
  email: "Email address, if released. Not guaranteed unique or verified.",
  groups: "Group object IDs (if the groups claim is configured).",
  amr: "Authentication methods used, e.g. pwd, mfa.",
  acr: "Authentication context class.",
  ver: "Token version: 1.0 or 2.0. Determines the issuer format.",
  idtyp: "Identity type: app for app-only tokens, user for delegated.",
  wids: "Entra directory role template IDs the user holds.",
  xms_cc: "Client capabilities, e.g. CP1 for continuous access evaluation.",
};

export function checkJwt(t: DecodedJwt, exp: JwtExpectations, at: Date, skewSeconds: number): Finding[] {
  const f: Finding[] = [];
  const { header: h, payload: p } = t;
  const now = at.getTime() / 1000;
  const kind = guessKind(p);

  f.push({ severity: "info", title: `Looks like ${kind === "id_token" ? "an ID token (OIDC sign-in)" : kind === "access_token" ? "an access token (OAuth API call)" : "a JWT of unknown type"}`, detail: kind === "id_token" ? "ID tokens are for the app that signed the user in. Don't send them to APIs." : kind === "access_token" ? "Access tokens are for the API named in aud. The client app shouldn't depend on their contents." : undefined });

  // alg
  if (!h.alg || h.alg === "none") f.push({ severity: "critical", title: "Unsigned token (alg: none)", detail: "Never accept unsigned tokens." });
  else if (/^HS/.test(h.alg)) f.push({ severity: "warn", title: `Symmetric signature (${h.alg})`, detail: "Signed with a shared secret. Fine between two parties you control; identity providers normally use RS256 or ES256." });
  else f.push({ severity: "ok", title: `Signed with ${h.alg}`, detail: h.kid ? `Key ID (kid): ${h.kid}` : "No kid in header." });
  if (h.nonce)
    f.push({ severity: "info", title: "Microsoft Graph token (header has a nonce)", detail: "Graph tokens are meant for Graph only. Their signature won't verify in your app by design. If your API receives one, the client requested the wrong scope/resource.", playbook: "graph-token" });

  // times
  if (typeof p.exp !== "number") f.push({ severity: "warn", title: "No exp claim" });
  else if (now - skewSeconds >= p.exp) f.push({ severity: "critical", title: "Token has expired", detail: `exp ${iso(p.exp)}, evaluated at ${at.toISOString()}. Get a new token (refresh token or new sign-in). If this is an old capture, evaluate it as of issue time.`, playbook: "token-expired" });
  else f.push({ severity: "ok", title: `Not expired (${Math.round((p.exp - now) / 60)} min left)`, detail: `exp ${iso(p.exp)}` });
  if (typeof p.nbf === "number" && now + skewSeconds < p.nbf)
    f.push({ severity: "critical", title: "Token not valid yet (nbf in the future)", detail: `nbf ${iso(p.nbf)}. Clock skew between the issuer and this machine.`, playbook: "clock-skew" });
  if (typeof p.iat === "number" && typeof p.exp === "number") {
    const life = (p.exp - p.iat) / 60;
    f.push({ severity: "info", title: `Lifetime ${Math.round(life)} minutes`, detail: `Issued ${iso(p.iat)}` });
  }

  // issuer
  if (!p.iss) f.push({ severity: "critical", title: "No iss claim" });
  else {
    if (exp.issuer && exp.issuer.replace(/\/$/, "") !== String(p.iss).replace(/\/$/, ""))
      f.push({ severity: "critical", title: "Issuer doesn't match what the app expects", detail: `Token iss "${p.iss}", expected "${exp.issuer}". In Entra, v1.0 tokens use https://sts.windows.net/{tenant}/ and v2.0 use https://login.microsoftonline.com/{tenant}/v2.0.`, playbook: "jwt-issuer" });
    else f.push({ severity: exp.issuer ? "ok" : "info", title: "Issuer", detail: String(p.iss) });
    if (/sts\.windows\.net/.test(p.iss) && p.ver === "2.0") f.push({ severity: "warn", title: "Issuer/version mismatch", detail: "v2.0 token with a v1 issuer is unusual." });
    if (/sts\.windows\.net/.test(p.iss) && !p.ver?.startsWith?.("2"))
      f.push({ severity: "info", title: "Entra v1.0 token", detail: "The API's accessTokenAcceptedVersion (app manifest: requestedAccessTokenVersion) controls this. Set it to 2 for v2 tokens." });
  }

  // audience
  const auds: string[] = Array.isArray(p.aud) ? p.aud : p.aud ? [p.aud] : [];
  const want = exp.audience || (kind === "id_token" ? exp.clientId : "");
  if (!auds.length) f.push({ severity: "critical", title: "No aud claim" });
  else if (want && !auds.includes(want))
    f.push({ severity: "critical", title: "Audience doesn't match", detail: `Token is for "${auds.join(", ")}", expected "${want}". For an API, the client must request a scope of this API (e.g. api://<app-id>/.default), not Graph.`, playbook: "jwt-audience" });
  else f.push({ severity: want ? "ok" : "info", title: "Audience", detail: auds.join(", ") + (want ? "" : " — pick an app above to compare.") });

  // kind-specific
  if (kind === "id_token" && !p.nonce) f.push({ severity: "info", title: "No nonce", detail: "Expected when the app sent a nonce in the sign-in request (required for implicit/hybrid flows)." });
  if (p.scp) f.push({ severity: "info", title: "Delegated token (user present)", detail: `Scopes: ${p.scp}` });
  if (p.roles) f.push({ severity: "info", title: p.idtyp === "app" || (!p.scp && p.oid === p.sub) ? "App-only token (client credentials)" : "Roles present", detail: `Roles: ${[].concat(p.roles).join(", ")}` });
  if (p.groups && Array.isArray(p.groups) && p.groups.length >= 150)
    f.push({ severity: "warn", title: "Large groups claim", detail: "Near the group overage limit. Consider app roles or 'groups assigned to the application'." });
  if (p._claim_names?.groups || p.hasgroups)
    f.push({ severity: "warn", title: "Groups overage", detail: "The user is in too many groups to fit in the token. The app must call Microsoft Graph to read them, or use app roles instead.", playbook: "groups-overage" });
  return f;
}

const ALG: Record<string, { import: any; verify: any }> = {
  RS256: { import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verify: { name: "RSASSA-PKCS1-v1_5" } },
  RS384: { import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, verify: { name: "RSASSA-PKCS1-v1_5" } },
  RS512: { import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, verify: { name: "RSASSA-PKCS1-v1_5" } },
  PS256: { import: { name: "RSA-PSS", hash: "SHA-256" }, verify: { name: "RSA-PSS", saltLength: 32 } },
  ES256: { import: { name: "ECDSA", namedCurve: "P-256" }, verify: { name: "ECDSA", hash: "SHA-256" } },
  ES384: { import: { name: "ECDSA", namedCurve: "P-384" }, verify: { name: "ECDSA", hash: "SHA-384" } },
};

export interface VerifyResult {
  ok: boolean;
  message: string;
}

/** Verifies the signature against a pasted JWKS (or single JWK), or an HMAC secret for HS*. */
export async function verifyJwt(t: DecodedJwt, keyMaterial: string): Promise<VerifyResult> {
  const alg = t.header.alg as string;
  const data = toUtf8(t.signingInput);
  if (/^HS(256|384|512)$/.test(alg)) {
    const key = await crypto.subtle.importKey("raw", toUtf8(keyMaterial), { name: "HMAC", hash: "SHA-" + alg.slice(2) }, false, ["verify"]);
    const ok = await crypto.subtle.verify("HMAC", key, t.signature, data);
    return { ok, message: ok ? "Signature is valid for this secret." : "Signature does NOT match this secret." };
  }
  const spec = ALG[alg];
  if (!spec) return { ok: false, message: `Algorithm ${alg} isn't supported by this checker.` };
  let parsed: any;
  try {
    parsed = JSON.parse(keyMaterial);
  } catch {
    return { ok: false, message: "Paste the JWKS as JSON (the document at the jwks_uri)." };
  }
  const keys: any[] = parsed.keys ?? [parsed];
  const kid = t.header.kid;
  const key = kid ? keys.find((k) => k.kid === kid) : keys[0];
  if (!key)
    return {
      ok: false,
      message: `No key with kid "${kid}" in this JWKS. Either it's the wrong tenant/issuer's JWKS, the key rolled (refresh your cached keys), or the app uses its own signing key (custom signing key / claims mapping, add appid to the jwks_uri).`,
    };
  try {
    const { kid: _k, use: _u, x5c: _x, x5t: _t, issuer: _i, alg: _a, key_ops: _o, ...jwk } = key;
    const ck = await crypto.subtle.importKey("jwk", { ...jwk, ext: true }, spec.import, false, ["verify"]);
    const ok = await crypto.subtle.verify(spec.verify, ck, t.signature, data);
    return { ok, message: ok ? `Signature is valid (key ${kid ?? "#1"}).` : `Signature does NOT verify with key ${kid ?? "#1"}. The token was altered or signed by a different key.` };
  } catch (e: any) {
    return { ok: false, message: "Couldn't use that key: " + (e?.message ?? String(e)) };
  }
}

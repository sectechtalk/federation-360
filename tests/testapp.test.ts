// @vitest-environment node
// Lab test app: SAML request building, the SAML round trip, captures, and how its API judges access tokens.
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
// @ts-ignore: plain JavaScript module run by Node in the lab
import { buildAuthnRequest, createTestApp, metadataCerts, validateAccessToken } from "../lab/testapp/server.mjs";

const TENANT = "11111111-2222-4333-8444-555555555555";
const API = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const b64url = (b: Buffer | string) => Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...(publicKey.export({ format: "jwk" }) as any), kid: "k1", use: "sig" };
const jwks = { keys: [jwk] };

function token(payload: Record<string, unknown>, header: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  const p = { iss: `https://login.microsoftonline.com/${TENANT}/v2.0`, aud: API, tid: TENANT, iat: now, nbf: now, exp: now + 3600, ...payload };
  const input = `${b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "k1", ...header }))}.${b64url(JSON.stringify(p))}`;
  return `${input}.${b64url(nodeSign("RSA-SHA256", Buffer.from(input), privateKey))}`;
}
const check = (t: string) => validateAccessToken(t, { tenantId: TENANT, audience: API, scope: "Jobs.Read", role: "Jobs.Read.All", getJwks: async () => jwks });
const failed = (r: { checks: { name: string; ok: boolean }[] }) => r.checks.filter((c) => !c.ok).map((c) => c.name);

describe("test app API token checks", () => {
  it("accepts a delegated token with Jobs.Read and an app-only token with Jobs.Read.All", async () => {
    expect(await check(token({ scp: "Jobs.Read" }))).toMatchObject({ accepted: true });
    expect(await check(token({ roles: ["Jobs.Read.All"], aud: `api://${API}`, iss: `https://sts.windows.net/${TENANT}/` }))).toMatchObject({ accepted: true });
  });

  it("names every reason a token is rejected", async () => {
    expect(failed(await check(token({ scp: "Jobs.Read", aud: "https://graph.microsoft.com" })))).toEqual(["Audience"]);
    expect(failed(await check(token({ scp: "User.Read" })))).toEqual(["Permission"]);
    expect(failed(await check(token({ scp: "Jobs.Read", exp: Math.floor(Date.now() / 1000) - 3600 })))).toEqual(["Lifetime"]);
    expect(failed(await check(token({ scp: "Jobs.Read", tid: "x", iss: "https://login.microsoftonline.com/x/v2.0" })))).toEqual(["Issuer", "Tenant"]);
    expect(failed(await check(token({ scp: "Jobs.Read" }, { nonce: "graph" })))).toEqual(["Signature"]);
    const t = token({ scp: "Jobs.Read" });
    const tampered = t.split(".").map((p, i) => (i === 1 ? b64url(JSON.stringify({ ...JSON.parse(Buffer.from(p, "base64url").toString()), scp: "Jobs.Read Admin" })) : p)).join(".");
    expect(failed(await check(tampered))).toEqual(["Signature"]);
    expect(failed(await check("not-a-token"))).toEqual(["Token format"]);
  });
});

describe("SAML request", () => {
  const base = { tenantId: TENANT, entityId: `api://${TENANT}/f360-testapp-saml`, acsUrl: "http://localhost:5174/saml/acs" };
  const xml = (v: string) => inflateRawSync(Buffer.from(v, "base64")).toString("utf8");

  it("is a Redirect-binding AuthnRequest with the app's Issuer and reply URL", () => {
    const r = buildAuthnRequest(base);
    expect(r.destination).toBe(`https://login.microsoftonline.com/${TENANT}/saml2`);
    expect(xml(r.value)).toContain(`<saml:Issuer>${base.entityId}</saml:Issuer>`);
    expect(xml(r.value)).toContain(`AssertionConsumerServiceURL="${base.acsUrl}"`);
    expect(xml(r.value)).toContain(`ID="${r.id}"`);
  });

  it("can be broken on purpose", () => {
    expect(xml(buildAuthnRequest({ ...base, fault: "issuer" }).value)).toContain(`${base.entityId}-wrong</saml:Issuer>`);
    expect(xml(buildAuthnRequest({ ...base, fault: "acs" }).value)).toContain('AssertionConsumerServiceURL="http://localhost:5174/saml/acs-wrong"');
  });

  it("reads the signing certificates from Entra metadata", () => {
    const md = `<EntityDescriptor><RoleDescriptor><KeyDescriptor><X509Certificate>NOTME</X509Certificate></KeyDescriptor></RoleDescriptor><IDPSSODescriptor><KeyDescriptor use="signing"><KeyInfo><X509Data><X509Certificate>MIIC
AAA=</X509Certificate></X509Data></KeyInfo></KeyDescriptor></IDPSSODescriptor></EntityDescriptor>`;
    expect(metadataCerts(md)).toEqual(["MIICAAA="]);
  });
});

describe("test app server", () => {
  let dir: string;
  let server: any;
  let url: string;
  const config = {
    tenantId: TENANT,
    f360Url: "http://localhost:5173",
    publicUrl: "http://localhost:5174",
    saml: { entityId: `api://${TENANT}/f360-testapp-saml`, appId: "saml-app-id" },
    liveTest: { clientId: "live-test-id" },
    api: { clientId: API, scope: "Jobs.Read", role: "Jobs.Read.All" },
    labUsers: ["lab.user1@contoso.onmicrosoft.com", "lab.user2@contoso.onmicrosoft.com"],
  };
  const fakeFetch = async (u: string) => {
    if (u.includes("federationmetadata")) return new Response("<IDPSSODescriptor><X509Certificate>CERTDATA</X509Certificate></IDPSSODescriptor>");
    if (u.includes("/discovery/v2.0/keys")) return Response.json(jwks);
    return new Response("not found", { status: 404 });
  };

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "f360-testapp-"));
    server = createTestApp({ config, captureDir: dir, fetch: fakeFetch, quiet: true });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("publishes its settings, without secrets, to Federation 360 only", async () => {
    const r = await fetch(`${url}/api/config`, { headers: { Origin: "http://localhost:5173" } });
    expect(r.headers.get("access-control-allow-origin")).toBe("http://localhost:5173");
    const c = await r.json();
    expect(c.oidc).toEqual({ clientId: "live-test-id", scope: `openid profile email api://${API}/Jobs.Read`, apiAudience: API });
    expect(c.clientCredentials).toBeNull();
    expect(c.labUsers).toEqual(["lab.user1@contoso.onmicrosoft.com", "lab.user2@contoso.onmicrosoft.com"]);
    const other = await fetch(`${url}/api/config`, { headers: { Origin: "https://evil.example" } });
    expect(other.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("SAML round trip: request to Entra, response back, capture handed to Federation 360", async () => {
    const login = await fetch(`${url}/saml/login`, { redirect: "manual" });
    expect(login.status).toBe(302);
    const to = new URL(login.headers.get("location")!);
    expect(to.origin + to.pathname).toBe(`https://login.microsoftonline.com/${TENANT}/saml2`);
    const relay = to.searchParams.get("RelayState")!;

    const acs = await fetch(`${url}/saml/acs`, {
      method: "POST",
      redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ SAMLResponse: Buffer.from("<samlp:Response/>").toString("base64"), RelayState: relay }),
    });
    expect(acs.status).toBe(303);
    expect(acs.headers.get("location")).toBe(`http://localhost:5173/?capture=${relay}#livetest`);

    const c = await (await fetch(`${url}/api/captures/${relay}`)).json();
    expect(c.format).toBe("f360.capture");
    expect(c.steps.map((s: any) => s.saml.param)).toEqual(["SAMLRequest", "SAMLResponse"]);
    expect(c.expect).toMatchObject({ spEntityId: config.saml.entityId, acsUrl: "http://localhost:5174/saml/acs", idpCerts: ["CERTDATA"] });
    expect((await (await fetch(`${url}/api/captures`)).json())[0].id).toBe(relay);
  });

  it("whoami checks a bearer token and records it on a capture", async () => {
    const saved = await fetch(`${url}/api/captures`, { method: "POST", body: JSON.stringify({ format: "f360.capture", version: 1, id: "oidc-run-1", kind: "oidc", source: "f360", title: "t", startedAt: new Date().toISOString(), steps: [] }) });
    expect(saved.status).toBe(201);
    const ok = await fetch(`${url}/api/whoami?capture=oidc-run-1`, { headers: { Authorization: `Bearer ${token({ scp: "Jobs.Read" })}` } });
    expect(ok.status).toBe(200);
    expect((await ok.json()).accepted).toBe(true);
    const c = await (await fetch(`${url}/api/captures/oidc-run-1`)).json();
    expect(c.steps[0].apiCheck.accepted).toBe(true);

    expect((await fetch(`${url}/api/whoami`)).status).toBe(401);
    const bad = await fetch(`${url}/api/whoami`, { headers: { Authorization: `Bearer ${token({ scp: "Jobs.Read", aud: "other" })}` } });
    expect(bad.status).toBe(401);
    expect((await bad.json()).checks.find((x: any) => x.name === "Audience").ok).toBe(false);
  });

  it("refuses client credentials until the certificate exists, and rejects bad capture ids", async () => {
    expect((await fetch(`${url}/api/run/client-credentials`, { method: "POST" })).status).toBe(409);
    expect((await fetch(`${url}/api/captures/..%2F..%2Fetc`)).status).toBe(404);
    expect((await fetch(`${url}/api/captures`, { method: "POST", body: JSON.stringify({ format: "f360.capture", id: "../x", steps: [] }) })).status).toBe(400);
  });
});

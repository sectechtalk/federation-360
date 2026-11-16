// @vitest-environment node
// Lab test app on Azure Static Web Apps: the managed function keeps nothing and hands every capture back.
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
// @ts-ignore: plain JavaScript module run by Node
import { stage } from "../lab/testapp/azure/stage.mjs";
// @ts-ignore: plain JavaScript module run by Node
import { unpack, CAPTURE_FRAGMENT } from "../lab/testapp/core.mjs";

const TENANT = "11111111-2222-4333-8444-555555555555";
const API = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const SITE = "https://nice-sand-0abc123.azurestaticapps.net";
const b64url = (b: Buffer | string) => Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwks = { keys: [{ ...(publicKey.export({ format: "jwk" }) as any), kid: "k1", use: "sig" }] };
function token(payload: Record<string, unknown>) {
  const now = Math.floor(Date.now() / 1000);
  const p = { iss: `https://login.microsoftonline.com/${TENANT}/v2.0`, aud: API, tid: TENANT, iat: now, nbf: now, exp: now + 3600, ...payload };
  const input = `${b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "k1" }))}.${b64url(JSON.stringify(p))}`;
  return `${input}.${b64url(nodeSign("RSA-SHA256", Buffer.from(input), privateKey))}`;
}

const config = {
  tenantId: TENANT,
  f360Url: "http://localhost:5173",
  publicUrl: SITE,
  saml: { entityId: `api://${TENANT}/f360-testapp-saml`, appId: "saml-app-id" },
  liveTest: { clientId: "live-test-id" },
  api: { clientId: API, scope: "Jobs.Read", role: "Jobs.Read.All" },
  daemon: { clientId: "daemon-id" },
  labUsers: ["lab.user1@contoso.onmicrosoft.com"],
};

let dir: string;
let fn: (context: any, req: any) => Promise<void>;
const realFetch = globalThis.fetch;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "f360-swa-"));
  stage(dir);
  process.env.F360_TESTAPP_CONFIG = Buffer.from(JSON.stringify(config)).toString("base64");
  delete process.env.F360_DAEMON_KEY;
  delete process.env.F360_DAEMON_CERT;
  globalThis.fetch = (async (u: string) => {
    if (String(u).includes("federationmetadata")) return new Response("<IDPSSODescriptor><X509Certificate>CERTDATA</X509Certificate></IDPSSODescriptor>");
    if (String(u).includes("/discovery/v2.0/keys")) return Response.json(jwks);
    return new Response("not found", { status: 404 });
  }) as any;
  fn = createRequire(import.meta.url)(join(dir, "api", "testapp", "index.js"));
});
afterAll(() => {
  globalThis.fetch = realFetch;
  delete process.env.F360_TESTAPP_CONFIG;
  rmSync(dir, { recursive: true, force: true });
});

async function call(method: string, path: string, { headers = {}, body = "", query = {} }: { headers?: Record<string, string>; body?: string; query?: Record<string, string> } = {}) {
  const context: any = {};
  const qs = new URLSearchParams(query).toString();
  await fn(context, { method, url: `${SITE}${path}${qs ? "?" + qs : ""}`, headers, query, params: { path: path.replace(/^\/api\//, "") }, rawBody: body });
  return context.res as { status: number; headers: Record<string, string>; body: string };
}

describe("Azure Static Web Apps site", () => {
  it("stages a self-contained site: page, config, function and the shared core", () => {
    for (const f of ["app/index.html", "app/staticwebapp.config.json", "api/host.json", "api/testapp/function.json", "api/testapp/index.js", "api/testapp/core.mjs"]) expect(existsSync(join(dir, f))).toBe(true);
    const swa = JSON.parse(readFileSync(join(dir, "app/staticwebapp.config.json"), "utf8"));
    expect(swa.platform.apiRuntime).toBe("node:22");
    const pkg = JSON.parse(readFileSync(join(dir, "api/package.json"), "utf8"));
    expect(pkg.dependencies).toBeUndefined();
  });

  it("says it keeps no captures, and puts SAML under /api", async () => {
    const r = await call("GET", "/api/config", { headers: { origin: "http://localhost:5173" } });
    expect(r.headers["Access-Control-Allow-Origin"]).toBe("http://localhost:5173");
    const c = JSON.parse(r.body);
    expect(c).toMatchObject({ stateless: true, host: "azure", configured: true });
    expect(c.saml).toEqual({ entityId: config.saml.entityId, acsUrl: `${SITE}/api/saml/acs`, loginUrl: `${SITE}/api/saml/login` });
    expect(c.clientCredentials).toBeNull();
    expect((await call("GET", "/api/captures")).status).toBe(404);
  });

  it("SAML round trip with nothing stored: request in a cookie, capture back in the URL fragment", async () => {
    const login = await call("GET", "/api/saml/login");
    expect(login.status).toBe(302);
    const to = new URL(login.headers.Location);
    expect(to.origin + to.pathname).toBe(`https://login.microsoftonline.com/${TENANT}/saml2`);
    const relay = to.searchParams.get("RelayState")!;
    const setCookie = login.headers["Set-Cookie"];
    expect(setCookie).toMatch(/^f360_saml=[\w-]+; Path=\/api\/saml; Max-Age=900; HttpOnly; Secure; SameSite=None$/);

    const acs = await call("POST", "/api/saml/acs", {
      headers: { "content-type": "application/x-www-form-urlencoded", cookie: setCookie.split(";")[0] },
      body: new URLSearchParams({ SAMLResponse: Buffer.from("<samlp:Response/>").toString("base64"), RelayState: relay }).toString(),
    });
    expect(acs.status).toBe(303);
    expect(acs.headers["Set-Cookie"]).toContain("Max-Age=0");
    const loc = acs.headers.Location;
    expect(loc.startsWith(`http://localhost:5173/#livetest&${CAPTURE_FRAGMENT}=`)).toBe(true);
    const c = unpack(loc.split(`${CAPTURE_FRAGMENT}=`)[1]);
    expect(c.id).toBe(relay);
    expect(c.steps.map((s: any) => s.saml.param)).toEqual(["SAMLRequest", "SAMLResponse"]);
    expect(c.expect).toMatchObject({ acsUrl: `${SITE}/api/saml/acs`, idpCerts: ["CERTDATA"] });
  });

  it("a SAML response with no matching cookie still comes back, as a sign-in started from My Apps", async () => {
    const acs = await call("POST", "/api/saml/acs", { body: new URLSearchParams({ SAMLResponse: "PHgvPg==" }).toString() });
    const c = unpack(acs.headers.Location.split(`${CAPTURE_FRAGMENT}=`)[1]);
    expect(c.title).toContain("My Apps");
    expect(c.steps).toHaveLength(1);
  });

  it("the broken reply URL test points at /api/saml/acs-wrong", async () => {
    const login = await call("GET", "/api/saml/login", { query: { fault: "acs" } });
    const req = new URL(login.headers.Location).searchParams.get("SAMLRequest")!;
    const { inflateRawSync } = await import("node:zlib");
    expect(inflateRawSync(Buffer.from(req, "base64")).toString()).toContain(`AssertionConsumerServiceURL="${SITE}/api/saml/acs-wrong"`);
    expect((await call("GET", "/api/saml/acs-wrong")).status).toBe(400);
  });

  it("whoami accepts the token as a form field, so the browser needs no CORS preflight", async () => {
    const ok = await call("POST", "/api/whoami", { headers: { "content-type": "application/x-www-form-urlencoded" }, body: `access_token=${token({ scp: "Jobs.Read" })}` });
    expect(ok.status).toBe(200);
    expect(JSON.parse(ok.body).accepted).toBe(true);
    expect((await call("POST", "/api/whoami")).status).toBe(401);
  });

  it("uses the form field even though Static Web Apps replaces the Authorization header with its own token", async () => {
    // What a real Azure run sees: the platform's HS256 token from <site>.scm.azurewebsites.net in the header.
    const swaToken = `${b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${b64url(JSON.stringify({ iss: "https://0abc1234.scm.azurewebsites.net", aud: "https://0abc1234.azurewebsites.net/azurefunctions" }))}.sig`;
    const ok = await call("POST", "/api/whoami", { headers: { authorization: `Bearer ${swaToken}`, "content-type": "application/x-www-form-urlencoded" }, body: `access_token=${token({ scp: "Jobs.Read" })}` });
    expect(ok.status).toBe(200);
    const j = JSON.parse(ok.body);
    expect(j.accepted).toBe(true);
    expect(j.step.method).toBe("POST");
    const headerOnly = await call("GET", "/api/whoami", { headers: { authorization: `Bearer ${token({ scp: "Jobs.Read" })}` } });
    expect(headerOnly.status).toBe(401);
    expect(JSON.parse(headerOnly.body).checks[0].detail).toMatch(/replaces it with its own internal token/);
  });

  it("client credentials stays off until the certificate is in the settings", async () => {
    expect((await call("POST", "/api/run/client-credentials")).status).toBe(409);
  });
});

describe("Live test page and the Azure test app", async () => {
  const { isAllowedTestAppUrl, unpackCapture, CAPTURE_FRAGMENT: PAGE_FRAGMENT } = await import("../src/lib/livetest");
  // @ts-ignore: plain JavaScript module run by Node
  const { pack } = await import("../lab/testapp/core.mjs");

  it("uses the same fragment name as the test app", () => {
    expect(PAGE_FRAGMENT).toBe(CAPTURE_FRAGMENT);
  });

  it("unpacks a capture packed by the test app", async () => {
    const c = { format: "f360.capture", version: 1, id: "x-123456", kind: "saml", source: "testapp", title: "t", startedAt: "2026-11-15T00:00:00Z", steps: [{ label: "é ✓", saml: { value: "A".repeat(9000) } }] };
    expect(await unpackCapture(pack(c))).toEqual(c);
    await expect(unpackCapture(pack({ hello: 1 }))).rejects.toThrow(/isn't a capture/);
  });

  it("only accepts a test app on this PC or on azurestaticapps.net from a link", () => {
    expect(isAllowedTestAppUrl("http://localhost:5174/")).toBe(true);
    expect(isAllowedTestAppUrl(`${SITE}/`)).toBe(true);
    expect(isAllowedTestAppUrl("https://gentle-river-0a1b2c3d4.5.azurestaticapps.net")).toBe(true);
    expect(isAllowedTestAppUrl("http://nice-sand.azurestaticapps.net/")).toBe(false);
    expect(isAllowedTestAppUrl("https://azurestaticapps.net.evil.example/")).toBe(false);
    expect(isAllowedTestAppUrl("https://evil.example/")).toBe(false);
    expect(isAllowedTestAppUrl(`${SITE}/api/config`)).toBe(false);
  });
});

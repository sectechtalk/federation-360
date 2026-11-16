// Flow Tracer: HAR parsing, flow checks and redaction.
import { parseHar } from "../src/lib/har";
import { analyzeCapture, redactCapture, type FlowCapture } from "../src/lib/flow";
import { HAR_SAMPLES } from "../src/data/harSamples";
import { makeJwtSample, SAML_SAMPLES } from "../src/data/samples";
import { SAMPLE_CERT_CURRENT } from "../src/data/sampleCerts";

const build = async (id: string) => JSON.stringify(await HAR_SAMPLES.find((s) => s.id === id)!.build());
const crit = (fs: { severity: string; title: string }[]) => fs.filter((f) => f.severity === "critical").map((f) => f.title);
const allFindings = (a: Awaited<ReturnType<typeof analyzeCapture>>) => [...a.overall, ...a.steps.flatMap((s) => s.findings)];

test("healthy SAML HAR: keeps only the two SAML hops and drops cookies", async () => {
  const c = parseHar(await build("saml-ok"), "ok.har");
  expect(c.kind).toBe("saml");
  expect(c.steps.map((s) => s.saml?.param)).toEqual(["SAMLRequest", "SAMLResponse"]);
  expect(c.steps[0].saml?.binding).toBe("redirect");
  expect(c.steps[1].saml?.binding).toBe("post");
  expect(c.steps[1].from).toBe("idp");
  expect(JSON.stringify(c)).not.toContain("ESTSAUTH");
});

test("healthy SAML HAR: the response is checked against the request and passes", async () => {
  const a = await analyzeCapture(parseHar(await build("saml-ok")));
  expect(crit(allFindings(a))).toEqual([]);
  expect(a.overall[0]).toMatchObject({ severity: "ok", title: "The flow completed" });
  const titles = a.steps[1].findings.map((f) => f.title);
  expect(titles).toContain("The response answers the request in this flow");
  expect(titles).toContain("Destination and Recipient match the ACS URL");
  expect(titles.some((t) => t.startsWith("Audience"))).toBe(true);
});

test("AADSTS50011 HAR: the error page becomes a hop that links to the playbook", async () => {
  const c = parseHar(await build("saml-50011"));
  expect(c.steps).toHaveLength(2);
  expect(c.steps[1].error?.code).toBe("AADSTS50011");
  const a = await analyzeCapture(c);
  const f = a.steps[1].findings.find((x) => x.playbook === "AADSTS50011");
  expect(f?.severity).toBe("critical");
  expect(a.overall[0].severity).toBe("critical");
});

test("a SAML response for a different request is flagged, and the signing cert is compared with metadata", async () => {
  const response = await SAML_SAMPLES.find((s) => s.id === "healthy")!.build();
  const request = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_other" Version="2.0" IssueInstant="${new Date().toISOString()}" AssertionConsumerServiceURL="https://expenses.contoso.example/saml/acs"><saml:Issuer>https://expenses.contoso.example/saml/metadata</saml:Issuer></samlp:AuthnRequest>`;
  const c: FlowCapture = {
    format: "f360.capture", version: 1, id: "t1", kind: "saml", source: "testapp", title: "t", startedAt: new Date().toISOString(),
    expect: { idpCerts: [SAMPLE_CERT_CURRENT] },
    steps: [
      { from: "app", to: "idp", label: "req", saml: { param: "SAMLRequest", value: request, binding: "redirect" } },
      { from: "idp", to: "app", label: "resp", saml: { param: "SAMLResponse", value: response, binding: "post" } },
    ],
  };
  const a = await analyzeCapture(c);
  expect(crit(a.steps[1].findings)).toContain("InResponseTo doesn't match the request in this flow");
  expect(a.steps[1].findings.map((f) => f.title)).toContain("Signing certificate matches the thumbprint on file");
});

function oidcHar(idToken: string, nonce: string) {
  const t = (s: number) => new Date(Date.now() + s * 1000).toISOString();
  const tenant = "11111111-2222-4333-8444-555555555555";
  const authorize = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize?client_id=5d1e2f3a-4b5c-4d6e-8f70-819203a4b5c6&response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=openid%20profile&state=st1&nonce=${nonce}&code_challenge=abc&code_challenge_method=S256`;
  return JSON.stringify({
    log: {
      entries: [
        { startedDateTime: t(-10), request: { method: "GET", url: authorize }, response: { status: 200 } },
        { startedDateTime: t(-5), request: { method: "POST", url: `https://login.microsoftonline.com/${tenant}/login` }, response: { status: 302, redirectURL: "https://app.example/cb?code=0.AAA-code&state=st1" } },
        {
          startedDateTime: t(-4),
          request: { method: "POST", url: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`, headers: [{ name: "Origin", value: "https://app.example" }], postData: { mimeType: "application/x-www-form-urlencoded", text: "grant_type=authorization_code&client_id=5d1e2f3a-4b5c-4d6e-8f70-819203a4b5c6&code=0.AAA-code&code_verifier=secretverifier" } },
          response: { status: 200, content: { mimeType: "application/json", text: JSON.stringify({ id_token: idToken, refresh_token: "rt-secret", token_type: "Bearer" }) } },
        },
      ],
    },
  });
}

test("OIDC HAR: authorize, code and token hops; secrets are never kept; nonce is checked", async () => {
  const { token } = await makeJwtSample("id"); // nonce n-0S6_WzA2Mj, aud 5d1e2f3a-...
  const c = parseHar(oidcHar(token, "n-0S6_WzA2Mj"));
  expect(c.kind).toBe("oidc");
  expect(c.steps.map((s) => s.label)).toEqual([
    expect.stringContaining("authorize request"),
    expect.stringContaining("with a code"),
    "The code is exchanged for tokens",
  ]);
  const json = JSON.stringify(c);
  expect(json).not.toContain("secretverifier");
  expect(json).not.toContain("rt-secret");
  expect(c.steps[2].params?.code_verifier).toBe("(present)");
  const a = await analyzeCapture(c);
  expect(crit(allFindings(a))).toEqual([]);
  expect(a.steps[0].findings.map((f) => f.title)).toContain("PKCE in use (S256)");
  expect(a.steps[2].findings.map((f) => f.title)).toContain("id_token: nonce matches the sign-in request");

  const bad = await analyzeCapture(parseHar(oidcHar(token, "a-different-nonce")));
  expect(crit(allFindings(bad))).toContain("id_token: nonce doesn't match the sign-in request");
});

test("redaction removes codes, token signatures and SAML signature values but keeps them decodable", async () => {
  const { token } = await makeJwtSample("id");
  const c = parseHar(oidcHar(token, "n-0S6_WzA2Mj"));
  const r = await redactCapture(c);
  const json = JSON.stringify(r);
  expect(json).not.toContain("0.AAA-code");
  expect(json).not.toContain(token.split(".")[2]);
  expect(r.steps[2].tokens?.[0].value.endsWith(".REDACTED")).toBe(true);
  expect(crit(allFindings(await analyzeCapture(r)))).toEqual([]);

  const saml = await redactCapture(parseHar(await build("saml-ok")));
  expect(saml.steps[1].saml?.value).toContain("<SignatureValue>REDACTED</SignatureValue>");
  expect((await analyzeCapture(saml)).steps[1].saml?.parsed.kind).toBe("Response");
});

test("not a HAR file: a plain-language error", () => {
  expect(() => parseHar("hello")).toThrow(/Save all as HAR with content/);
  expect(() => parseHar("{}")).toThrow(/isn't a HAR file/);
});

test("an Entra authorization code (opaque, but it contains dots) is never decoded or warned about", async () => {
  const c: FlowCapture = {
    format: "f360.capture", version: 1, id: "oidc-code-1", kind: "oidc", source: "f360", title: "t", startedAt: new Date().toISOString(),
    steps: [{ at: new Date().toISOString(), from: "idp", to: "f360", method: "302", url: "http://localhost:5173/", label: "code back", tokens: [{ name: "code", value: "1.AXIAqZe2HMBYNkOq2ic6bZELdw.AgABBAIAAAApTwJmzXqdR4BN2miheQMYAgDs_wUA9P8.AQABAAEAAA" }, { name: "refresh_token", value: "1.AXIA.abc.def" }] }],
  };
  const a = await analyzeCapture(c);
  expect(a.steps[0].findings.filter((f) => /couldn't be decoded/.test(f.title))).toEqual([]);
  expect(a.steps[0].jwts).toEqual([]);
});

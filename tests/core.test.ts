import { decodeSamlInput, parseSaml, checkSaml } from "../src/lib/saml";
import { decodeJwt, checkJwt, verifyJwt } from "../src/lib/jwt";
import { parseCertificate } from "../src/lib/x509";
import { parseSamlMetadata, checkSamlMetadata, checkDiscovery } from "../src/lib/metadata";
import { appHealth } from "../src/lib/health";
import { SAML_SAMPLES, makeJwtSample, SAMPLE_IDP_METADATA, SAMPLE_DISCOVERY } from "../src/data/samples";
import { SAMPLE_CERT_CURRENT } from "../src/data/sampleCerts";
import { exampleData } from "../src/data/seed";

const expenses = exampleData().apps.find((a) => a.id === "ex-expenses")!;
const exp = { spEntityId: expenses.saml.entityId, acsUrl: expenses.saml.acsUrl, idpEntityId: expenses.saml.idpEntityId, certThumbprint: expenses.saml.certThumbprint };
const opts = () => ({ at: new Date(), skewSeconds: 300 });
const crit = (f: { severity: string; title: string }[]) => f.filter((x) => x.severity === "critical").map((x) => x.title);

test("parses certificate validity and thumbprint", async () => {
  const c = await parseCertificate(SAMPLE_CERT_CURRENT);
  expect(c.subject).toContain("Example Entra SSO Certificate");
  expect(c.sha1).toBe("749A276BF39BC76DFAA117BB9F8605D526A5B63F");
  expect(c.daysLeft).toBeGreaterThan(1000);
});

test("healthy SAML sample has no problems", async () => {
  const s = SAML_SAMPLES.find((x) => x.id === "healthy")!;
  const p = await parseSaml((await decodeSamlInput(await s.build())).xml);
  expect(p.kind).toBe("Response");
  expect(crit(checkSaml(p, exp, opts()))).toEqual([]);
});

test("mismatch sample flags audience, destination and recipient", async () => {
  const s = SAML_SAMPLES.find((x) => x.id === "audience")!;
  const p = await parseSaml((await decodeSamlInput(await s.build())).xml);
  const c = crit(checkSaml(p, exp, opts())).join("|");
  expect(c).toMatch(/Audience/);
  expect(c).toMatch(/Destination/);
  expect(c).toMatch(/Recipient/);
});

test("rolled sample flags cert mismatch and NotBefore", async () => {
  const s = SAML_SAMPLES.find((x) => x.id === "rolled")!;
  const p = await parseSaml((await decodeSamlInput(await s.build())).xml);
  const f = checkSaml(p, exp, opts());
  expect(crit(f).join("|")).toMatch(/NOT the one on file/);
  expect(crit(f).join("|")).toMatch(/isn't valid yet/);
  expect(f.some((x) => /SHA-1/.test(x.title))).toBe(true);
});

test("redirect-binding AuthnRequest is inflated and checked", async () => {
  const s = SAML_SAMPLES.find((x) => x.id === "request")!;
  const r = await decodeSamlInput(await s.build());
  expect(r.steps.join(" ")).toMatch(/Inflated/);
  const p = await parseSaml(r.xml);
  expect(p.kind).toBe("AuthnRequest");
  const f = checkSaml(p, exp, opts());
  expect(f.some((x) => x.playbook === "AADSTS75011")).toBe(true);
  expect(crit(f)).toEqual([]);
});

test("JWT sample verifies and passes checks", async () => {
  const s = await makeJwtSample("id");
  const t = decodeJwt(s.token);
  expect((await verifyJwt(t, s.jwks)).ok).toBe(true);
  const f = checkJwt(t, { audience: "5d1e2f3a-4b5c-4d6e-8f70-819203a4b5c6" }, new Date(), 300);
  expect(crit(f)).toEqual([]);
  const [h, pl] = s.token.split(".");
  const other = await makeJwtSample("id");
  const tampered = decodeJwt(h + "." + pl + "." + other.token.split(".")[2]);
  expect((await verifyJwt(tampered, s.jwks)).ok).toBe(false);
});

test("expired access token flagged", async () => {
  const s = await makeJwtSample("access");
  const f = checkJwt(decodeJwt(s.token), { audience: "c3d4e5f6-0718-4293-a4b5-c6d7e8f90a1b" }, new Date(), 60);
  expect(crit(f).join("|")).toMatch(/expired/);
  expect(crit(f).join("|")).toMatch(/Audience/);
});

test("metadata and discovery checks", async () => {
  const m = await parseSamlMetadata(SAMPLE_IDP_METADATA);
  expect(m.entityId).toMatch(/sts\.windows\.net/);
  expect(m.certs.length).toBe(2);
  const f = checkSamlMetadata(m);
  expect(f.some((x) => x.severity === "warn" && /expires in/.test(x.title))).toBe(true);
  const d = checkDiscovery(JSON.parse(SAMPLE_DISCOVERY));
  expect(crit(d)).toEqual([]);
});

test("inventory health flags the broken examples", () => {
  const apps = exampleData().apps;
  const by = (id: string) => appHealth(apps.find((a) => a.id === id)!);
  expect(crit(by("ex-hr")).length).toBeGreaterThan(0);
  expect(crit(by("ex-partner")).join("|")).toMatch(/expired/);
  expect(crit(by("ex-expenses"))).toEqual([]);
});

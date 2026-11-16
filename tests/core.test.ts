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

// ---------------------------------------------------------------- SCIM
import { parseScim, checkScim, compareSignInId, parseScimPath, describeScim } from "../src/lib/scim";
import { SCIM_SAMPLES } from "../src/data/scimSamples";
import { nextExpiry } from "../src/lib/health";
import { PLAYBOOKS, playbookById } from "../src/data/playbooks";
import { WIZARDS } from "../src/data/wizards";

const scimSample = (id: string) => SCIM_SAMPLES.find((s) => s.id === id)!;
const titles = (f: { title: string }[]) => f.map((x) => x.title).join(" | ");

test("SCIM create request parses with its request line and passes", () => {
  const s = scimSample("create");
  const m = parseScim(s.text);
  expect(m.kind).toBe("user");
  expect(m.method).toBe("POST");
  expect(m.path).toBe("/scim/v2/Users");
  const f = checkScim(m, { signInId: s.signInId });
  expect(crit(f)).toEqual([]);
  expect(titles(f)).toContain("Sign-in identifier matches userName exactly");
  expect(describeScim(m)).toContain("Create a user account");
});

test("SCIM sign-in identifier mismatch is a problem, case-only difference a warning", () => {
  const s = scimSample("mismatch");
  const m = parseScim(s.text);
  expect(crit(checkScim(m, { signInId: s.signInId }))).toContain("Sign-in identifier doesn't match the provisioned account");
  const near = compareSignInId("Avery.Lee@contoso.example", m.body);
  expect(near[0].severity).toBe("warn");
  // Matching only on email is reported, not passed.
  const emailOnly = compareSignInId("avery.lee@contoso.example", { ...m.body, userName: "alee" });
  expect(emailOnly[0].severity).toBe("info");
  // A disabled account fails even when the name matches.
  expect(crit(compareSignInId("avery.lee@contoso.example", { ...m.body, active: false }))).toContain("The account exists but is disabled");
});

test("SCIM Entra default disable PATCH is flagged for text boolean and capitalised op", () => {
  const m = parseScim(scimSample("disable").text);
  expect(m.kind).toBe("patch");
  const t = titles(checkScim(m));
  expect(t).toContain('active is the text "False"');
  expect(t).toContain("disables the account");
  expect(t).toContain("Operation names are capitalised");
  expect(describeScim(m)).toContain("leaver");
  // The standard form raises neither format finding.
  const std = titles(checkScim(parseScim('{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}')));
  expect(std).not.toContain("is the text");
  expect(std).not.toContain("capitalised");
});

test("SCIM PATCH structural errors are problems", () => {
  const bad = parseScim('{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove"},{"op":"merge","path":"x","value":1},{"op":"add","path":"title"}]}');
  const c = crit(checkScim(bad));
  expect(c).toContain("Operation 1: remove needs a path");
  expect(c).toContain("Operation 2: op must be add, replace or remove");
  expect(c).toContain("Operation 3: add needs a value");
});

test("SCIM lookup, error and group samples are classified and explained", () => {
  const lookup = parseScim(scimSample("lookup").text);
  expect(lookup.kind).toBe("list");
  expect(lookup.filter).toBe('userName eq "jordan.kim@contoso.example"');
  expect(titles(checkScim(lookup))).toContain("No matching account in the app");

  const conflict = parseScim(scimSample("conflict").text);
  expect(conflict.kind).toBe("error");
  expect(conflict.status).toBe(409);
  const cf = checkScim(conflict);
  expect(cf[0].playbook).toBe("scim-409");
  expect(titles(cf)).toContain("scimType: uniqueness");

  expect(checkScim(parseScim(scimSample("unauthorized").text))[0].playbook).toBe("scim-401");
  expect(titles(checkScim(parseScim(scimSample("group").text)))).toContain("adds 2 group members");

  const dupes = parseScim('{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":2,"Resources":[{"id":"1"},{"id":"2"}]}');
  expect(crit(checkScim(dupes))).toContain("2 accounts match one identifier");
});

test("SCIM input errors are explained, and missing userName is a problem", () => {
  expect(() => parseScim("")).toThrow();
  expect(() => parseScim("hello")).toThrow(/doesn't look like SCIM/);
  expect(() => parseScim('{"schemas": [')).toThrow(/valid JSON/);
  expect(crit(checkScim(parseScim('{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"emails":[]}')))).toContain("userName is missing");
});

test("SCIM path parser handles filters, sub-attributes and extension URNs", () => {
  expect(parseScimPath('emails[type eq "work"].value')).toEqual({ attr: "emails", filter: { attr: "type", op: "eq", value: "work" }, sub: "value" });
  expect(parseScimPath("name.givenName")).toEqual({ attr: "name", sub: "givenName" });
  expect(parseScimPath('members[value eq "u-1"]')?.filter?.value).toBe("u-1");
  expect(parseScimPath("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber")?.attr).toContain("employeeNumber");
  expect(parseScimPath("emails[type eq")).toBeNull();
});

test("SCIM inventory health: token expiry and identifier source mismatch", () => {
  const aws = exampleData().apps.find((a) => a.id === "ex-awsidc")!;
  expect(appHealth(aws).some((f) => /SCIM token expires in \d+ days/.test(f.title))).toBe(true);
  const expired = { ...aws, scim: { ...aws.scim!, tokenExpires: "2020-01-01" } };
  expect(crit(appHealth(expired)).some((t) => t.startsWith("SCIM token expired"))).toBe(true);
  expect(nextExpiry(expired)).toEqual({ date: "2020-01-01", what: "SCIM token" });
  const mismatch = { ...aws, saml: { ...aws.saml, nameIdSource: "user.userprincipalname" }, scim: { ...aws.scim!, userNameSource: "mail" } };
  expect(appHealth(mismatch).some((f) => f.title === "Sign-in and provisioning use different source attributes")).toBe(true);
  // Entries saved before the SCIM module have no scim block and must not crash.
  const legacy = { ...aws, scim: undefined };
  expect(appHealth(legacy).some((f) => f.title === "SCIM token expiry not recorded")).toBe(true);
});

test("every playbook referenced by a SCIM finding exists, and the SCIM wizard saves SCIM settings", () => {
  const src = ["scim-identifier-mismatch", "scim-not-provisioned", "scim-leaver", "scim-401", "scim-404", "scim-409", "scim-400", "scim-quarantine", "scim-group-members"];
  for (const id of src) expect(playbookById(id), id).toBeTruthy();
  expect(new Set(PLAYBOOKS.map((p) => p.id)).size).toBe(PLAYBOOKS.length);
  const w = WIZARDS.find((x) => x.id === "entra-scim")!;
  const app = w.toApp({ appName: "Expense Portal", tenantUrl: "https://x.example/scim/v2", tokenExpires: "2027-01-01", userNameSource: "mail" });
  expect(app.provisioning).toBe("scim");
  expect(app.scim).toMatchObject({ endpoint: "https://x.example/scim/v2", tokenExpires: "2027-01-01", userNameSource: "mail", matchAttribute: "userName" });
  expect(w.outputs({ tenantUrl: "https://x.example/scim/v2" })[0].body).toContain("https://x.example/scim/v2?aadOptscim062020");
});

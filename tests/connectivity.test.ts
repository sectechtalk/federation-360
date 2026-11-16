// Agentless connectivity test: plan building, embedding the plan in the PowerShell script, and reading results back.
import script from "../connectivity/Test-F360Connectivity.ps1?raw";
import remediate from "../connectivity/Remediate-F360Connectivity.ps1?raw";
import { buildPlan, embedPlan, extractPlan, isTestableHost, parseResults, parseSummaryLine, r360Fields, splitJson, summarizeByTest, PLAN_SCHEMA } from "../src/lib/connectivity";
import { emptyOidc, emptySaml, type AppIntegration, type Tenant } from "../src/lib/types";

const TID = "8f2b6c1e-0d4a-4a7e-9a51-3c0d2e7b9f10";
const now = new Date("2026-11-15T12:00:00Z");
const tenant = (p: Partial<Tenant>): Tenant => ({ id: "t1", name: "Lab", platform: "entra", tenantRef: TID, domain: "contoso.onmicrosoft.com", environment: "test", notes: "", updatedAt: "", ...p });
const app = (p: Partial<AppIntegration>): AppIntegration => ({
  id: "a1", tenantId: "t1", name: "App", protocol: "saml", environment: "test", owner: "", status: "live", provisioning: "none",
  saml: emptySaml(), oidc: emptyOidc(), notes: "", updatedAt: "", ...p,
});

describe("plan building", () => {
  it("adds the Entra baseline, tenant discovery and metadata, and the app's own hosts, each once", () => {
    const apps = [
      app({ id: "a1", name: "Payroll", saml: { ...emptySaml(), acsUrl: "https://payroll.contoso.com/saml/acs", signOnUrl: "https://payroll.contoso.com/login" } }),
      app({ id: "a2", name: "Wiki", saml: { ...emptySaml(), acsUrl: "https://payroll.contoso.com/wiki/acs" } }),
    ];
    const plan = buildPlan([tenant({})], apps, { now });
    expect(plan.schema).toBe(PLAN_SCHEMA);
    const keys = plan.tests.map((t) => `${t.type}|${t.url ?? t.host}`);
    expect(new Set(keys).size).toBe(keys.length);
    const tls = plan.tests.find((t) => t.type === "tls" && t.host === "login.microsoftonline.com")!;
    expect(tls.expectIssuer).toBe("Microsoft|DigiCert");
    expect(tls.apps).toEqual(["Payroll", "Wiki"]);
    expect(plan.tests.some((t) => t.type === "clock")).toBe(true);
    const disc = plan.tests.find((t) => t.url?.endsWith("/v2.0/.well-known/openid-configuration"))!;
    expect(disc.expectIssuer).toBe(`https://login.microsoftonline.com/${TID}/v2.0`);
    expect(plan.tests.find((t) => t.url?.includes("federationmetadata"))?.expectContains).toBe("EntityDescriptor");
    const payrollTls = plan.tests.find((t) => t.type === "tls" && t.host === "payroll.contoso.com")!;
    expect(payrollTls.apps).toEqual(["Payroll", "Wiki"]);
    expect(plan.tests.map((t) => t.id)).toEqual(plan.tests.map((_, i) => `t${i + 1}`));
  });

  it("skips localhost, plain HTTP, custom schemes and reserved example names", () => {
    expect(isTestableHost("localhost")).toBe(false);
    expect(isTestableHost("expenses.contoso.example")).toBe(false);
    expect(isTestableHost("example.com")).toBe(false);
    expect(isTestableHost("login.microsoftonline.com")).toBe(true);
    const plan = buildPlan([tenant({ tenantRef: "" , domain: "" })], [
      app({ protocol: "oidc", oidc: { ...emptyOidc(), redirectUris: "http://localhost:3000/cb\nmsauth://x/y\nhttp://plain.contoso.com/cb\nhttps://app.contoso.example/cb" } }),
    ], { now });
    const hosts = new Set(plan.tests.map((t) => t.host ?? new URL(t.url!).hostname));
    expect([...hosts].sort()).toEqual(["aadcdn.msftauth.net", "login.microsoftonline.com"]);
  });

  it("checks a non-Entra issuer's discovery document, AWS access portals and SCIM endpoints", () => {
    const plan = buildPlan(
      [tenant({ id: "aws", name: "AWS", platform: "aws-idc", tenantRef: "arn:aws:sso:::instance/x", domain: "d-1234567890.awsapps.com" }), tenant({ id: "ok", name: "Okta", platform: "okta", tenantRef: "", domain: "acme.okta.com" })],
      [
        app({ id: "x", tenantId: "aws", name: "Console", provisioning: "scim", scim: { endpoint: "https://scim.us-east-1.amazonaws.com/abc/scim/v2", tokenExpires: "", matchAttribute: "", userNameSource: "" } }),
        app({ id: "y", tenantId: "ok", name: "Portal", protocol: "oidc", oidc: { ...emptyOidc(), issuer: "https://acme.okta.com/oauth2/default", redirectUris: "https://portal.acme.com/cb" } }),
      ],
      { now },
    );
    const urls = plan.tests.filter((t) => t.url).map((t) => t.url);
    expect(urls).toContain("https://d-1234567890.awsapps.com/start");
    expect(urls).toContain("https://scim.us-east-1.amazonaws.com/abc/scim/v2");
    expect(urls).toContain("https://acme.okta.com/oauth2/default/.well-known/openid-configuration");
    expect(plan.tests.find((t) => t.url === "https://acme.okta.com/oauth2/default/.well-known/openid-configuration")?.expectIssuer).toBe("https://acme.okta.com/oauth2/default");
    expect(plan.tests.some((t) => t.host === "login.microsoftonline.com")).toBe(false);
  });

  it("falls back to the Entra sign-in baseline when nothing chosen is device-testable, so there is always a plan", () => {
    for (const plan of [buildPlan([], [], { now }), buildPlan([tenant({ platform: "other", domain: "" })], [app({ saml: { ...emptySaml(), acsUrl: "http://localhost/acs" } })], { now })]) {
      expect(plan.fallback).toBe(true);
      expect(plan.name).toBe("Microsoft Entra sign-in baseline");
      expect(plan.tests.map((t) => t.type)).toEqual(["dns", "tcp", "tls", "clock", "dns", "tcp", "tls", "http"]);
      expect(plan.tests.find((t) => t.type === "tls")?.expectIssuer).toBe("Microsoft|DigiCert");
    }
    expect(buildPlan([tenant({})], [app({})], { now }).fallback).toBeUndefined();
  });

  it("gives the same id to the same tests regardless of the time", () => {
    const a = buildPlan([tenant({})], [app({})], { now });
    const b = buildPlan([tenant({})], [app({})], { now: new Date("2027-01-01") });
    expect(a.id).toBe(b.id);
    expect(buildPlan([tenant({})], [app({ name: "Other" })], { now }).id).not.toBe(a.id);
  });
});

describe("the PowerShell script", () => {
  it("is plain Windows PowerShell 5.1 and fits Remediation 360's rules", () => {
    expect(new TextEncoder().encode(script).length).toBeLessThan(150 * 1024);
    expect(script).not.toMatch(/SIG # Begin signature block/);
    // PowerShell 7-only syntax would break on Windows PowerShell 5.1.
    const code = script.replace(/<#[\s\S]*?#>/g, "").replace(/^\s*#.*$/gm, "");
    expect(code).not.toMatch(/\?\?|\?\.|::new\(|\s\?\s.*\s:\s|-Parallel|\bclean\s*\{/);
    expect(code).not.toMatch(/Invoke-WebRequest|Invoke-RestMethod|Start-Job|Register-ScheduledTask|New-Service|Install-Module/);
    expect(code).toMatch(/UseDefaultCredentials = \$false/);
    expect(remediate).toMatch(/exit 0/);
  });

  it("ships with a valid baseline plan and takes a new one between the markers", () => {
    const base = extractPlan(script)!;
    expect(base.id).toBe("baseline");
    expect(base.schema).toBe(PLAN_SCHEMA);
    expect(base.tests.length).toBeGreaterThan(3);
    const plan = buildPlan([tenant({})], [app({ name: "Payroll's app", saml: { ...emptySaml(), acsUrl: "https://payroll.contoso.com/acs" } })], { now });
    const out = embedPlan(script, plan);
    expect(extractPlan(out)).toEqual(plan);
    // Everything outside the plan block is untouched.
    const strip = (s: string) => s.replace(/# >>> F360 PLAN[\s\S]*# <<< F360 PLAN/, "");
    expect(strip(out)).toBe(strip(script));
    expect(embedPlan(out, plan)).toBe(out);
    expect(() => embedPlan("no markers", plan)).toThrow();
  });

  it("supports every test type the plan builder produces", () => {
    for (const t of ["dns", "tcp", "tls", "http", "clock"]) expect(script).toContain(`'${t}'`);
  });

  it("r360 form values fit the remediation schema limits", () => {
    const f = r360Fields(buildPlan([tenant({})], [app({})], { now }));
    expect(f.folder).toMatch(/^[A-Za-z0-9][A-Za-z0-9._-]*$/);
    expect(f.displayName.length).toBeGreaterThanOrEqual(3);
    expect(f.runRemediationScript).toBe(false);
    expect(f.schedule.time).toMatch(/^\d\d:\d\d:\d\d$/);
  });
});

const fileResult = (device: string, startedAt: string, statuses: string[]) => ({
  schema: "f360.connectivity.result/1",
  planId: "abc123",
  device,
  runAs: "NT AUTHORITY\\SYSTEM",
  startedAt,
  counts: {},
  // Windows PowerShell 5.1 writes a one-item array as a bare string.
  results: statuses.map((s, i) => ({ id: `t${i + 1}`, type: "tls", label: `Check ${i + 1}`, target: "login.microsoftonline.com:443", status: s, ms: 12, detail: "x", apps: "Payroll", data: { inspected: s === "warn" } })),
});

describe("reading results", () => {
  it("reads result files, keeps the newest per device, and normalises PowerShell's one-item arrays", () => {
    const { reports, errors } = parseResults([
      JSON.stringify(fileResult("PC1", "2026-11-14T09:00:00Z", ["fail"])),
      JSON.stringify(fileResult("PC1", "2026-11-15T09:00:00Z", ["pass", "warn"])) + "\n" + JSON.stringify(fileResult("PC2", "2026-11-15T09:00:00Z", ["fail", "pass"])),
    ]);
    expect(errors).toEqual([]);
    expect(reports.map((r) => r.device)).toEqual(["PC2", "PC1"]);
    expect(reports[1].counts).toEqual({ pass: 1, warn: 1, fail: 0 });
    expect(reports[0].results[0].apps).toEqual(["Payroll"]);
  });

  it("reads Intune summary lines, also out of a CSV export, and names checks from the plan", () => {
    const plan = { ...buildPlan([tenant({})], [app({})], { now }) };
    const line = `F360|v1|plan=${plan.id}|device=LAPTOP7|pass=7|warn=1|fail=1|fail:t3:login.microsoftonline.com:443,warn:t4:https://login.microsoftonline.com/`;
    const csv = `"Device name","Pre-remediation detection output"\n"LAPTOP7","${line}"\n"LAPTOP8","F360|v1|plan=${plan.id}|device=LAPTOP8|pass=9|warn=0|fail=0|"`;
    const { reports } = parseResults([csv], plan);
    expect(reports.map((r) => r.device)).toEqual(["LAPTOP7", "LAPTOP8"]);
    const r = reports[0];
    expect(r.source).toBe("summary");
    expect(r.results.map((x) => [x.status, x.id, x.target])).toEqual([["fail", "t3", "login.microsoftonline.com:443"], ["warn", "t4", "https://login.microsoftonline.com/"]]);
    expect(r.results[0].label).toBe(plan.tests[2].label);
    expect(parseSummaryLine("F360|v1|error=plan|bad")).toBeNull();
  });

  it("says when it recognises nothing, and rolls up by check", () => {
    expect(parseResults(["hello"]).errors).toHaveLength(1);
    const { reports } = parseResults([JSON.stringify([fileResult("A", "", ["fail"]), fileResult("B", "", ["pass"])])]);
    const rows = summarizeByTest(reports);
    expect(rows[0].fail).toEqual(["A"]);
    expect(rows[0].pass).toEqual(["B"]);
    expect(splitJson('{"a":"}{"}{"b":1}')).toEqual(['{"a":"}{"}', '{"b":1}']);
  });
});

import { readFileSync } from "node:fs";
import {
  ACCESS_FORMAT, accessReport, accessRow, formatLifetime, isoMinutes, parseAccess, parseCaPolicy, parseSyncJob, parseTokenPolicy,
  policiesForApp, scimHealth, timespanMinutes, type AccessSnapshot,
} from "../src/lib/access";
import { collectAccess } from "../src/lib/accessCollect";
import { sampleAccess, SAMPLE_APP_IDS } from "../src/data/sampleAccess";
import { exampleData } from "../src/data/seed";

const NOW = new Date("2026-11-24T12:00:00Z");

describe("duration parsing", () => {
  it("reads ISO 8601 durations and token-policy timespans", () => {
    expect(isoMinutes("PT40M")).toBe(40);
    expect(isoMinutes("PT1H30M")).toBe(90);
    expect(isoMinutes("P1D")).toBe(1440);
    expect(isoMinutes("")).toBeUndefined();
    expect(timespanMinutes("8:00:00")).toBe(480);
    expect(timespanMinutes("1.00:00:00")).toBe(1440);
    expect(timespanMinutes("00:30:00")).toBe(30);
    expect(timespanMinutes("nope")).toBeUndefined();
  });
});

describe("Graph objects to plain facts", () => {
  it("token lifetime policy: SAML and ID token fall back to the access token value", () => {
    const p = parseTokenPolicy({ id: "x", displayName: "Long", definition: ['{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"10:00:00"}}'] }, ["sp1"]);
    expect(p).toMatchObject({ accessTokenMinutes: 600, idTokenMinutes: 600, samlTokenMinutes: 600, appliesTo: ["sp1"], isOrganizationDefault: false });
  });

  it("Conditional Access: sign-in frequency in minutes, every time, persistent browser, CAE, users in words", () => {
    const p = parseCaPolicy({
      id: "1", displayName: "SIF", state: "enabled",
      conditions: { applications: { includeApplications: ["All"], excludeApplications: ["abc"] }, users: { includeUsers: [], includeGroups: ["g1", "g2"], excludeUsers: ["u1"] } },
      sessionControls: { signInFrequency: { isEnabled: true, value: 2, type: "days", frequencyInterval: "timeBased" }, persistentBrowser: { isEnabled: true, mode: "never" }, continuousAccessEvaluation: { mode: "strictEnforcement" } },
    });
    expect(p).toMatchObject({ signInFrequency: 2880, persistentBrowser: "never", cae: "strictEnforcement", users: "2 groups (1 excluded)" });
    expect(parseCaPolicy({ sessionControls: { signInFrequency: { isEnabled: true, frequencyInterval: "everyTime" } }, conditions: { users: { includeUsers: ["All"] } } })).toMatchObject({ signInFrequency: "everyTime", users: "All users", state: "enabledForReportingButNotEnforced" });
    expect(policiesForApp([p], "ABC")).toEqual([]);
    expect(policiesForApp([p], "def")).toHaveLength(1);
  });

  it("synchronization job: schedule, status, last run, quarantine; year-0001 runs count as never", () => {
    const j = parseSyncJob({
      id: "scim.1", templateId: "scim", schedule: { interval: "PT40M", state: "Active" },
      status: { code: "Quarantine", countSuccessiveCompleteFailures: 3, quarantine: { reason: "TooManyDeletes", seriesBegan: "2026-11-23T00:00:00Z" },
        lastExecution: { timeBegan: "2026-11-24T10:00:00Z", timeEnded: "2026-11-24T10:01:00Z", state: "Failed", error: { code: "x", message: "Boom" }, countEntitledForProvisioning: 12 },
        lastSuccessfulExecution: { timeBegan: "0001-01-01T00:00:00Z" } },
    });
    expect(j).toMatchObject({ intervalMinutes: 40, status: "Quarantine", failures: 3, inScope: 12, lastRun: { state: "Failed", error: "Boom" }, quarantine: { reason: "TooManyDeletes" } });
    expect(j.lastSuccess).toBeUndefined();
  });
});

describe("SCIM health", () => {
  const base = { id: "j", templateId: "scim", intervalMinutes: 40, scheduleState: "Active", status: "Active", failures: 0 };
  it("rates every state", () => {
    expect(scimHealth(null, "scim").health.label).toBe("Not read");
    expect(scimHealth([], "scim").health).toMatchObject({ severity: "warn", label: "No job in Entra" });
    expect(scimHealth([], "none").health.label).toBe("No SCIM");
    expect(scimHealth([{ ...base, status: "Quarantine", quarantine: { reason: "R" } }], "scim", NOW).health.severity).toBe("critical");
    expect(scimHealth([{ ...base, status: "Paused" }], "scim", NOW).health.label).toBe("Paused");
    expect(scimHealth([{ ...base, status: "NotRun" }], "scim", NOW).health.label).toBe("Never ran");
    const ok = scimHealth([{ ...base, lastRun: { began: "2026-11-24T11:40:00Z", ended: "2026-11-24T11:41:00Z", state: "Succeeded" }, lastSuccess: "2026-11-24T11:41:00Z" }], "scim", NOW).health;
    expect(ok).toMatchObject({ severity: "ok", label: "Healthy", delayMinutes: 45 });
    const behind = scimHealth([{ ...base, lastRun: { began: "2026-11-24T06:00:00Z", state: "Succeeded" }, lastSuccess: "2026-11-24T06:00:00Z" }], "scim", NOW).health;
    expect(behind.label).toBe("Behind");
  });
});

describe("access report on the sample", () => {
  const snap = sampleAccess(NOW);
  const { apps } = exampleData();
  const report = accessReport(snap, apps, NOW);
  const row = (name: string) => report.rows.find((r) => r.name === name)!;

  it("flags the quarantined job first and counts healthy jobs", () => {
    expect(report.findings[0]).toMatchObject({ severity: "critical" });
    expect(report.findings[0].title).toContain("quarantine");
    expect(report.counts.scim).toBe(3);
    expect(report.counts.scimProblems).toBe(2);
  });

  it("app policy beats the default; default is 60 to 90 minutes", () => {
    expect(row("Field Service app").accessToken).toMatchObject({ min: 480, source: "app-policy" });
    expect(formatLifetime(row("Partner Portal").accessToken)).toBe("60 to 90 min");
  });

  it("sign-in frequency takes the strictest enforced policy; report-only policies don't count", () => {
    expect(row("Expense Portal").signInFrequency.text).toBe("Every 12 hours; every time for 4 roles");
    expect(row("Partner Portal").signInFrequency.text).toBe("Rolling 90 days (Entra default); every time for 4 roles");
    expect(row("Expense Portal").persistentBrowser).toMatch(/^Never/);
    expect(row("Expense Portal").caPolicies.map((p) => p.id)).toEqual(["ca-1", "ca-2", "ca-4"]);
  });

  it("CAE never applies to a third-party app", () => {
    expect(row("AWS IAM Identity Center").cae.applies).toBe(false);
  });

  it("example inventory profiles are matched by name", () => {
    expect(row("Expense Portal").profile?.sessionMinutes).toBe(480);
    expect(row("Expense Portal").findings.some((f) => f.title.includes("keeps its own session"))).toBe(true);
  });

  it("without Conditional Access, says so and shows the default", () => {
    const noCa: AccessSnapshot = { ...snap, caPolicies: null, caNote: "Needs P1" };
    const r = accessRow(noCa, noCa.apps[0], [], NOW);
    expect(r.signInFrequency.source).toBe("not-read");
    expect(accessReport(noCa, [], NOW).findings.some((f) => f.detail === "Needs P1")).toBe(true);
  });
});

describe("loading files", () => {
  it("rejects other files", () => {
    expect(() => parseAccess("nope")).toThrow(/isn't JSON/);
    expect(() => parseAccess('{"format":"f360-posture"}')).toThrow(/isn't an access export/);
  });

  it("reads the PowerShell export (raw Graph objects)", () => {
    const raw = {
      format: ACCESS_FORMAT, version: 1, rawGraph: true, collectedAt: NOW.toISOString(), collector: "powershell",
      tenant: { id: "t", name: "T", domain: "t.example" },
      tokenPolicies: [{ policy: { id: "p", displayName: "P", isOrganizationDefault: true, definition: ['{"TokenLifetimePolicy":{"AccessTokenLifetime":"02:00:00"}}'] }, appliesTo: [] }],
      caPolicies: null, caNote: "Needs P1",
      apps: [{ spId: "s", appId: "a", name: "App", ssoMode: "saml", syncJobs: [{ id: "j", schedule: { interval: "PT40M" }, status: { code: "Active" } }] }],
      warnings: [],
    };
    const s = parseAccess(JSON.stringify(raw));
    expect(s.tokenPolicies?.[0]).toMatchObject({ isOrganizationDefault: true, accessTokenMinutes: 120 });
    expect(s.apps[0].syncJobs?.[0]).toMatchObject({ intervalMinutes: 40, status: "Active" });
    expect(accessRow(s, s.apps[0], [], NOW).accessToken).toMatchObject({ min: 120, source: "org-default" });
    expect((s as any).rawGraph).toBeUndefined();
  });

  it("round-trips a browser snapshot", () => {
    const s = sampleAccess(NOW);
    expect(parseAccess(JSON.stringify(s)).apps).toHaveLength(s.apps.length);
  });
});

describe("browser collector", () => {
  it("sends only GETs, reads policies and jobs, and survives a Free tenant's 403 on Conditional Access", async () => {
    const calls: string[] = [];
    const err = (status: number) => Object.assign(new Error(`${status} denied`), { status });
    const get = async (path: string) => {
      calls.push(path);
      if (path.startsWith("organization")) return { value: [{ id: "tid", displayName: "Lab", verifiedDomains: [{ name: "lab.example", isDefault: true }] }] };
      if (path === "policies/tokenLifetimePolicies") return { value: [{ id: "p1", displayName: "Short", definition: ['{"TokenLifetimePolicy":{"AccessTokenLifetime":"00:30:00"}}'] }] };
      if (path.startsWith("policies/tokenLifetimePolicies/p1/appliesTo")) return { value: [{ id: "sp-saml", appId: SAMPLE_APP_IDS.expenses }] };
      if (path.startsWith("identity/conditionalAccess")) throw err(403);
      if (path.startsWith("servicePrincipals?")) return { value: [
        { id: "sp-saml", appId: SAMPLE_APP_IDS.expenses, displayName: "LAB-SAML-App", servicePrincipalType: "Application", tags: ["WindowsAzureActiveDirectoryIntegratedApp"], preferredSingleSignOnMode: "saml" },
        { id: "sp-scim", appId: "scim-app", displayName: "F360-ScimApp", servicePrincipalType: "Application", tags: ["WindowsAzureActiveDirectoryIntegratedApp"] },
        { id: "sp-ms", appId: "ms", displayName: "Microsoft thing", servicePrincipalType: "Application", appOwnerOrganizationId: "f8cdef31-a31e-4b4a-93e4-5f571e91255a", tags: ["WindowsAzureActiveDirectoryIntegratedApp"] },
      ] };
      if (path === "servicePrincipals/sp-saml/synchronization/jobs") return { value: [] };
      if (path === "servicePrincipals/sp-scim/synchronization/jobs") return { value: [{ id: "scim.x", schedule: { interval: "PT40M", state: "Active" }, status: { code: "Active", lastExecution: { timeBegan: "2026-11-24T11:50:00Z", timeEnded: "2026-11-24T11:51:00Z", state: "Succeeded" } } }] };
      throw err(404);
    };
    const s = await collectAccess(get, "tid");
    expect(s.caPolicies).toBeNull();
    expect(s.caNote).toMatch(/P1/);
    expect(s.apps.map((a) => a.name)).toEqual(["LAB-SAML-App", "F360-ScimApp"]);
    expect(s.tokenPolicies?.[0].appliesTo).toContain("sp-saml");
    expect(s.apps[1].syncJobs?.[0].status).toBe("Active");
    expect(calls.some((c) => c.includes("ms/synchronization"))).toBe(false);
  });
});

describe("Export-F360Access.ps1", () => {
  const ps = readFileSync("access/Export-F360Access.ps1", "utf8");
  it("asks only for the three read-only scopes and never writes to Graph", () => {
    expect(ps).toContain("@('Application.Read.All', 'Policy.Read.All', 'Synchronization.Read.All')");
    expect(ps).not.toMatch(/-Method (POST|PATCH|PUT|DELETE)/i);
    expect(ps).toContain("format        = 'f360-access'");
    expect(ps).toContain("rawGraph      = $true");
  });
});

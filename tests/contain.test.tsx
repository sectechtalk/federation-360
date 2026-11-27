import { renderToStaticMarkup } from "react-dom/server";
import { Ctx, type AppCtx } from "../src/components/ui";
import UserLookup from "../src/views/UserLookup";
import { compareReads, containRunbook, liveRefreshes, r360Base, r360DeviceUrl, r360OffboardUrl } from "../src/lib/contain";
import { sampleUserAccess, SAMPLE_PEOPLE } from "../src/data/sampleUserAccess";
import type { FlowCapture } from "../src/lib/flow";

const SP = "e1a2b3c4-0000-4000-8000-000000000007";
const SP2 = "e1a2b3c4-0000-4000-8000-000000000002";
const GRAY = SAMPLE_PEOPLE[0];
afterEach(() => localStorage.clear());

describe("Remediation 360 hand-off links", () => {
  it("builds the Offboard link Remediation 360 reads: user, GUID apps as id:name, source", () => {
    const url = r360OffboardUrl("http://localhost:3660/some/path", "disable", "sam.leaver@contoso.example", [{ spId: SP, name: "HR Hub" }, { spId: "nope", name: "x" }, { spId: SP2, name: "AWS & Co" }]);
    expect(url.startsWith("http://localhost:3660/#offboard/disable?")).toBe(true);
    const q = new URLSearchParams(url.split("?")[1]);
    expect(q.get("user")).toBe("sam.leaver@contoso.example");
    expect(q.getAll("app")).toEqual([`${SP}:HR Hub`, `${SP2}:AWS & Co`]);
    expect(q.get("from")).toBe("federation-360");
  });
  it("sends exactly one app for Remove from one app, and the device name for Emergency", () => {
    const q = new URLSearchParams(r360OffboardUrl("", "remove", "a@b.com", [{ spId: SP, name: "A" }, { spId: SP2, name: "B" }]).split("?")[1]);
    expect(q.getAll("app")).toHaveLength(1);
    expect(r360DeviceUrl("http://localhost:3660", "SAM-MACBOOK")).toBe("http://localhost:3660/#emergency/device?name=SAM-MACBOOK&action=isolate");
  });
  it("accepts only localhost over http, any https origin, nothing else", () => {
    expect(r360Base("https://remediation.contoso.example/x")).toBe("https://remediation.contoso.example");
    expect(r360Base("http://evil.example")).toBe("http://localhost:3660");
    expect(r360Base("javascript:alert(1)")).toBe("http://localhost:3660");
    expect(r360Base("")).toBe("http://localhost:3660");
  });
});

describe("Contain runbook", () => {
  const ps = containRunbook({ upn: "o'brien@contoso.example", tenantId: "00000000-0000-0000-0000-000000000000", apps: [{ spId: SP, name: "HR Hub" }] });
  it("changes nothing without -Run, and asks before every write", () => {
    expect(ps).toContain("if (-not $Run) { $WhatIfPreference = $true");
    expect(ps).toContain("[CmdletBinding(SupportsShouldProcess)]");
    const writes = ps.match(/-Method (PATCH|POST)/g) ?? [];
    expect(writes).toHaveLength(3);
    expect((ps.match(/\$PSCmdlet\.ShouldProcess/g) ?? []).length).toBe(3);
    expect(ps).not.toMatch(/-Method DELETE|Directory\.ReadWrite|Application\.ReadWrite/);
  });
  it("quotes the person safely and lists the SCIM apps", () => {
    expect(ps).toContain("[string]$User = 'o''brien@contoso.example'");
    expect(ps).toContain(`@{ Id = '${SP}'; Name = 'HR Hub' }`);
    expect(ps).toContain("provisionOnDemand");
    expect(ps).toContain("revokeSignInSessions");
  });
});

describe("compareReads", () => {
  it("shows the account disabled, sessions revoked and a removed assignment", () => {
    const before = sampleUserAccess(GRAY, new Date("2026-11-24T10:00:00Z"))!;
    const after = { ...before, collectedAt: "2026-11-24T11:00:00Z", user: { ...before.user, enabled: false, sessionsValidFrom: "2026-11-24T10:30:00Z" }, assignments: before.assignments.slice(1) };
    const c = compareReads(before, after);
    expect(c.find((x) => x.what === "Account")).toMatchObject({ before: "Enabled", after: "Disabled", good: true });
    expect(c.find((x) => x.what === "Sessions valid from")!.good).toBe(true);
    expect(c.some((x) => x.what === "Removed: Expense Portal")).toBe(true);
    expect(compareReads(before, before).find((x) => x.what === "Account")!.good).toBe(false);
  });
});

describe("liveRefreshes", () => {
  const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  const jwt = (iat: number) => `${b64({ alg: "none" })}.${b64({ iat, exp: iat + 75 * 60, aud: "x" })}.sig`;
  const step = (min: number, client: string, error?: string) => ({
    at: new Date(Date.parse("2026-11-24T10:00:00Z") + min * 60000).toISOString(), from: "browser", to: "idp", label: "Tokens are refreshed",
    params: { grant_type: "refresh_token", client_id: client, scope: "openid" }, tokens: error ? [] : [{ name: "access_token", value: jwt(1_700_000_000) }], ...(error ? { error: { code: error } } : {}),
  });
  it("groups refreshes per app with the typical gap and the token lifetime", () => {
    const caps = [{ id: "1", steps: [step(0, "app-a"), step(70, "app-a"), step(140, "app-a"), step(150, "app-b", "invalid_grant"), { ...step(5, "app-a"), params: { grant_type: "authorization_code", client_id: "app-a" } }] } as unknown as FlowCapture];
    const { events, apps } = liveRefreshes(caps);
    expect(events).toHaveLength(4);
    const a = apps.find((x) => x.clientId === "app-a")!;
    expect(a).toMatchObject({ count: 3, medianGapMin: 70, lifetimeMin: 75, failures: 0 });
    expect(apps.find((x) => x.clientId === "app-b")!.failures).toBe(1);
  });
});

describe("User lookup Contain panel", () => {
  const ctx = (params: Record<string, string>): AppCtx => ({ store: null, tenants: [], apps: [], loading: false, go: () => {}, params, toast: () => {}, loadExamples: async () => {} });
  it("offers Remediation 360 hand-offs, the runbook, Verify, the drill, and shows before and after", () => {
    const after = sampleUserAccess(GRAY, new Date())!;
    const before = sampleUserAccess(GRAY, new Date(Date.now() - 3600_000))!;
    localStorage.setItem("f360:pref:lookup:reads", JSON.stringify({ [GRAY]: { ...after, user: { ...after.user, enabled: false } } }));
    localStorage.setItem("f360:pref:lookup:previous", JSON.stringify({ [GRAY]: before }));
    const out = renderToStaticMarkup(<Ctx.Provider value={ctx({ q: GRAY })}><UserLookup /></Ctx.Provider>);
    for (const t of ["Contain", "Disable user everywhere in Remediation 360", "Download contain runbook", "Verify with a fresh read", "Lab offboarding drill", "Isolate in Remediation 360", "As expected"]) expect(out).toContain(t);
  });
});

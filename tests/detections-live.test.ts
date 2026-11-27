import { readLogFile, readEntity360Timeline, parseCsvRows, toSignIn, type SignInEvent, type AuditEvent } from "../src/detections/events";
import { riskySignIn, riskyThenChange, runDetections } from "../src/detections/rules";
import { readTenantLogs, MAX_ROWS } from "../src/detections/live";

const T0 = Date.parse("2026-11-20T08:00:00Z");
const MIN = 60_000;
const si = (min: number, user: string, p: Partial<SignInEvent> = {}): SignInEvent => ({
  time: T0 + min * MIN, user, ip: "192.0.2.10", country: "US", city: "Seattle", interactive: true, app: "Exchange", client: "Browser", errorCode: 0, details: "", session: "", risk: "none", ...p,
});
const au = (min: number, activity: string, actor: string, p: Partial<AuditEvent> = {}): AuditEvent => ({ time: T0 + min * MIN, activity, actor, targetUser: "", target: "", ...p });
const logs = (signIns: SignInEvent[], audits: AuditEvent[] = []) => ({ signIns, audits, sources: [] });

describe("risky sign-in", () => {
  it("medium is a warning, high is critical, failures and low risk don't count", () => {
    expect(riskySignIn.run(logs([si(0, "a", { risk: "medium" })]), [])).toMatchObject([{ severity: "warn", user: "a" }]);
    expect(riskySignIn.run(logs([si(0, "a", { risk: "medium" }), si(5, "a", { risk: "high" })]), [])).toMatchObject([{ severity: "critical" }]);
    expect(riskySignIn.run(logs([si(0, "a", { risk: "high", errorCode: 50126 }), si(1, "b", { risk: "low" })]), [])).toEqual([]);
  });
  it("says it can't run when no sign-in carries a risk level, instead of all clear", () => {
    const r = runDetections(logs([{ ...si(0, "a"), risk: "" }]));
    expect(r.find((x) => x.rule.id === "risky-signin")?.missing).toMatch(/P2/);
  });
});

describe("sensitive change after a risky sign-in", () => {
  it("fires on a role, MFA method or credential change by or to the same person within 4 hours", () => {
    const h = riskyThenChange.run(logs([si(0, "a", { risk: "high" })], [au(30, "Add member to role", "admin@x", { targetUser: "a", target: "Global Administrator" })]), []);
    expect(h).toMatchObject([{ severity: "critical", user: "a", title: "Add member to role (Global Administrator) 30 minutes after a high-risk sign-in" }]);
    expect(h[0].evidence[1]).toMatch(/by admin@x/);
  });
  it("doesn't fire after 4 hours, before the sign-in, on ordinary activities, or on app consent (its own rule covers that)", () => {
    const s = [si(0, "a", { risk: "medium" })];
    expect(riskyThenChange.run(logs(s, [au(300, "User registered security info", "a")]), [])).toEqual([]);
    expect(riskyThenChange.run(logs(s, [au(-10, "User registered security info", "a")]), [])).toEqual([]);
    expect(riskyThenChange.run(logs(s, [au(10, "Update group", "a"), au(11, "Consent to application", "a")]), [])).toEqual([]);
  });
});

describe("Entity 360 exports", () => {
  const csv = '﻿"Time UTC","Activity","Category","Result","Source","Actor","Target","Direction","IP","Record ID"\r\n' +
    '"2026-11-20T08:00:00Z","Office 365 Exchange Online sign-in","Sign-in","Success","Entra","Alex Admin","Office 365 Exchange Online","Actor","192.0.2.5","abc"\r\n' +
    '"2026-11-20T08:05:00Z","Azure Portal sign-in","Sign-in","Failure","Entra","Alex Admin","Azure Portal","Actor","203.0.113.9","def"\r\n' +
    '"2026-11-20T09:00:00Z","Add member to group","Audit","Success","Entra","Alex Admin","Group, with comma","Actor","",""\r\n';
  it("reads the timeline CSV's sign-in rows, keyed by the person's name, with failures marked as reason unknown", () => {
    const l = readLogFile("entity-360-user-11111111-2222-3333-4444-555555555555-2026-11-20.csv", csv);
    expect(l.signIns).toHaveLength(2);
    expect(l.signIns[0]).toMatchObject({ user: "alex admin", app: "Office 365 Exchange Online", errorCode: 0, ip: "192.0.2.5", country: "", from: "Entity 360" });
    expect(l.signIns[1].errorCode).toBe(-1);
    expect(l.sources[0]).toMatch(/from Entity 360 .*no country, error code or risk level/);
  });
  it("parses quoted cells and strips the formula guard", () => {
    expect(parseCsvRows('"a ""b""","c, d","\'=1+1"\n')).toEqual([['a "b"', "c, d", "=1+1"]]);
    expect(readEntity360Timeline("x.csv", '"Foo","Bar"\n"1","2"\n')).toEqual([]);
    expect(() => readLogFile("x.csv", '"Time UTC","Activity","Category"\n"2026-11-20T08:00:00Z","Thing","Audit"\n')).toThrow(/no Entity 360 sign-in rows/);
  });
  it("reads one sign-in pasted from Raw source evidence, with risk and device", () => {
    const l = readLogFile("pasted.json", JSON.stringify({ createdDateTime: "2026-11-20T08:00:00Z", userPrincipalName: "A@x.example", status: { errorCode: 0 }, riskLevelDuringSignIn: "High", deviceDetail: { displayName: "LAPTOP-1" } }));
    expect(l.signIns[0]).toMatchObject({ user: "a@x.example", risk: "high", device: "LAPTOP-1" });
    expect(toSignIn({ TimeGenerated: "2026-11-20T08:00:00Z", UserPrincipalName: "b@x", RiskLevelDuringSignIn: "medium", DeviceDetail: '{"displayName":"PC-2"}' })).toMatchObject({ risk: "medium", device: "PC-2" });
  });
});

describe("read from your tenant", () => {
  const tok = (scp: string) => `x.${btoa(JSON.stringify({ scp }))}.y`;
  const reply = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status }));
  it("pages through sign-ins and audits, marks non-interactive ones, and filters audits to the user", async () => {
    const urls: string[] = [];
    const f = (async (u: string) => {
      urls.push(u);
      if (u.includes("page2")) return reply({ value: [{ createdDateTime: "2026-11-20T08:05:00Z", userPrincipalName: "a@x", status: { errorCode: 0 }, riskLevelDuringSignIn: "high" }] });
      if (u.includes("interactiveUser")) return reply({ value: [{ createdDateTime: "2026-11-20T08:00:00Z", userPrincipalName: "a@x", status: { errorCode: 0 } }], "@odata.nextLink": "https://graph.microsoft.com/page2" });
      if (u.includes("nonInteractiveUser")) return reply({ value: [{ createdDateTime: "2026-11-20T07:00:00Z", userPrincipalName: "a@x", status: { errorCode: 0 } }] });
      return reply({ value: [
        { activityDateTime: "2026-11-20T08:10:00Z", activityDisplayName: "Add member to role", initiatedBy: { user: { userPrincipalName: "boss@x" } }, targetResources: [{ userPrincipalName: "a@x", type: "User" }] },
        { activityDateTime: "2026-11-20T08:10:00Z", activityDisplayName: "Update group", initiatedBy: { user: { userPrincipalName: "c@x" } }, targetResources: [] },
      ] });
    }) as unknown as typeof fetch;
    const r = await readTenantLogs(tok("AuditLog.Read.All Directory.Read.All"), { days: 7, user: "A@x" }, f);
    expect(r.logs.signIns.map((s) => [s.interactive, s.risk])).toEqual([[false, ""], [true, ""], [true, "high"]]);
    expect(r.logs.audits.map((a) => a.activity)).toEqual(["Add member to role"]);
    expect(urls[0]).toContain(encodeURIComponent("userPrincipalName eq 'a@x'"));
    expect(r.logs.sources[0]).toMatch(/3 sign-ins, 1 audit events, 1 sign-in with a risk level/);
    expect(r.capped).toEqual([]);
    expect(MAX_ROWS).toBeGreaterThan(1000);
  });
  it("refuses a token without AuditLog.Read.All and explains Graph's refusals", async () => {
    await expect(readTenantLogs(tok("User.Read"), { days: 7 })).rejects.toMatchObject({ problem: "no-consent" });
    const f = (() => reply({ error: { code: "Authentication_RequestFromNonPremiumTenantOrB2CTenant", message: "premium license" } }, 403)) as unknown as typeof fetch;
    await expect(readTenantLogs(tok("AuditLog.Read.All"), { days: 7 }, f)).rejects.toMatchObject({ problem: "unlicensed" });
  });
});

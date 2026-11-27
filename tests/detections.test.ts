import { readLogFile, mergeLogs, EMPTY_LOGS, toSignIn, type LoadedLogs, type SignInEvent, type AuditEvent } from "../src/detections/events";
import { RULES, runDetections, mfaFatigue, passwordSpray, bruteForceSuccess, legacyAuth, tokenReplay, newCountryThenMfaChange, consentAfterSuspicious } from "../src/detections/rules";
import { sampleSignInLog } from "../src/detections/sample";
import { playbookById } from "../src/data/playbooks";

const T0 = Date.parse("2026-11-20T08:00:00Z");
const MIN = 60_000;
let n = 0;
const si = (min: number, user: string, p: Partial<SignInEvent> = {}): SignInEvent => ({
  time: T0 + min * MIN, user, ip: "192.0.2.10", country: "US", city: "Seattle", interactive: true, app: "Exchange", client: "Browser", errorCode: 0, details: "", session: `s-${user}-${++n}`, ...p,
});
const au = (min: number, activity: string, actor: string, p: Partial<AuditEvent> = {}): AuditEvent => ({ time: T0 + min * MIN, activity, actor, targetUser: "", target: "", ...p });
const logs = (signIns: SignInEvent[], audits: AuditEvent[] = []): LoadedLogs => ({ signIns, audits, sources: [] });
const run = (r: (typeof RULES)[number], l: LoadedLogs) => r.run.call(r, l, []);

describe("MFA fatigue", () => {
  const denied = (m: number) => si(m, "u", { errorCode: 500121, ip: "198.51.100.1", country: "NL" });
  it("3 denials in 10 minutes is a warning; a success within the hour makes it critical", () => {
    expect(run(mfaFatigue, logs([denied(0), denied(3), denied(6)]))[0]).toMatchObject({ severity: "warn", user: "u" });
    const h = run(mfaFatigue, logs([denied(0), denied(3), denied(6), si(40, "u", { ip: "198.51.100.1" })]))[0];
    expect(h.severity).toBe("critical");
    expect(h.title).toMatch(/then a successful sign-in/);
  });
  it("does not fire on 2 denials or on 3 spread over more than 10 minutes, and a success 2 hours later stays a warning", () => {
    expect(run(mfaFatigue, logs([denied(0), denied(5)]))).toEqual([]);
    expect(run(mfaFatigue, logs([denied(0), denied(6), denied(12)]))).toEqual([]);
    expect(run(mfaFatigue, logs([denied(0), denied(1), denied(2), si(200, "u")]))[0].severity).toBe("warn");
  });
  it("a fraud report makes it critical", () => {
    expect(run(mfaFatigue, logs([denied(0), denied(1), { ...denied(2), details: "MFA denied; user reported fraud" }]))[0].severity).toBe("critical");
  });
});

describe("password spray", () => {
  const fail = (m: number, u: string) => si(m, u, { errorCode: 50126, ip: "203.0.113.5" });
  const users = Array.from({ length: 10 }, (_, i) => `user${i}`);
  it("10 accounts from one address within an hour fires; a success from that address makes it critical", () => {
    expect(run(passwordSpray, logs(users.map((u, i) => fail(i * 5, u))))[0]).toMatchObject({ severity: "warn" });
    const h = run(passwordSpray, logs([...users.map((u, i) => fail(i * 5, u)), si(50, "user3", { ip: "203.0.113.5" })]))[0];
    expect(h).toMatchObject({ severity: "critical", user: "user3" });
  });
  it("9 accounts, or 10 spread over more than an hour, doesn't fire", () => {
    expect(run(passwordSpray, logs(users.slice(0, 9).map((u, i) => fail(i, u))))).toEqual([]);
    expect(run(passwordSpray, logs(users.map((u, i) => fail(i * 10, u))))).toEqual([]);
  });
});

describe("password guessing then success", () => {
  const fails = (k: number) => Array.from({ length: k }, (_, i) => si(i * 3, "u", { errorCode: 50126, ip: "203.0.113.9" }));
  it("10 failures then a success within the hour is critical", () => {
    const h = run(bruteForceSuccess, logs([...fails(10), si(60, "u", { ip: "203.0.113.9" })]));
    expect(h[0]).toMatchObject({ severity: "critical", title: "10 wrong passwords, then signed in from the same address" });
  });
  it("9 failures, or no success, doesn't fire", () => {
    expect(run(bruteForceSuccess, logs([...fails(9), si(40, "u")]))).toEqual([]);
    expect(run(bruteForceSuccess, logs(fails(12)))).toEqual([]);
  });
});

test("legacy authentication: successful IMAP fires, a failed one and modern clients don't", () => {
  expect(run(legacyAuth, logs([si(0, "u", { client: "IMAP4" })]))[0]).toMatchObject({ severity: "warn", title: "Signed in with IMAP4 (1 time)" });
  expect(run(legacyAuth, logs([si(0, "u", { client: "IMAP4", errorCode: 50126 }), si(1, "v", { client: "Mobile Apps and Desktop clients" })]))).toEqual([]);
});

test("token replay: one session from two countries within a day is critical; same country or a day apart isn't", () => {
  const a = si(0, "u", { session: "S1" });
  expect(run(tokenReplay, logs([a, si(60, "u", { session: "S1", country: "SG", interactive: false })]))[0]).toMatchObject({ severity: "critical", title: "One session used from US and SG" });
  expect(run(tokenReplay, logs([a, si(60, "u", { session: "S1", ip: "192.0.2.99" })]))).toEqual([]);
  expect(run(tokenReplay, logs([a, si(26 * 60, "u", { session: "S1", country: "SG" })]))).toEqual([]);
});

test("new country then new security info: needs earlier history, fires within 2 hours", () => {
  const hist = si(0, "u");
  const ng = si(300, "u", { country: "NG", ip: "198.51.100.5" });
  const add = au(330, "User registered security info", "u", { targetUser: "u" });
  expect(run(newCountryThenMfaChange, logs([hist, ng], [add]))[0]).toMatchObject({ severity: "critical", title: "First sign-in from NG, then new security info 30 minutes later" });
  expect(run(newCountryThenMfaChange, logs([ng], [add]))).toEqual([]); // no history: stays quiet
  expect(run(newCountryThenMfaChange, logs([hist, ng], [au(500, "User registered security info", "u", { targetUser: "u" })]))).toEqual([]); // too late
  expect(run(newCountryThenMfaChange, logs([hist, si(300, "u")], [add]))).toEqual([]); // same country
});

test("consent after a flagged sign-in fires; consent without one doesn't", () => {
  const prior = [{ rule: "mfa-fatigue", severity: "critical" as const, user: "u", time: T0, title: "x", evidence: [] }];
  const c = au(60, "Consent to application", "u", { target: "Notes app" });
  expect(consentAfterSuspicious.run.call(consentAfterSuspicious, logs([], [c]), prior)[0].title).toBe("Consented to Notes app after: x");
  expect(consentAfterSuspicious.run.call(consentAfterSuspicious, logs([], [c]), [])).toEqual([]);
});

test("rules say when the logs can't support them instead of reporting all clear", () => {
  const r = runDetections(logs([si(0, "u", { session: "" })]));
  const missing = Object.fromEntries(r.map((x) => [x.rule.id, x.missing ?? ""]));
  expect(missing["token-replay"]).toMatch(/no session IDs/);
  expect(missing["new-country-mfa-change"]).toMatch(/audit logs/);
  expect(missing["mfa-fatigue"]).toBe("");
});

test("the sample log fires every rule once, and nothing on the ordinary sign-ins", () => {
  const l = readLogFile("sample", JSON.stringify(sampleSignInLog(new Date("2026-11-21T08:00:00Z"))));
  const r = runDetections(l);
  for (const x of r) expect(x.missing, x.rule.id).toBeUndefined();
  const byRule = Object.fromEntries(r.map((x) => [x.rule.id, x.hits]));
  expect(byRule["mfa-fatigue"].map((h) => [h.user, h.severity])).toEqual([["blair.ops@f360sample.onmicrosoft.com", "critical"]]);
  expect(byRule["password-spray"].map((h) => [h.user, h.severity])).toEqual([["noor.legal@f360sample.onmicrosoft.com", "critical"]]);
  expect(byRule["brute-force-success"].map((h) => h.user)).toEqual(["oak.warehouse@f360sample.onmicrosoft.com"]);
  expect(byRule["legacy-auth-success"].map((h) => h.user)).toEqual(["pat.warehouse@f360sample.onmicrosoft.com"]);
  expect(byRule["token-replay"].map((h) => h.user)).toEqual(["frankie.mac@f360sample.onmicrosoft.com"]);
  expect(byRule["new-country-mfa-change"].map((h) => h.user)).toEqual(["casey.helpdesk@f360sample.onmicrosoft.com"]);
  expect(byRule["consent-after-suspicious"].map((h) => h.title)).toEqual([expect.stringMatching(/^Consented to Northwind Meeting Notes after: 5 MFA prompts/)]);
  expect(byRule["risky-signin"].map((h) => [h.user, h.severity])).toEqual([
    ["casey.helpdesk@f360sample.onmicrosoft.com", "warn"],
    ["gray.finance@f360sample.onmicrosoft.com", "critical"],
  ]);
  expect(byRule["risky-then-change"].map((h) => [h.user, h.title])).toEqual([
    ["casey.helpdesk@f360sample.onmicrosoft.com", "User registered security info 20 minutes after a medium-risk sign-in"],
    ["gray.finance@f360sample.onmicrosoft.com", "Add member to role (Global Administrator) 25 minutes after a high-risk sign-in"],
  ]);
});

test("reads Log Analytics columns, Graph Explorer pages and audit rows; rejects other files with plain words", () => {
  const la = toSignIn({ TimeGenerated: "2026-11-20T08:00:00Z", UserPrincipalName: "A@x.example", IPAddress: "192.0.2.1", ResultType: "50126", LocationDetails: '{"countryOrRegion":"us","city":"Seattle"}', ClientAppUsed: "Browser", SessionId: "S", Category: "NonInteractiveUserSignInLogs" })!;
  expect(la).toMatchObject({ user: "a@x.example", errorCode: 50126, country: "US", session: "S", interactive: false });
  const page = readLogFile("graph.json", JSON.stringify({ value: [{ createdDateTime: "2026-11-20T08:00:00Z", userPrincipalName: "b@x.example", status: { errorCode: 0 } }] }));
  expect(page.signIns).toHaveLength(1);
  const audits = readLogFile("audit.json", JSON.stringify([{ activityDateTime: "2026-11-20T08:00:00Z", activityDisplayName: "Consent to application", initiatedBy: { user: { userPrincipalName: "B@x.example" } }, targetResources: [{ displayName: "App", type: "ServicePrincipal" }] }]));
  expect(audits.audits[0]).toMatchObject({ actor: "b@x.example", target: "App" });
  expect(mergeLogs(page, audits)).toMatchObject({ signIns: [{}], audits: [{}] });
  expect(() => readLogFile("x.json", "{")).toThrow(/isn't JSON/);
  expect(() => readLogFile("x.json", JSON.stringify([{ hello: 1 }]))).toThrow(/no sign-in or audit events/);
  expect(EMPTY_LOGS.signIns).toEqual([]);
});

test("every rule has an ATT&CK technique, KQL and an existing playbook", () => {
  for (const r of RULES) {
    expect(r.attack.id, r.id).toMatch(/^T\d{4}(\.\d{3})?$/);
    expect(r.kql.length, r.id).toBeGreaterThan(40);
    expect(playbookById(r.playbook), r.id).toBeTruthy();
  }
  expect(new Set(RULES.map((r) => r.id)).size).toBe(RULES.length);
});

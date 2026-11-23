// Entra's verdict: finding a captured sign-in in Entra's sign-in log and explaining it in plain words.
import { classifyGraphError, consumeSetupLink, explain, fetchCandidates, LogsError, matchSignIns, tenantConfigs, type SignInRecord } from "../src/lib/entraLogs";
import { entraHints, parseHarEntries, type HarEntry } from "../src/lib/har";
import { addHop, addTokenResponse, classify, toEntry, type CaptureState } from "../extension/capture-core.js";
import type { EntraHints } from "../src/lib/flow";

const T = "8f2b6c1e-0d4a-4a7e-9a51-3c0d2e7b9f10";
const APP = "11111111-2222-4333-8444-555555555555";
const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const jwt = (claims: object) => `${b64({ alg: "RS256", typ: "JWT" })}.${b64(claims)}.sig`;

const rec = (o: Partial<SignInRecord>): SignInRecord => ({ id: crypto.randomUUID(), createdDateTime: "2026-11-17T12:00:00Z", userPrincipalName: "lab.user1@contoso.onmicrosoft.com", appDisplayName: "Expenses", appId: APP, status: { errorCode: 0 }, ...o });
const hints = (o: Partial<EntraHints> = {}): EntraHints => ({ tenant: T, requestIds: [], correlationIds: [], clientIds: [], from: "2026-11-17T11:59:50Z", to: "2026-11-17T12:00:05Z", ...o });

test("Graph refusals sort into problems a person can fix", () => {
  expect(classifyGraphError(403, "Authentication_RequestFromNonPremiumTenantOrB2CTenant", "Neither tenant is B2C or tenant doesn't have premium license")).toBe("unlicensed");
  expect(classifyGraphError(403, "Authentication_MSGraphPermissionMissing", "Calling principal does not have required MSGraph permissions AuditLog.Read.All")).toBe("no-consent");
  expect(classifyGraphError(403, "Authentication_RequestFromUnsupportedUserRole", "User is not in the allowed roles")).toBe("no-role");
  expect(classifyGraphError(401, "InvalidAuthenticationToken", "Lifetime validation failed, the token is expired.")).toBe("signed-out");
});

test("a token without AuditLog.Read.All is reported as missing consent before Graph is called", async () => {
  const f = vi.fn();
  vi.stubGlobal("fetch", f);
  await expect(fetchCandidates(jwt({ scp: "User.Read openid" }), hints())).rejects.toMatchObject({ problem: "no-consent" });
  expect(f).not.toHaveBeenCalled();
  vi.unstubAllGlobals();
});

test("a free tenant's refusal becomes 'unlicensed', not an error", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: { code: "Authentication_RequestFromNonPremiumTenantOrB2CTenant", message: "Neither tenant is B2C or tenant doesn't have premium license" } }), { status: 403 })));
  const e = await fetchCandidates(jwt({ scp: "AuditLog.Read.All" }), hints()).catch((x) => x);
  expect(e).toBeInstanceOf(LogsError);
  expect(e.problem).toBe("unlicensed");
  vi.unstubAllGlobals();
});

test("matches by request ID, and brings the MFA prompt from the same correlation along", () => {
  const corr = crypto.randomUUID();
  const mfa = rec({ correlationId: corr, createdDateTime: "2026-11-17T11:59:58Z", status: { errorCode: 50074 } });
  const ok = rec({ correlationId: corr });
  const other = rec({ appId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" });
  const m = matchSignIns(hints({ requestIds: [ok.id] }), [other, ok, mfa]);
  expect(m?.how).toBe("exact");
  expect(m?.records).toEqual([mfa, ok]);
});

test("falls back to the closest sign-in to the same app, and says so", () => {
  const near = rec({ createdDateTime: "2026-11-17T12:00:20Z", correlationId: "c1" });
  const far = rec({ createdDateTime: "2026-11-17T13:00:00Z", correlationId: "c2" });
  expect(matchSignIns(hints({ clientIds: [APP] }), [far, near])).toEqual({ records: [near], how: "likely" });
  expect(matchSignIns(hints(), [near])).toBeNull();
});

test("plain words: success with Conditional Access satisfied", () => {
  const v = explain([rec({ conditionalAccessStatus: "success", authenticationRequirement: "multiFactorAuthentication", appliedConditionalAccessPolicies: [{ id: "p1", displayName: "Require MFA for admins", result: "success" }] })]);
  expect(v.tone).toBe("ok");
  expect(v.headline).toBe("Entra signed lab.user1@contoso.onmicrosoft.com in to Expenses.");
  expect(v.lines.join(" ")).toContain("“Require MFA for admins” applied and was satisfied");
});

test("plain words: blocked by a named Conditional Access policy, with the fix and playbook", () => {
  const v = explain(
    [rec({ status: { errorCode: 53003, failureReason: "Access has been blocked by Conditional Access policies." }, conditionalAccessStatus: "failure", appliedConditionalAccessPolicies: [{ id: "p2", displayName: "Block outside US", result: "failure", enforcedGrantControls: ["block"] }] })],
    (c) => c === "AADSTS53003",
  );
  expect(v.tone).toBe("fail");
  expect(v.headline).toContain("A Conditional Access policy blocked the sign-in. (AADSTS53003)");
  expect(v.lines[0]).toBe("Blocked by Conditional Access policy “Block outside US”, which requires nothing: it blocks access.");
  expect(v.fix).toBeTruthy();
  expect(v.playbook).toBe("AADSTS53003");
});

test("plain words: an unanswered MFA prompt is a pause, and hidden policy names are explained", () => {
  const v = explain([rec({ status: { errorCode: 50074 }, conditionalAccessStatus: "success" })]);
  expect(v.tone).toBe("warn");
  expect(v.headline).toContain("multifactor authentication");
  expect(v.lines.join(" ")).toContain("Security Reader");
});

test("the setup script's link connects the tenant, including a free tenant", () => {
  history.replaceState(null, "", `/#flowtracer&f360logs=${T}.${APP}.Contoso%20Ltd`);
  expect(consumeSetupLink()).toEqual({ tenantId: T, clientId: APP, name: "Contoso Ltd" });
  expect(location.hash).toBe("#flowtracer");
  expect(tenantConfigs()[T].clientId).toBe(APP);
  history.replaceState(null, "", `/#flowtracer&f360logs=${T}.free`);
  expect(consumeSetupLink()?.clientId).toBe("free");
});

test("a recording yields the tenant, request IDs, correlation IDs and client ID", () => {
  const rid = "0a1b2c3d-4e5f-4061-8728-394a5b6c7d8e";
  const crid = "9e8d7c6b-5a49-4382-a716-f5e4d3c2b1a0";
  const entries: HarEntry[] = [
    { startedDateTime: "2026-11-17T12:00:00Z", request: { method: "GET", url: `https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=${APP}&scope=openid&response_type=code`, headers: [{ name: "client-request-id", value: crid }] }, response: { status: 302, redirectURL: "http://localhost:5180/cb?code=x&state=y", headers: [{ name: "x-ms-request-id", value: rid }] } },
    { startedDateTime: "2026-11-17T12:00:01Z", request: { method: "POST", url: "https://login.microsoftonline.com/organizations/oauth2/v2.0/token", postData: { mimeType: "application/x-www-form-urlencoded", text: `client_id=${APP}&grant_type=authorization_code&code=x` } }, response: { status: 200, content: { text: JSON.stringify({ id_token: jwt({ tid: T, aud: APP }) }) } } },
  ];
  const c = parseHarEntries(entries, { title: "t" });
  expect(c.entra).toMatchObject({ tenant: T, requestIds: [rid], correlationIds: [crid], clientIds: [APP] });
  expect(entraHints([{ request: { method: "GET", url: "https://example.com/" }, response: { status: 200 } }], [])).toBeUndefined();
});

describe("token replies read inside the page", () => {
  const TOKEN = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";
  const body = JSON.stringify({ access_token: jwt({ aud: "api://lab", tid: T }), refresh_token: "(issued)" });
  const start = (state: CaptureState, now: number) => {
    const e = toEntry({ url: `https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=${APP}&scope=openid`, method: "GET", time: now }, { status: 200 });
    addHop(state, { tabId: 1, entry: e, kind: classify(e), now });
  };

  test("fill in the network copy when it came first", () => {
    const now = Date.now();
    const state: CaptureState = { flows: [] };
    start(state, now);
    const net = toEntry({ url: TOKEN, method: "POST", formData: { grant_type: ["authorization_code"], client_id: [APP] }, time: now }, { status: 200 });
    addHop(state, { tabId: 1, entry: net, kind: classify(net), now });
    addTokenResponse(state, { tabId: 1, url: TOKEN, request: "grant_type=authorization_code", status: 200, body, now: now + 50 });
    expect(state.flows[0].entries).toHaveLength(2);
    expect(state.flows[0].entries[1].response.content?.text).toBe(body);
  });

  test("are joined by the network copy when they came first, with no duplicate hop", () => {
    const now = Date.now();
    const state: CaptureState = { flows: [] };
    start(state, now);
    addTokenResponse(state, { tabId: 1, url: TOKEN, request: "grant_type=authorization_code", status: 200, body, now: now + 10 });
    const net = toEntry({ url: TOKEN, method: "POST", formData: { grant_type: ["authorization_code"], client_id: [APP] }, time: now + 20 }, { status: 200, requestId: "0a1b2c3d-4e5f-4061-8728-394a5b6c7d8e" });
    addHop(state, { tabId: 1, entry: net, kind: classify(net), now: now + 20 });
    expect(state.flows[0].entries).toHaveLength(2);
    const tok = state.flows[0].entries[1];
    expect(tok.response.content?.text).toBe(body);
    expect(tok.response.headers?.find((h) => h.name === "x-ms-request-id")).toBeTruthy();
  });

  test("ignore anything that isn't an identity provider's token endpoint", () => {
    expect(addTokenResponse({ flows: [] }, { tabId: 1, url: "https://evil.example.com/token", request: "", status: 200, body: "{}", now: Date.now() })).toBeNull();
  });
});

test("the sign-in popup hands its code to the Flow tracer page and doesn't render the app", async () => {
  const { consumeLogsPopup } = await import("../src/lib/entraLogs");
  localStorage.setItem("f360:signinlogs:pending", JSON.stringify({ state: "st1" }));
  history.replaceState(null, "", "/?code=c0de&state=st1");
  vi.spyOn(window, "close").mockImplementation(() => {});
  expect(consumeLogsPopup()).toBe(true);
  expect(JSON.parse(localStorage.getItem("f360:signinlogs:result")!)).toMatchObject({ state: "st1", code: "c0de" });
  expect(location.search).toBe("");
  history.replaceState(null, "", "/?code=x&state=someone-else");
  expect(consumeLogsPopup()).toBe(false);
});

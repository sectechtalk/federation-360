// Federation 360 Capture extension: which requests it keeps, how it groups them, and that Flow tracer decodes the
// result exactly as it decodes a saved HAR file.
import { readFileSync } from "node:fs";
import { addHop, classify, FLOW_GAP_MS, IDP_HOSTS, mightMatter, toEntry, type CaptureState, type CapturedRequest } from "../extension/capture-core.js";
import { IDP_HOSTS as HAR_IDP_HOSTS, parseHar, type HarEntry } from "../src/lib/har";
import { flowToCapture } from "../src/lib/browserCapture";
import { analyzeCapture } from "../src/lib/flow";
import { HAR_SAMPLES } from "../src/data/harSamples";

/** What webRequest hands the extension for a HAR entry: decoded form fields, no cookies, no response body. */
function asWebRequest(e: HarEntry): { req: CapturedRequest; res: { status: number; redirectUrl?: string } } {
  const pd = e.request.postData;
  let formData: Record<string, string[]> | undefined;
  if (pd?.params) {
    formData = {};
    for (const p of pd.params) (formData[decodeURIComponent(p.name)] ??= []).push(decodeURIComponent((p.value ?? "").replace(/\+/g, "%20")));
  } else if (pd?.text) {
    formData = {};
    for (const [k, v] of new URLSearchParams(pd.text)) (formData[k] ??= []).push(v);
  }
  const loc = e.response.redirectURL || e.response.headers?.find((h) => h.name.toLowerCase() === "location")?.value;
  const auth = e.request.headers?.find((h) => h.name.toLowerCase() === "authorization")?.value;
  return { req: { url: e.request.url, method: e.request.method, formData, authorization: auth, time: Date.parse(e.startedDateTime ?? "") }, res: { status: e.response.status, redirectUrl: loc } };
}

function record(entries: HarEntry[], tabId = 7, state: CaptureState = { flows: [] }, now = Date.now()) {
  for (const e of entries) {
    const { req, res } = asWebRequest(e);
    if (!mightMatter(req.url, req.method, req.formData) && !req.authorization) continue;
    const entry = toEntry(req, res);
    addHop(state, { tabId, entry, kind: classify(entry), now });
  }
  return state;
}

const sample = async (id: string) => (await HAR_SAMPLES.find((s) => s.id === id)!.build()).log.entries as HarEntry[];

test("identity provider list matches Flow tracer's", () => {
  expect(IDP_HOSTS.map(String)).toEqual(HAR_IDP_HOSTS.map(String));
});

test("a recorded SAML sign-in decodes to the same hops as the saved HAR", async () => {
  for (const id of HAR_SAMPLES.map((s) => s.id)) {
    const entries = await sample(id);
    const state = record(entries);
    const fromHar = parseHar(JSON.stringify({ log: { entries } }));
    if (!fromHar.steps.length) continue;
    expect(state.flows).toHaveLength(1);
    const live = flowToCapture({ ...state.flows[0], tabTitle: "expenses.contoso.example" });
    expect(live.source).toBe("extension");
    expect(live.kind).toBe(fromHar.kind);
    expect(live.steps.map((s) => s.label)).toEqual(fromHar.steps.filter((s) => s.label !== "The identity provider shows an error page").map((s) => s.label));
    expect(live.steps.map((s) => s.saml?.value)).toEqual(fromHar.steps.filter((s) => s.label !== "The identity provider shows an error page").map((s) => s.saml?.value));
  }
});

test("the decoded live flow gets the same findings", async () => {
  const live = flowToCapture({ ...record(await sample("saml-ok")).flows[0] });
  const a = await analyzeCapture(live);
  expect(a.steps.some((s) => s.saml)).toBe(true);
  expect([...a.overall, ...a.steps.flatMap((s) => s.findings)].filter((f) => f.severity === "critical")).toEqual([]);
});

test("ordinary browsing is dropped", () => {
  const state = record([
    { request: { method: "GET", url: "https://news.example.com/" }, response: { status: 200 } },
    { request: { method: "POST", url: "https://shop.example.com/cart", postData: { text: "item=1&qty=2" } }, response: { status: 302, redirectURL: "/cart" } },
    { request: { method: "GET", url: "https://api.example.com/me", headers: [{ name: "Authorization", value: "Bearer eyJhbGciOi.x.y" }] }, response: { status: 200 } },
  ] as HarEntry[]);
  expect(state.flows).toEqual([]);
});

test("an API call with a token joins the tab's sign-in, and a pause starts a new flow", () => {
  const authorize: HarEntry = { request: { method: "GET", url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc&scope=openid&response_type=code" }, response: { status: 200 } };
  const api: HarEntry = { request: { method: "GET", url: "https://api.example.com/me", headers: [{ name: "Authorization", value: "Bearer eyJhbGciOi.x.y" }] }, response: { status: 200 } };
  const t = Date.now();
  const state = record([authorize, api], 3, { flows: [] }, t);
  expect(state.flows[0].entries).toHaveLength(2);
  record([api], 4, state, t); // another tab with no sign-in: dropped
  expect(state.flows).toHaveLength(1);
  record([authorize], 3, state, t + FLOW_GAP_MS + 1);
  expect(state.flows).toHaveLength(2);
});

test("an AADSTS error read from the sign-in page becomes an error hop", () => {
  const entry = toEntry({ url: "https://login.microsoftonline.com/common/saml2", method: "GET" }, { status: 200, bodyText: "AADSTS50011: The redirect URI specified in the request does not match." });
  const state: CaptureState = { flows: [] };
  addHop(state, { tabId: 1, entry, kind: classify(entry), now: Date.now() });
  const c = flowToCapture(state.flows[0]);
  expect(c.steps[0].error?.code).toBe("AADSTS50011");
});

test("the extension sends nothing over the network", () => {
  const manifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
  expect(manifest.manifest_version).toBe(3);
  for (const f of ["background.js", "bridge.js", "idp-page.js", "capture-core.js", "relay.js"]) {
    expect(readFileSync(`extension/${f}`, "utf8")).not.toMatch(/\bfetch\(|XMLHttpRequest|sendBeacon|WebSocket/);
  }
});

test("back-to-back sign-ins in one tab are listed separately", async () => {
  const t = Date.now();
  const state = record(await sample("saml-ok"), 9, { flows: [] }, t);
  record(await sample("saml-ok"), 9, state, t + 1000);
  expect(state.flows).toHaveLength(2);
  const silent: HarEntry = { request: { method: "GET", url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc&scope=openid&response_type=code" }, response: { status: 302, redirectURL: "http://localhost:5180/cb?code=x&state=y" } };
  record([silent], 9, state, t + 2000);
  expect(state.flows).toHaveLength(3);
  expect(flowToCapture(state.flows[0]).steps.map((s) => s.from + ">" + s.to)).toEqual(["app>idp", "idp>app"]);
});

// ---- What the extension may hold, and who it hands it to -----------------------------------------------------------

import { addTokenResponse, F360_ORIGINS, F360_SITE, isF360Page, PRESENT, REPLY_FIELDS, safeForm, safeFormText, safeRequestUrl, safeTokenReply, scrubEntry, scrubState, SECRET_FIELDS, SHOWN_FIELDS } from "../extension/capture-core.js";
import { KEEP, SECRET } from "../src/lib/har";
import { extensionOutOfDate, MIN_EXTENSION } from "../src/lib/browserCapture";

const LOGIN = "https://login.microsoftonline.com";
const TENANT = "8f2b6c1e-0d4a-4a7e-9a51-3c0d2e7b9f10";
const held = (x: unknown) => JSON.stringify(x);

describe("only the sign-in protocol's own fields are held", () => {
  test("the lists match what Flow tracer shows", () => {
    expect(SHOWN_FIELDS).toEqual(KEEP);
    expect(SECRET_FIELDS).toEqual(SECRET);
  });

  test("a password posted to the identity provider is never held, even when that hop sends the user back to the app", () => {
    const url = `${LOGIN}/common/login?ctx=CTX-in-query&sessionid=SESSION-in-query`;
    const raw = { login: ["lab.user1@contoso.example"], loginfmt: ["lab.user1@contoso.example"], passwd: ["Sup3rSecret"], Password: ["Sup3rSecret"], flowToken: ["FLOWTOKEN"], canary: ["CANARY"], ctx: ["CTX"], otc: ["123456"] };
    // What the request listener remembers while the request is in flight.
    expect(safeForm(url, raw)).toEqual({});
    expect(safeRequestUrl(url)).toBe(`${LOGIN}/common/login`);
    // And the finished hop, even if a caller hands toEntry the raw request.
    const entry = toEntry({ url, method: "POST", formData: raw, time: Date.now() }, { status: 302, redirectUrl: "https://app.contoso.example/cb?code=0.AAA&state=s1" });
    expect(classify(entry)).toBe("signin");
    const state: CaptureState = { flows: [] };
    addHop(state, { tabId: 1, entry, kind: classify(entry), now: Date.now() });
    for (const secret of ["Sup3rSecret", "FLOWTOKEN", "CANARY", "CTX", "123456", "SESSION-in-query", "lab.user1"]) expect(held(state)).not.toContain(secret);
    // The part Flow tracer shows is still there: the hop back to the app with its code.
    const c = flowToCapture(state.flows[0]);
    expect(c.steps.map((s) => s.label)).toEqual(["The identity provider sends the user back to the app with a code"]);
    expect(c.steps[0].tokens).toEqual([{ name: "code", value: "0.AAA" }]);
  });

  test("a password posted to a sign-in page that isn't on the list of identity providers is not held either", () => {
    // AD FS and others post the user name and password to the address that carries the SAML request.
    const url = "https://adfs.contoso.example/adfs/ls/?SAMLRequest=fZJNT8MwDIb&RelayState=%2Fhome";
    const entry = toEntry({ url, method: "POST", formData: { UserName: ["CONTOSO\\lab.user1"], Password: ["Sup3rSecret"], password: ["Sup3rSecret"], AuthMethod: ["FormsAuthentication"] }, time: Date.now() }, { status: 200 });
    expect(classify(entry)).toBe("signin");
    expect(held(entry)).not.toContain("Sup3rSecret");
    expect(held(entry)).not.toContain("lab.user1");
    expect(new URLSearchParams(entry.request.postData!.text).get("password")).toBe(PRESENT);
    expect(entry.request.url).toBe(url); // the SAML request itself is the sign-in, so it stays
  });

  test("a token request keeps what Flow tracer shows and only notes that the secrets were sent", () => {
    const url = `${LOGIN}/${TENANT}/oauth2/v2.0/token`;
    const form = "client_id=abc&grant_type=refresh_token&refresh_token=REFRESH-SECRET&scope=openid&client_secret=CLIENT-SECRET&code=THE-CODE&code_verifier=VERIFIER&client_assertion=ASSERTION&assertion=OBO-TOKEN&username=lab.user1&password=ROPC-PW&device_code=DEVICE";
    for (const entry of [
      toEntry({ url, method: "POST", formText: form, time: Date.now() }, { status: 200 }),
      toEntry({ url, method: "POST", formData: Object.fromEntries([...new URLSearchParams(form)].map(([k, v]) => [k, [v]])), time: Date.now() }, { status: 200 }),
    ]) {
      for (const secret of ["REFRESH-SECRET", "CLIENT-SECRET", "THE-CODE", "VERIFIER", "ASSERTION", "OBO-TOKEN", "lab.user1", "ROPC-PW", "DEVICE"]) expect(held(entry)).not.toContain(secret);
      const c = flowToCapture({ id: "t", startedAt: new Date().toISOString(), updatedAt: Date.now(), entries: [entry] });
      expect(c.steps[0].label).toBe("Tokens are refreshed");
      expect(c.steps[0].params).toMatchObject({ client_id: "abc", grant_type: "refresh_token", scope: "openid", refresh_token: PRESENT, client_secret: PRESENT, code_verifier: PRESENT, client_assertion: PRESENT, password: PRESENT });
    }
    // A secret a careless client put in the address is noted, not held.
    expect(safeRequestUrl(`${url}?p=B2C_1_susi&client_secret=CLIENT-SECRET&junk=1`)).toBe(`${url}?p=B2C_1_susi&client_secret=%28present%29`);
    expect(safeRequestUrl(`${url}?p=B2C_1_susi`)).toBe(`${url}?p=B2C_1_susi`);
  });

  test("a token reply is cut down to the tokens and the error; the refresh token's value is never held", () => {
    const reply = safeTokenReply(JSON.stringify({ token_type: "Bearer", expires_in: 3600, access_token: "eyJ.a.b", id_token: "eyJ.c.d", refresh_token: "REFRESH-SECRET", client_info: "CLIENT-INFO", foci: "1", device_secret: "DEVICE-SECRET" }));
    expect(JSON.parse(reply)).toEqual({ token_type: "Bearer", expires_in: 3600, access_token: "eyJ.a.b", id_token: "eyJ.c.d", refresh_token: "(issued)" });
    const everyField = JSON.stringify(Object.fromEntries(REPLY_FIELDS.map((k) => [k, "x"])));
    expect(Object.keys(JSON.parse(safeTokenReply(everyField)))).toEqual(REPLY_FIELDS);
    expect(safeTokenReply("<html>proxy error</html>")).toBe("");
    expect(safeTokenReply("[1]")).toBe("");
    // The same rule when the reply arrives from the page, whichever copy arrives first.
    const url = `${LOGIN}/${TENANT}/oauth2/v2.0/token`;
    const body = JSON.stringify({ access_token: "eyJ.a.b", refresh_token: "REFRESH-SECRET", client_info: "CLIENT-INFO" });
    const now = Date.now();
    const first: CaptureState = { flows: [] };
    addTokenResponse(first, { tabId: 1, url, request: "grant_type=authorization_code&code=THE-CODE&code_verifier=VERIFIER", status: 200, body, now });
    const net = toEntry({ url, method: "POST", formData: { grant_type: ["authorization_code"], code: ["THE-CODE"], code_verifier: ["VERIFIER"] }, time: now }, { status: 200 });
    addHop(first, { tabId: 1, entry: net, kind: classify(net), now: now + 5 });
    const second: CaptureState = { flows: [] };
    addHop(second, { tabId: 1, entry: toEntry({ url, method: "POST", formData: { grant_type: ["authorization_code"], code: ["THE-CODE"], code_verifier: ["VERIFIER"] }, time: now }, { status: 200 }), kind: "signin", now });
    addTokenResponse(second, { tabId: 1, url, request: "grant_type=authorization_code&code=THE-CODE&code_verifier=VERIFIER", status: 200, body, now: now + 5 });
    for (const state of [first, second]) {
      expect(state.flows[0].entries).toHaveLength(1);
      for (const secret of ["REFRESH-SECRET", "CLIENT-INFO", "THE-CODE", "VERIFIER"]) expect(held(state)).not.toContain(secret);
      expect(flowToCapture(state.flows[0]).steps[0].tokens).toEqual([{ name: "access_token", value: "eyJ.a.b" }]);
      expect(flowToCapture(state.flows[0]).steps[0].params).toMatchObject({ refresh_token: "(issued)", code_verifier: PRESENT });
    }
  });

  test("what a sign-in brings back to the app is kept: SAML response, code and tokens", () => {
    const acs = toEntry({ url: "https://app.contoso.example/saml/acs", method: "POST", formData: { SAMLResponse: ["PHNhbWw+"], RelayState: ["/home"], csrf: ["CSRF-TOKEN"] }, time: Date.now() }, { status: 302, redirectUrl: "/home" });
    expect(new URLSearchParams(acs.request.postData!.text).get("SAMLResponse")).toBe("PHNhbWw+");
    expect(held(acs)).not.toContain("CSRF-TOKEN");
    const formPost = toEntry({ url: "https://app.contoso.example/signin-oidc", method: "POST", formData: { code: ["0.AAA"], id_token: ["eyJ.a.b"], state: ["s1"], session_state: ["ss"], __RequestVerificationToken: ["CSRF-TOKEN"] }, time: Date.now() }, { status: 302, redirectUrl: "/" });
    expect(classify(formPost)).toBe("signin");
    expect(Object.fromEntries(new URLSearchParams(formPost.request.postData!.text))).toEqual({ code: "0.AAA", id_token: "eyJ.a.b", state: "s1", session_state: "ss" });
    // A SAML response posted on to the identity provider (a federated domain) is also the sign-in itself.
    const federated = toEntry({ url: `${LOGIN}/login.srf?client-request-id=1`, method: "POST", formData: { SAMLResponse: ["PHNhbWw+"], id_token: ["eyJ.upstream"] }, time: Date.now() }, { status: 200 });
    expect(Object.fromEntries(new URLSearchParams(federated.request.postData!.text))).toEqual({ SAMLResponse: "PHNhbWw+" });
  });

  test("an identity provider address keeps its query only when it is the sign-in request", () => {
    const authorize = `${LOGIN}/${TENANT}/oauth2/v2.0/authorize?client_id=abc&scope=openid&code_challenge=cc&login_hint=lab.user1%40contoso.example`;
    expect(safeRequestUrl(authorize)).toBe(authorize);
    const saml = `${LOGIN}/${TENANT}/saml2?SAMLRequest=fZJ&RelayState=x&SigAlg=y&Signature=z`;
    expect(safeRequestUrl(saml)).toBe(saml);
    expect(safeRequestUrl(`${LOGIN}/common/reprocess?ctx=CTX&sessionid=SESSION&flowtoken=FLOW#frag`)).toBe(`${LOGIN}/common/reprocess`);
    expect(safeRequestUrl(`${LOGIN}/login.srf`, true)).toBe(`${LOGIN}/login.srf`);
    // The app's own addresses are not the extension's to cut.
    expect(safeRequestUrl("https://api.contoso.example/items?$filter=x")).toBe("https://api.contoso.example/items?$filter=x");
    // A hop that sends the browser on to another identity provider page keeps the path of that page only.
    const hop = toEntry({ url: authorize, method: "GET", time: Date.now() }, { status: 302, redirectUrl: `${LOGIN}/common/reprocess?ctx=CTX&sessionid=SESSION` });
    expect(hop.response.redirectURL).toBe(`${LOGIN}/common/reprocess`);
    expect(held(hop)).not.toContain("SESSION");
  });

  test("an API call's posted form is not held", () => {
    const api = toEntry({ url: "https://api.contoso.example/profile", method: "POST", formData: { ssn: ["123-45-6789"], note: ["hello"] }, authorization: "Bearer eyJhbGciOi.x.y", time: Date.now() }, { status: 200 });
    expect(classify(api)).toBe("api");
    expect(held(api)).not.toContain("123-45-6789");
    // A post with none of the protocol's fields is not even remembered while it is in flight.
    expect(mightMatter("https://shop.example.com/checkout", "POST", { card: ["4111111111111111"], state: [] as string[] } as Record<string, string[]>)).toBe(true); // "state" is a protocol field name
    expect(mightMatter("https://shop.example.com/checkout", "POST", { card: ["4111111111111111"], cvv: ["123"] })).toBe(false);
    expect(safeForm("https://shop.example.com/checkout", { card: ["4111111111111111"], state: ["CA"] })).toEqual({ state: ["CA"] });
  });

  test("scrubbing is safe to run twice, and cleans up what an older version left in memory", () => {
    const old = {
      flows: [{
        id: "b-1", tabId: 1, tabTitle: "app", startedAt: new Date().toISOString(), updatedAt: Date.now(),
        entries: [
          { startedDateTime: new Date().toISOString(), request: { method: "POST", url: `${LOGIN}/common/login?ctx=CTX`, headers: [{ name: "Cookie", value: "ESTSAUTH=COOKIE" }], postData: { mimeType: "application/x-www-form-urlencoded", text: "login=lab.user1&passwd=Sup3rSecret&flowToken=FLOW" } }, response: { status: 302, redirectURL: "https://app.contoso.example/cb?code=0.AAA&state=s1", headers: [{ name: "Location", value: "https://app.contoso.example/cb?code=0.AAA&state=s1" }, { name: "Set-Cookie", value: "ESTSAUTH=COOKIE" }] } },
          { startedDateTime: new Date().toISOString(), request: { method: "POST", url: `${LOGIN}/${TENANT}/oauth2/v2.0/token`, headers: [], postData: { text: "grant_type=refresh_token&refresh_token=REFRESH-SECRET&client_id=abc" } }, response: { status: 200, headers: [{ name: "x-ms-request-id", value: "0a1b2c3d-4e5f-4061-8728-394a5b6c7d8e" }], content: { mimeType: "application/json", text: JSON.stringify({ access_token: "eyJ.a.b", refresh_token: "(issued)" }) } }, _fromPage: true, _paired: true },
        ],
      }],
    };
    const once = scrubState(old);
    for (const secret of ["Sup3rSecret", "FLOW", "CTX", "COOKIE", "REFRESH-SECRET", "lab.user1"]) expect(held(once)).not.toContain(secret);
    expect(scrubState(once)).toEqual(once);
    expect(once.flows[0].entries.map((e) => scrubEntry(e))).toEqual(once.flows[0].entries);
    // What Flow tracer shows from those hops is unchanged.
    const before = flowToCapture({ ...old.flows[0], id: "x1" } as never).steps.map((s) => [s.label, s.tokens, s.params]);
    const after = flowToCapture({ ...once.flows[0], id: "x2" }).steps.map((s) => [s.label, s.tokens, s.params]);
    expect(after).toEqual(before);
    expect(scrubState(null)).toEqual({ flows: [] });
    expect(scrubState({ flows: [null, { entries: "x" }] })).toEqual({ flows: [] });
  });

  test("the bundled examples decode exactly the same after scrubbing", async () => {
    for (const s of HAR_SAMPLES) {
      const state = record((await s.build()).log.entries as HarEntry[]);
      for (const f of state.flows) {
        const again = scrubState({ flows: [f] }).flows[0];
        expect(again.entries).toEqual(f.entries);
      }
    }
  });

  test("a form field named like an object's built-ins can't trip the scrubber", () => {
    expect(safeFormText(`${LOGIN}/common/login`, "__proto__=x&constructor=y&toString=z&state=s1")).toBe("state=s1");
    expect(safeForm(`${LOGIN}/common/login`, JSON.parse('{"__proto__":["x"],"constructor":["y"],"state":["s1"]}'))).toEqual({ state: ["s1"] });
  });
});

describe("sign-ins are handed only to Federation 360's own pages", () => {
  test("which pages count", () => {
    for (const ok of ["http://localhost:5173/", "http://localhost:5173/#flowtracer", "http://127.0.0.1:5173/?testapp=x#livetest", "http://localhost:8080/", "http://127.0.0.1:8080/#learn", `${F360_SITE}`, `${F360_SITE}#flowtracer`]) expect(isF360Page(ok)).toBe(true);
    for (const no of [
      "http://localhost/", "http://localhost:5174/", "http://localhost:3000/", "http://localhost:8360/", "http://127.0.0.1:5180/spa", "https://localhost:5173/",
      "http://localhost:5173.evil.example/", "http://evil.example/?http://localhost:5173/", "https://sectechtalk.github.io/", "https://sectechtalk.github.io/federation-360-evil/",
      "https://sectechtalk.github.io@evil.example/federation-360/", "https://evil.example/federation-360/", "chrome://extensions", "", undefined, null, 5,
    ]) expect(isF360Page(no as never)).toBe(false);
  });

  test("the manifest, the bridge and the background agree on that list", () => {
    const manifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
    const matches: string[] = manifest.content_scripts[0].matches;
    expect(manifest.content_scripts[0].js).toEqual(["bridge.js"]);
    expect(manifest.content_scripts[0].all_frames).toBeUndefined();
    expect(matches).toEqual([...F360_ORIGINS.map((o) => `${o}/*`), `${F360_SITE}*`]);
    for (const m of matches) expect(m).not.toMatch(/^https?:\/\/(localhost|127\.0\.0\.1)\//); // a pattern without a port would match every port
    const bridge = readFileSync("extension/bridge.js", "utf8");
    expect(JSON.parse(bridge.match(/const ORIGINS = (\[[^\]]*\]);/)![1])).toEqual(F360_ORIGINS);
    expect(bridge.match(/const SITE = "([^"]+)";/)![1]).toBe(F360_SITE);
    // The bridge posts nothing into the page until the page asks, and never calls the extension on its own.
    expect(bridge).toMatch(/let asked = false;/);
    expect(bridge.match(/\bask\(/g)).toHaveLength(1);
    const background = readFileSync("extension/background.js", "utf8");
    expect(background).not.toMatch(/tabs\.query\(\{\s*url:/);
    expect(background).toMatch(/isF360Page\(sender\.url\)/);
    expect(background).toMatch(/safeForm\(d\.url, d\.requestBody\?\.formData\)/);
    expect(background).not.toMatch(/formData: d\.requestBody/);
  });

  test("Flow tracer asks for at least the version that does this", () => {
    const manifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
    expect(extensionOutOfDate(manifest.version)).toBe(false);
    expect(extensionOutOfDate(MIN_EXTENSION)).toBe(false);
    expect(extensionOutOfDate("0.2.1")).toBe(true);
    expect(extensionOutOfDate("0.2.0")).toBe(true);
    expect(extensionOutOfDate("0.1.0")).toBe(true);
    expect(extensionOutOfDate("0.10.0")).toBe(false); // numbers, not text: "0.10.0" < "0.2.1" as text
    expect(extensionOutOfDate("1.0")).toBe(false);
    expect(extensionOutOfDate(undefined)).toBe(false); // not heard yet
  });
});

describe("a token reply read inside the page lands on the hop it belongs to", () => {
  const TOKEN = `${LOGIN}/${TENANT}/oauth2/v2.0/token`;
  const tok = (aud: string) => `eyJhbGciOiJSUzI1NiJ9.${Buffer.from(JSON.stringify({ aud })).toString("base64url")}.c2ln`;
  const reply = (aud: string) => JSON.stringify({ access_token: tok(aud), refresh_token: "r" });
  const call = (scope: string, t: number) => toEntry({ url: TOKEN, method: "POST", formData: { client_id: ["abc"], grant_type: ["refresh_token"], refresh_token: ["r"], scope: [scope] }, time: t }, { status: 200 });
  const req = (scope: string) => `client_id=abc&grant_type=refresh_token&refresh_token=r&scope=${encodeURIComponent(scope)}`;
  const shown = (state: CaptureState) => flowToCapture(state.flows[0]).steps.map((s) => `${s.params?.scope} -> ${s.tokens?.map((t) => JSON.parse(Buffer.from(t.value.split(".")[1], "base64url").toString()).aud).join(",")}`);
  const now = Date.now();
  const net = (state: CaptureState, scope: string, at: number) => { const e = call(scope, at); addHop(state, { tabId: 1, entry: e, kind: classify(e), now: at }); };
  const page = (state: CaptureState, scope: string | null, aud: string, at: number) => addTokenResponse(state, { tabId: 1, url: TOKEN, request: scope === null ? "" : req(scope), status: 200, body: reply(aud), now: at });

  test("two tokens fetched at once, whichever order the copies arrive in", () => {
    const want = ["api://a/.default -> api://a", "api://b/.default -> api://b"];
    // Both calls finish, then both replies are read.
    let s: CaptureState = { flows: [] };
    net(s, "api://a/.default", now); net(s, "api://b/.default", now + 1); page(s, "api://a/.default", "api://a", now + 2); page(s, "api://b/.default", "api://b", now + 3);
    expect(shown(s)).toEqual(want);
    // The replies are read in the other order.
    s = { flows: [] };
    net(s, "api://a/.default", now); net(s, "api://b/.default", now + 1); page(s, "api://b/.default", "api://b", now + 2); page(s, "api://a/.default", "api://a", now + 3);
    expect(shown(s)).toEqual(want);
    // A reply is read before its own call is seen on the network, while another call is still waiting for its reply.
    s = { flows: [] };
    net(s, "api://a/.default", now); page(s, "api://b/.default", "api://b", now + 1); net(s, "api://b/.default", now + 2); page(s, "api://a/.default", "api://a", now + 3);
    expect(shown(s)).toEqual(want);
    expect(s.flows[0].entries).toHaveLength(2);
    // Both replies are read before either call is seen on the network.
    s = { flows: [] };
    page(s, "api://b/.default", "api://b", now); page(s, "api://a/.default", "api://a", now + 1); net(s, "api://a/.default", now + 2); net(s, "api://b/.default", now + 3);
    expect(shown(s).sort()).toEqual(want);
    expect(s.flows[0].entries).toHaveLength(2);
  });

  test("identical calls are answered in order, and each reply is used once", () => {
    const s: CaptureState = { flows: [] };
    net(s, "openid", now); net(s, "openid", now + 1); page(s, "openid", "first", now + 2); page(s, "openid", "second", now + 3);
    expect(shown(s)).toEqual(["openid -> first", "openid -> second"]);
    page(s, "openid", "third", now + 4); // a third reply with no call waiting becomes its own hop
    expect(shown(s)).toEqual(["openid -> first", "openid -> second", "openid -> third"]);
  });

  test("when the page can't say what it sent, the oldest waiting call gets the reply", () => {
    const s: CaptureState = { flows: [] };
    net(s, "api://a/.default", now); net(s, "api://b/.default", now + 1); page(s, null, "api://a", now + 2); page(s, null, "api://b", now + 3);
    expect(shown(s)).toEqual(["api://a/.default -> api://a", "api://b/.default -> api://b"]);
  });

  test("when the browser doesn't hand over the posted form, the page's copy fills it in", () => {
    const s: CaptureState = { flows: [] };
    const bare = toEntry({ url: TOKEN, method: "POST", time: now }, { status: 200 });
    addHop(s, { tabId: 1, entry: bare, kind: classify(bare), now });
    page(s, "api://a/.default", "api://a", now + 1);
    expect(shown(s)).toEqual(["api://a/.default -> api://a"]);
    expect(held(s)).not.toContain("refresh_token=r");
  });

  test("a reply that arrives after its hop shows, even on the last hop", () => {
    const s: CaptureState = { flows: [] };
    net(s, "api://a/.default", now);
    // The page gets a fresh copy of the flow each time, as it does from the extension.
    const before = flowToCapture(JSON.parse(JSON.stringify(s.flows[0])));
    expect(before.steps[0].tokens).toEqual([]);
    expect(before.steps[0].note).toMatch(/couldn't be read/);
    page(s, "api://a/.default", "api://a", now + 1);
    const after = flowToCapture(JSON.parse(JSON.stringify(s.flows[0])));
    expect(after.steps[0].tokens?.map((t) => t.name)).toEqual(["access_token"]);
    expect(after.steps[0].note).toBeUndefined();
    // Nothing changed: the same object comes back, so the page doesn't analyze it again.
    expect(flowToCapture(JSON.parse(JSON.stringify(s.flows[0])))).toBe(after);
  });

  test("the request ID the network copy brings shows up, even when the page's copy arrived first", () => {
    const s: CaptureState = { flows: [] };
    page(s, "api://a/.default", "api://a", now);
    expect(flowToCapture(JSON.parse(JSON.stringify(s.flows[0]))).entra?.requestIds).toEqual([]);
    const e = toEntry({ url: TOKEN, method: "POST", formData: { client_id: ["abc"], grant_type: ["refresh_token"], refresh_token: ["r"], scope: ["api://a/.default"] }, time: now + 1 }, { status: 200, requestId: "0a1b2c3d-4e5f-4061-8728-394a5b6c7d8e" });
    addHop(s, { tabId: 1, entry: e, kind: classify(e), now: now + 1 });
    expect(s.flows[0].entries).toHaveLength(1);
    expect(flowToCapture(JSON.parse(JSON.stringify(s.flows[0]))).entra?.requestIds).toEqual(["0a1b2c3d-4e5f-4061-8728-394a5b6c7d8e"]);
  });
});

// ---- A sign-in the identity provider refuses, and which app a sign-in is for ----------------------------------------

import { addIdpError, appHost, phase } from "../extension/capture-core.js";

describe("a sign-in the identity provider refuses on an error page", () => {
  const ERR = "AADSTS50011: The reply URL 'https://expenses-old.contoso.example/saml/acs' specified in the request does not match the reply URLs configured for the application.";
  const RID = "0a1b2c3d-4e5f-4061-8728-394a5b6c7d8e";
  const CID = "9e8d7c6b-5a49-4382-a716-f5e4d3c2b1a0";
  const AUTHZ = `${LOGIN}/${TENANT}/oauth2/v2.0/authorize?client_id=abc&scope=openid&response_type=code&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb`;
  /** The network listener's copy of a page request: no body, because the browser doesn't hand one over. */
  const net = (state: CaptureState, url: string, at: number, requestId?: string) => {
    const e = toEntry({ url, method: "GET", time: at }, { status: 200, requestId });
    return addHop(state, { tabId: 5, entry: e, kind: classify(e), now: at });
  };
  /** What idp-page.js reads from the error page at that address. */
  const refused = (state: CaptureState, url: string, at: number, text = ERR) => addIdpError(state, { tabId: 5, url, text, requestId: RID, correlationId: CID, now: at });
  const shown = (f: CaptureState["flows"][number]) => flowToCapture(JSON.parse(JSON.stringify(f)));
  const badRequest = async () => (await sample("saml-50011"))[0].request.url;

  test("the error lands on the request it answers, exactly as in a saved recording", async () => {
    const saved = await sample("saml-50011");
    const fromHar = parseHar(JSON.stringify({ log: { entries: saved } }));
    const s: CaptureState = { flows: [] };
    const t = Date.now();
    net(s, saved[0].request.url, t);
    expect(s.flows[0].done).toBeFalsy();
    expect(refused(s, saved[0].request.url, t + 400)).toBe(s.flows[0]);
    expect(s.flows).toHaveLength(1);
    expect(s.flows[0].entries).toHaveLength(1); // one request, not the request twice
    expect(s.flows[0].done).toBe(true);
    const live = shown(s.flows[0]);
    expect(live.steps.map((x) => x.label)).toEqual(["The app sends a SAML request to the identity provider", "The identity provider shows an error page"]);
    expect(live.steps.map((x) => x.label)).toEqual(fromHar.steps.map((x) => x.label));
    expect(live.steps[1].error?.code).toBe("AADSTS50011");
    // The IDs on the error page find the sign-in in Entra's log.
    expect(live.entra).toMatchObject({ requestIds: [RID], correlationIds: [CID] });
  });

  test("each attempt in the same tab is a sign-in of its own, and a clean one is judged on its own request", async () => {
    const bad = await badRequest();
    const s: CaptureState = { flows: [] };
    const t = Date.now();
    net(s, bad, t);
    refused(s, bad, t + 300);
    // The same broken request again a few seconds later, then a sign-in that works.
    net(s, bad, t + 4000);
    refused(s, bad, t + 4300);
    record(await sample("saml-ok"), 5, s, t + 9000);
    expect(s.flows.map((f) => f.entries.length)).toEqual([2, 1, 1]);
    expect(s.flows.every((f) => f.done)).toBe(true);
    const clean = await analyzeCapture(shown(s.flows[0]));
    expect([...clean.overall, ...clean.steps.flatMap((x) => x.findings)].filter((f) => f.severity === "critical")).toEqual([]);
    const failed = await analyzeCapture(shown(s.flows[1]));
    expect(failed.steps.flatMap((x) => x.findings).filter((f) => f.severity === "critical").map((f) => f.title)).toEqual(["Entra stopped the sign-in with AADSTS50011"]);
  });

  test("the error can arrive before the network's copy of the page", async () => {
    const bad = await badRequest();
    const s: CaptureState = { flows: [] };
    const t = Date.now();
    refused(s, bad, t);
    expect(s.flows[0].done).toBe(true);
    net(s, bad, t + 50, "11111111-2222-4333-8444-555555555555");
    expect(s.flows).toHaveLength(1);
    expect(s.flows[0].entries).toHaveLength(1);
    expect(shown(s.flows[0]).steps.map((x) => x.label)).toEqual(["The app sends a SAML request to the identity provider", "The identity provider shows an error page"]);
    // A second request for the same page later is a new attempt, not another copy.
    net(s, bad, t + 5000);
    expect(s.flows).toHaveLength(2);
  });

  test("an error on a later page of the sign-in ends it too, and that page's query isn't held", async () => {
    const bad = await badRequest();
    const s: CaptureState = { flows: [] };
    const t = Date.now();
    net(s, bad, t);
    refused(s, `${LOGIN}/${TENANT}/login?ctx=CTX-secret&flowtoken=FLOW-secret`, t + 9000);
    expect(s.flows).toHaveLength(1);
    expect(s.flows[0].entries).toHaveLength(2);
    expect(s.flows[0].done).toBe(true);
    expect(held(s)).not.toMatch(/CTX-secret|FLOW-secret/);
    expect(shown(s.flows[0]).steps.map((x) => x.label)).toEqual(["The app sends a SAML request to the identity provider", "The identity provider shows an error page"]);
    net(s, bad, t + 12000);
    expect(s.flows).toHaveLength(2);
  });

  test("an OpenID Connect request refused on its own page", () => {
    const s: CaptureState = { flows: [] };
    const t = Date.now();
    net(s, AUTHZ, t);
    refused(s, AUTHZ, t + 200, "AADSTS50011: The redirect URI 'https://app.example.com/cb' specified in the request does not match.");
    expect(s.flows[0].entries).toHaveLength(1);
    const c = shown(s.flows[0]);
    expect(c.steps.map((x) => x.label)).toEqual(["The app sends the user to sign in (OpenID Connect authorize request)", "The identity provider shows an error page"]);
    net(s, AUTHZ, t + 5000);
    expect(s.flows).toHaveLength(2);
  });

  test("an error page ends the attempt whatever its address", async () => {
    const at = (url: string, text?: string) => phase(toEntry({ url, method: "GET" }, { status: 200, bodyText: text }));
    expect(at(await badRequest())).toBe("start");
    expect(at(await badRequest(), ERR)).toBe("whole");
    expect(at(AUTHZ)).toBe("start");
    expect(at(AUTHZ, ERR)).toBe("whole");
    expect(at(`${LOGIN}/${TENANT}/login`, ERR)).toBe("return");
    expect(at(`${LOGIN}/${TENANT}/login`)).toBeNull();
  });

  test("only an identity provider's own AADSTS page is taken, cut to a short text", () => {
    const s: CaptureState = { flows: [] };
    const t = Date.now();
    expect(addIdpError(s, { tabId: 5, url: "https://signin.example.net/error", text: ERR, now: t })).toBeNull();
    expect(addIdpError(s, { tabId: 5, url: `${LOGIN}/${TENANT}/login`, text: "Enter your password", now: t })).toBeNull();
    expect(s.flows).toEqual([]);
    addIdpError(s, { tabId: 5, url: `${LOGIN}/${TENANT}/login`, text: ERR + " " + "x".repeat(5000), now: t });
    expect(s.flows[0].entries[0].response.content?.text?.length).toBe(2000);
  });

  test("the background hands error pages to this", () => {
    const background = readFileSync("extension/background.js", "utf8");
    expect(background).toMatch(/addIdpError\(state, \{ tabId: sender\.tab\.id, url: sender\.url/);
    // The app's redirect to the identity provider is remembered without its query.
    expect(background).toMatch(/sentBy\.set\(d\.requestId, d\.url\.split\(\/\[\?#\]\/\)\[0\]\)/);
  });
});

describe("a sign-in is named after the app it is for", () => {
  const SAML = `${LOGIN}/${TENANT}/saml2?SAMLRequest=abc`;
  const authz = (redirect: string) => `${LOGIN}/${TENANT}/oauth2/v2.0/authorize?client_id=abc&scope=openid&redirect_uri=${encodeURIComponent(redirect)}`;

  test("from the hop itself when it says", () => {
    // The answer is delivered to the app.
    expect(appHost("https://expenses.contoso.example/saml/acs")).toBe("expenses.contoso.example");
    // An authorize request names where its answer goes.
    expect(appHost(authz("https://spa.contoso.example/cb"), "https://portal.contoso.example")).toBe("spa.contoso.example");
    // The identity provider sends the browser back to the app.
    expect(appHost(`${LOGIN}/${TENANT}/login`, undefined, "http://localhost:5180/cb?code=x")).toBe("localhost:5180");
  });

  test("otherwise from whoever sent the browser to the identity provider", () => {
    // The app's own redirect (the lab test app on port 5174), not the page the link was on.
    expect(appHost(SAML, "http://localhost:5174/saml/login")).toBe("localhost:5174");
    // A desktop app's redirect address is the identity provider's own: the page the request came from names it.
    expect(appHost(authz(`${LOGIN}/common/oauth2/nativeclient`), "https://portal.contoso.example")).toBe("portal.contoso.example");
  });

  test("never the identity provider, a browser page or something that isn't a web address", () => {
    expect(appHost(SAML)).toBe("");
    expect(appHost(SAML, LOGIN)).toBe("");
    expect(appHost(SAML, "null")).toBe("");
    expect(appHost(SAML, "chrome://newtab/")).toBe("");
    expect(appHost("chrome://newtab/")).toBe("");
    expect(appHost("edge://extensions/")).toBe("");
    expect(appHost(`${LOGIN}/${TENANT}/login`)).toBe("");
    expect(appHost(authz("msal11111111-2222-4333-8444-555555555555://auth"))).toBe("");
    expect(appHost("not an address")).toBe("");
    expect(appHost(`${LOGIN}/${TENANT}/login`, undefined, "http://[bad")).toBe("");
  });
});

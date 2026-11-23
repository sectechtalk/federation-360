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

test("the extension only runs on Federation 360's own pages and sends nothing over the network", () => {
  const manifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
  expect(manifest.manifest_version).toBe(3);
  expect(manifest.content_scripts[0].matches).toEqual(["http://localhost/*", "http://127.0.0.1/*", "https://sectechtalk.github.io/federation-360/*"]);
  for (const f of ["background.js", "bridge.js", "idp-page.js", "capture-core.js"]) {
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

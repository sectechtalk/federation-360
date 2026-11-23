// Federation 360 Capture: watches the browser's requests, keeps only sign-in hops and hands them to any open
// Federation 360 page. Hops live in chrome.storage.session: browser memory only, gone when the browser closes.
import { addHop, addTokenResponse, classify, mightMatter, openFlow, toEntry } from "./capture-core.js";

const FLOW_TRACER = "http://localhost:5173/#flowtracer";
const F360_PAGES = ["http://localhost/*", "http://127.0.0.1/*", "https://sectechtalk.github.io/federation-360/*"];

let state = { flows: [] };
const ready = chrome.storage.session.get("state").then((r) => {
  if (r.state?.flows) state = r.state;
});

const pending = new Map();

async function tabTitle(tabId) {
  if (tabId < 0) return "";
  try {
    const t = await chrome.tabs.get(tabId);
    return t.url ? new URL(t.url).host : t.title ?? "";
  } catch {
    return "";
  }
}

let saveTimer;
function changed() {
  chrome.action.setBadgeText({ text: state.flows.length ? String(state.flows.length) : "" });
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => chrome.storage.session.set({ state }), 200);
  broadcast();
}

async function broadcast() {
  const tabs = await chrome.tabs.query({ url: F360_PAGES });
  for (const t of tabs) chrome.tabs.sendMessage(t.id, { type: "flows", flows: state.flows }).catch(() => {});
}

async function record(tabId, entry) {
  await ready;
  const kind = classify(entry);
  if (!kind) return;
  const flow = addHop(state, { tabId, entry, kind, now: Date.now() });
  if (!flow) return;
  if (!flow.tabTitle) flow.tabTitle = await tabTitle(tabId);
  changed();
}

const ALL = { urls: ["<all_urls>"] };

chrome.webRequest.onBeforeRequest.addListener((d) => {
  const formData = d.requestBody?.formData;
  if (!mightMatter(d.url, d.method, formData)) return;
  pending.set(d.requestId, { url: d.url, method: d.method, formData, tabId: d.tabId, time: d.timeStamp });
}, ALL, ["requestBody"]);

const header = (hs, name) => hs?.find((h) => h.name.toLowerCase() === name)?.value;

chrome.webRequest.onSendHeaders.addListener(async (d) => {
  const auth = header(d.requestHeaders, "authorization");
  const crid = header(d.requestHeaders, "client-request-id");
  const p = pending.get(d.requestId);
  if (p) {
    if (auth && /^Bearer\s+ey/i.test(auth)) p.authorization = auth;
    if (crid) p.clientRequestId = crid;
    return;
  }
  if (!auth || !/^Bearer\s+ey/i.test(auth)) return;
  await ready;
  // An API call with a token is only interesting while that tab is signing in.
  if (openFlow(state, d.tabId, Date.now())) pending.set(d.requestId, { url: d.url, method: d.method, tabId: d.tabId, time: d.timeStamp, authorization: auth });
}, ALL, ["requestHeaders"]);

chrome.webRequest.onBeforeRedirect.addListener((d) => {
  const p = pending.get(d.requestId);
  if (!p) return;
  pending.delete(d.requestId); // the next hop of the redirect chain arrives as a new onBeforeRequest
  record(p.tabId, toEntry(p, { status: d.statusCode, redirectUrl: d.redirectUrl, requestId: header(d.responseHeaders, "x-ms-request-id") }));
}, ALL, ["responseHeaders"]);

chrome.webRequest.onCompleted.addListener((d) => {
  const p = pending.get(d.requestId);
  if (!p) return;
  pending.delete(d.requestId);
  record(p.tabId, toEntry(p, { status: d.statusCode, requestId: header(d.responseHeaders, "x-ms-request-id") }));
}, ALL, ["responseHeaders"]);

chrome.webRequest.onErrorOccurred.addListener((d) => pending.delete(d.requestId), ALL);

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    await ready;
    if (msg?.type === "hello") reply({ type: "flows", flows: state.flows, version: chrome.runtime.getManifest().version });
    else if (msg?.type === "clear") {
      state.flows = [];
      changed();
      reply({ type: "flows", flows: [] });
    } else if (msg?.type === "token-response" && sender.tab && typeof msg.url === "string" && typeof msg.body === "string") {
      // A token reply the page received (token-hook.js). addTokenResponse ignores anything that isn't an identity provider's token endpoint.
      const flow = addTokenResponse(state, { tabId: sender.tab.id, url: msg.url, request: String(msg.request ?? ""), status: Number(msg.status) || 0, body: msg.body.slice(0, 200000), now: Date.now() });
      if (flow) {
        if (!flow.tabTitle) flow.tabTitle = await tabTitle(sender.tab.id);
        changed();
      }
      reply({ ok: !!flow });
    } else if (msg?.type === "idp-error" && sender.tab) {
      // The identity provider's error page (AADSTS code), read by idp-page.js.
      const guid = (v) => (typeof v === "string" && /^[0-9a-f-]{36}$/i.test(v) ? v : undefined);
      await record(sender.tab.id, toEntry({ url: msg.url, method: "GET", time: Date.now(), clientRequestId: guid(msg.correlationId) }, { status: 200, bodyText: String(msg.text).slice(0, 2000), requestId: guid(msg.requestId) }));
      reply({ ok: true });
    }
  })();
  return true;
});

// Clicking the toolbar button opens Flow tracer, or switches to it if it's already open.
chrome.action.onClicked.addListener(async () => {
  const [t] = await chrome.tabs.query({ url: F360_PAGES });
  if (t) {
    await chrome.tabs.update(t.id, { active: true, url: t.url.replace(/#.*$/, "") + "#flowtracer" });
    await chrome.windows.update(t.windowId, { focused: true });
  } else await chrome.tabs.create({ url: FLOW_TRACER });
});

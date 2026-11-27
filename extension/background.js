// Federation 360 Capture: watches the browser's requests, keeps only sign-in hops and hands them to Federation 360's
// own pages when one asks. Hops live in chrome.storage.session: browser memory only, gone when the browser closes.
// What a hop may hold is decided in capture-core.js (safeForm, scrubEntry): a typed password is never remembered.
import { addHop, addIdpError, addTokenResponse, appHost, classify, isF360Page, isIdpHost, mightMatter, openFlow, safeForm, safeRequestUrl, scrubState, toEntry } from "./capture-core.js";

const FLOW_TRACER = "http://localhost:5173/#flowtracer";

let state = { flows: [] };
const ready = chrome.storage.session.get("state").then((r) => {
  // Anything an older version left in memory is cut down to what this version may hold.
  if (r.state?.flows) state = scrubState(r.state);
});

/** Open tabs showing Federation 360 itself. */
async function f360Tabs() {
  return (await chrome.tabs.query({})).filter((t) => isF360Page(t.url));
}

const pending = new Map();
/** For a request that reached the identity provider by a redirect: the address that sent it there, which is the app. */
const sentBy = new Map();

/** The site the tab is showing, when that can be the app: never the identity provider or a browser page. */
async function tabTitle(tabId) {
  if (tabId < 0) return "";
  try {
    return appHost((await chrome.tabs.get(tabId)).url ?? "");
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
  for (const t of await f360Tabs()) chrome.tabs.sendMessage(t.id, { type: "flows", flows: state.flows, version: chrome.runtime.getManifest().version }, { frameId: 0 }).catch(() => {});
}

/** from: the address that sent the browser to this hop (a redirect, or the page the request came from). */
async function record(tabId, entry, from) {
  await ready;
  const kind = classify(entry);
  if (!kind) return;
  const flow = addHop(state, { tabId, entry, kind, now: Date.now() });
  if (!flow) return;
  // A sign-in is named after the app it is for. The first hop that says which app that is names it.
  if (!flow.tabTitle) flow.tabTitle = (kind === "signin" && appHost(entry.request.url, from, entry.response.redirectURL)) || (await tabTitle(tabId));
  changed();
}

const ALL = { urls: ["<all_urls>"] };

chrome.webRequest.onBeforeRequest.addListener((d) => {
  // Only the sign-in protocol's own form fields are remembered. A typed password, a one-time code and every other
  // field are dropped right here, and so is the query of an identity provider page that isn't a sign-in request.
  const formData = safeForm(d.url, d.requestBody?.formData);
  if (!mightMatter(d.url, d.method, formData)) return;
  const samlInForm = !!formData && ("SAMLRequest" in formData || "SAMLResponse" in formData);
  pending.set(d.requestId, { url: safeRequestUrl(d.url, samlInForm), method: d.method, formData, tabId: d.tabId, time: d.timeStamp, from: sentBy.get(d.requestId) ?? d.initiator });
}, ALL, ["requestBody"]);

const header = (hs, name) => hs?.find((h) => h.name.toLowerCase() === name)?.value;
const hostOf = (url) => {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
};

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
  if (!p) {
    // An app's own redirect to the identity provider isn't kept, but it says which app the sign-in is for. Only the
    // app's address without its query is remembered, and only until this request ends.
    if (!isIdpHost(hostOf(d.url)) && mightMatter(d.redirectUrl, "GET")) sentBy.set(d.requestId, d.url.split(/[?#]/)[0]);
    return;
  }
  pending.delete(d.requestId); // the next hop of the redirect chain arrives as a new onBeforeRequest
  record(p.tabId, toEntry(p, { status: d.statusCode, redirectUrl: d.redirectUrl, requestId: header(d.responseHeaders, "x-ms-request-id") }), p.from);
}, ALL, ["responseHeaders"]);

chrome.webRequest.onCompleted.addListener((d) => {
  sentBy.delete(d.requestId);
  const p = pending.get(d.requestId);
  if (!p) return;
  pending.delete(d.requestId);
  record(p.tabId, toEntry(p, { status: d.statusCode, requestId: header(d.responseHeaders, "x-ms-request-id") }), p.from);
}, ALL, ["responseHeaders"]);

chrome.webRequest.onErrorOccurred.addListener((d) => {
  sentBy.delete(d.requestId);
  pending.delete(d.requestId);
}, ALL);

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    await ready;
    // Sign-ins go only to Federation 360's own pages (bridge.js, top frame), and only when the page asks.
    const fromF360 = sender.frameId === 0 && isF360Page(sender.url);
    if (msg?.type === "hello" || msg?.type === "clear") {
      if (!fromF360) return reply({ type: "refused" });
      if (msg.type === "clear") {
        state.flows = [];
        changed();
      }
      reply({ type: "flows", flows: state.flows, version: chrome.runtime.getManifest().version });
    } else if (msg?.type === "token-response" && sender.tab && typeof msg.url === "string" && typeof msg.body === "string") {
      // A token reply the page received (token-hook.js). addTokenResponse ignores anything that isn't an identity provider's token endpoint.
      const flow = addTokenResponse(state, { tabId: sender.tab.id, url: msg.url, request: String(msg.request ?? ""), status: Number(msg.status) || 0, body: msg.body.slice(0, 200000), now: Date.now() });
      if (flow) {
        if (!flow.tabTitle) flow.tabTitle = await tabTitle(sender.tab.id);
        changed();
      }
      reply({ ok: !!flow });
    } else if (msg?.type === "idp-error" && sender.tab && sender.frameId === 0 && isIdpHost(hostOf(sender.url))) {
      // The identity provider's error page (AADSTS code), read by idp-page.js on the provider's own sign-in page.
      // It goes onto the hop for that page's request and ends the tab's flow, so the next attempt is listed on its own.
      const guid = (v) => (typeof v === "string" && /^[0-9a-f-]{36}$/i.test(v) ? v : undefined);
      const flow = addIdpError(state, { tabId: sender.tab.id, url: sender.url, text: String(msg.text), requestId: guid(msg.requestId), correlationId: guid(msg.correlationId), now: Date.now() });
      if (flow) {
        if (!flow.tabTitle) flow.tabTitle = await tabTitle(sender.tab.id);
        changed();
      }
      reply({ ok: !!flow });
    }
  })();
  return true;
});

// Clicking the toolbar button opens Flow tracer, or switches to it if it's already open.
chrome.action.onClicked.addListener(async () => {
  const [t] = await f360Tabs();
  if (t) {
    await chrome.tabs.update(t.id, { active: true, url: t.url.replace(/#.*$/, "") + "#flowtracer" });
    await chrome.windows.update(t.windowId, { focused: true });
  } else await chrome.tabs.create({ url: FLOW_TRACER });
});

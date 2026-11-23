// Federation 360 Capture: the parts of the extension that don't touch the browser APIs, so tests can run them.
//
// It decides which requests are sign-in traffic and groups them into flows, one per tab. Everything else the browser
// does is ignored and never stored. Hops are kept as HAR entries, so Federation 360 decodes them with the same code it
// uses for a saved HAR file (src/lib/har.ts).

/** Identity provider hosts. Kept in step with IDP_HOSTS in src/lib/har.ts (tests/browser-capture.test.ts checks). */
export const IDP_HOSTS = [
  /(^|\.)login\.microsoftonline\.com$/i,
  /(^|\.)login\.microsoft\.com$/i,
  /(^|\.)login\.windows\.net$/i,
  /(^|\.)sts\.windows\.net$/i,
  /(^|\.)login\.live\.com$/i,
  /\.b2clogin\.com$/i,
  /\.ciamlogin\.com$/i,
  /\.okta(preview)?\.com$/i,
  /\.oktapreview\.com$/i,
  /\.auth0\.com$/i,
  /(^|\.)accounts\.google\.com$/i,
  /(^|\.)oauth2\.googleapis\.com$/i,
  /\.awsapps\.com$/i,
  /(^|\.)portal\.sso\.[a-z0-9-]+\.amazonaws\.com$/i,
];

/** A new flow starts when a tab has had no sign-in traffic for this long. */
export const FLOW_GAP_MS = 90 * 1000;
export const MAX_FLOWS = 25;
export const MAX_HOPS = 200;

export function isIdpHost(host) {
  return IDP_HOSTS.some((r) => r.test(host));
}

function safeUrl(u) {
  try {
    return new URL(u);
  } catch {
    return null;
  }
}

/** webRequest formData ({ name: [values] }) to a urlencoded string. */
export function formText(formData) {
  if (!formData) return undefined;
  const q = new URLSearchParams();
  for (const [k, vs] of Object.entries(formData)) for (const v of vs) q.append(k, String(v));
  return q.toString();
}

/**
 * One finished request as a HAR entry.
 * req: { url, method, formData?, authorization?, time } from webRequest; res: { status, redirectUrl?, bodyText? }.
 */
export function toEntry(req, res) {
  const headers = req.authorization ? [{ name: "Authorization", value: req.authorization }] : [];
  // Entra records client-request-id as the sign-in log's correlation ID, and x-ms-request-id as its request ID.
  if (req.clientRequestId) headers.push({ name: "client-request-id", value: req.clientRequestId });
  const resHeaders = res.redirectUrl ? [{ name: "Location", value: res.redirectUrl }] : [];
  if (res.requestId) resHeaders.push({ name: "x-ms-request-id", value: res.requestId });
  const text = req.formText ?? formText(req.formData);
  return {
    startedDateTime: new Date(Number.isFinite(req.time) ? req.time : Date.now()).toISOString(),
    request: {
      method: (req.method || "GET").toUpperCase(),
      url: req.url,
      headers,
      ...(text !== undefined ? { postData: { mimeType: "application/x-www-form-urlencoded", text } } : {}),
    },
    response: {
      status: res.status ?? 0,
      ...(res.redirectUrl ? { redirectURL: res.redirectUrl } : {}),
      headers: resHeaders,
      ...(res.bodyText ? { content: { mimeType: res.mimeType ?? "text/html", text: res.bodyText } } : {}),
    },
  };
}

/** Worth looking at before the request finishes? Keeps the extension from holding every request on every site. */
export function mightMatter(url, method, formData) {
  const u = safeUrl(url);
  if (!u) return false;
  if (isIdpHost(u.hostname)) return true;
  if (u.searchParams.has("SAMLRequest") || u.searchParams.has("SAMLResponse")) return true;
  return method === "POST" && !!formData;
}

/**
 * "signin": a hop of a sign-in (starts or continues a flow).
 * "api": a call with a bearer token (only kept when the tab is already in a flow).
 * null: not sign-in traffic; dropped.
 */
export function classify(entry) {
  const u = safeUrl(entry.request.url);
  if (!u) return null;
  const idp = isIdpHost(u.hostname);
  const form = new URLSearchParams(entry.request.postData?.text ?? "");
  const q = u.searchParams;
  const has = (k) => q.has(k) || form.has(k);
  if (has("SAMLRequest") || has("SAMLResponse")) return "signin";
  if (idp) {
    if (/\/authorize\/?$/i.test(u.pathname) && q.has("client_id")) return "signin";
    if (entry.request.method === "POST" && /\/token\/?$/i.test(u.pathname)) return "signin";
    if (/AADSTS\d{4,}/.test(entry.response.content?.text ?? "")) return "signin";
    const back = entry.response.redirectURL ? safeUrl(new URL(entry.response.redirectURL, u).href) : null;
    if (back && !isIdpHost(back.hostname)) {
      const frag = new URLSearchParams(back.hash.replace(/^#/, ""));
      if (["code", "id_token", "access_token", "error"].some((k) => back.searchParams.has(k) || frag.has(k))) return "signin";
    }
    return null;
  }
  if (entry.request.method === "POST" && form.has("state") && (form.has("code") || form.has("id_token") || form.has("error"))) return "signin";
  const auth = entry.request.headers?.find((h) => h.name.toLowerCase() === "authorization")?.value ?? "";
  if (/^Bearer\s+ey/i.test(auth)) return "api";
  return null;
}

/**
 * "start": the app sends the user to the identity provider (SAML request, authorize request).
 * "return": the user arrives back at the app with a SAML response, code, token or error, or sees an error page.
 * "silent": both at once (an authorize request answered straight away because the user is already signed in).
 * A start after a return in the same tab begins a new flow, so back-to-back sign-ins are listed separately.
 */
export function phase(entry) {
  const u = safeUrl(entry.request.url);
  if (!u) return null;
  const idp = isIdpHost(u.hostname);
  const form = new URLSearchParams(entry.request.postData?.text ?? "");
  if (u.searchParams.has("SAMLRequest") || form.has("SAMLRequest")) return "start";
  if (idp && /\/authorize\/?$/i.test(u.pathname) && u.searchParams.has("client_id")) {
    const back = entry.response.redirectURL ? safeUrl(new URL(entry.response.redirectURL, u).href) : null;
    return back && !isIdpHost(back.hostname) ? "silent" : "start"; // "silent": signed in already, sent straight back
  }
  if (idp && /AADSTS\d{4,}/.test(entry.response.content?.text ?? "")) return "return";
  if (!idp && (u.searchParams.has("SAMLResponse") || form.has("SAMLResponse"))) return "return";
  if (!idp && entry.request.method === "POST" && form.has("state") && (form.has("code") || form.has("id_token") || form.has("error"))) return "return";
  if (idp && entry.response.redirectURL) {
    const back = safeUrl(new URL(entry.response.redirectURL, u).href);
    if (back && !isIdpHost(back.hostname)) return "return";
  }
  return null;
}

/** The open flow for a tab, if it had sign-in traffic recently. */
export function openFlow(state, tabId, now) {
  return state.flows.find((f) => f.tabId === tabId && now - f.updatedAt < FLOW_GAP_MS) ?? null;
}

/** Adds a hop to the tab's open flow, or starts a new flow. Returns the flow it went to, or null if dropped. */
const isTokenCall = (e) => {
  const u = safeUrl(e.request.url);
  return !!u && e.request.method === "POST" && /\/token\/?$/i.test(u.pathname) && isIdpHost(u.hostname);
};
const sameEndpoint = (a, b) => a.split("?")[0].toLowerCase() === b.split("?")[0].toLowerCase();
/** How close in time a token reply read in the page and the same call seen on the network must be to pair. */
export const PAIR_MS = 15 * 1000;

/**
 * A token reply that token-hook.js read inside the page. It fills in the body of the token call the network
 * listener already recorded, or waits in the flow for that call to arrive.
 */
export function addTokenResponse(state, { tabId, tabTitle, url, request, status, body, now }) {
  const u = safeUrl(url);
  if (!u || !isIdpHost(u.hostname) || !/\/token\/?$/i.test(u.pathname)) return null;
  const flow = openFlow(state, tabId, now);
  const match = flow && [...flow.entries].reverse().find((e) => isTokenCall(e) && !e.response.content?.text && sameEndpoint(e.request.url, url) && now - Date.parse(e.startedDateTime) < PAIR_MS);
  if (match) {
    match.response.content = { mimeType: "application/json", text: body };
    if (!match.response.status) match.response.status = status;
    if (tabTitle) flow.tabTitle = flow.tabTitle || tabTitle;
    return flow;
  }
  const entry = toEntry({ url, method: "POST", formText: request, time: now }, { status, bodyText: body, mimeType: "application/json" });
  entry._fromPage = true;
  return addHop(state, { tabId, tabTitle, entry, kind: "signin", now });
}

export function addHop(state, { tabId, tabTitle, entry, kind, now }) {
  if (!kind) return null;
  // The network listener's copy of a token call whose reply the page already handed over: merge, don't repeat.
  if (isTokenCall(entry) && !entry._fromPage) {
    const open = openFlow(state, tabId, now);
    const early = open && open.entries.find((e) => e._fromPage && !e._paired && sameEndpoint(e.request.url, entry.request.url) && now - Date.parse(e.startedDateTime) < PAIR_MS);
    if (early) {
      early._paired = true;
      early.request = { ...entry.request, postData: entry.request.postData ?? early.request.postData };
      early.response = { ...entry.response, content: early.response.content };
      return open;
    }
  }
  const ph = phase(entry);
  let flow = openFlow(state, tabId, now);
  if (flow && flow.done && (ph === "start" || ph === "silent")) flow = null;
  if (!flow) {
    if (kind !== "signin") return null;
    flow = { id: `b-${now.toString(36)}-${Math.random().toString(36).slice(2, 7)}`, tabId, tabTitle: "", startedAt: new Date(now).toISOString(), updatedAt: now, entries: [] };
    state.flows.unshift(flow);
    state.flows.splice(MAX_FLOWS);
  }
  if (tabTitle) flow.tabTitle = tabTitle;
  if (flow.entries.length < MAX_HOPS) flow.entries.push(entry);
  if (kind === "signin") flow.updatedAt = now;
  if (ph === "return" || ph === "silent") flow.done = true;
  return flow;
}

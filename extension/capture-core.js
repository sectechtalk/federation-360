// Federation 360 Capture: the parts of the extension that don't touch the browser APIs, so tests can run them.
//
// It decides which requests are sign-in traffic and groups them into flows, one per tab. Everything else the browser
// does is ignored and never stored. Hops are kept as HAR entries, so Federation 360 decodes them with the same code it
// uses for a saved HAR file (src/lib/har.ts).
//
// What it may hold is an allow-list, not a block-list: from a posted form only the sign-in protocol's own fields, from
// an identity provider's address only what a SAML or authorize request carries, from a token reply only the tokens and
// the error. A typed password, a one-time code and the provider's session values are dropped before a request is even
// remembered (scrubEntry, safeForm). Tokens and codes are the point of the tool, so those are kept.

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

/**
 * Federation 360's own addresses: the only pages sign-ins are handed to, and only after the page asks.
 * bridge.js and manifest.json carry the same list (tests/browser-capture.test.ts checks).
 */
export const F360_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8080", "http://127.0.0.1:8080"];
export const F360_SITE = "https://sectechtalk.github.io/federation-360/";

/** Form fields Flow tracer shows. Kept in step with KEEP in src/lib/har.ts (tests check). */
export const SHOWN_FIELDS = ["client_id", "response_type", "response_mode", "scope", "redirect_uri", "state", "nonce", "prompt", "login_hint", "domain_hint", "code_challenge_method", "grant_type", "resource", "RelayState", "SigAlg", "error", "error_description", "error_uri", "session_state"];
/** Fields Flow tracer shows only as "(present)". Their values are never held. Kept in step with SECRET in src/lib/har.ts. */
export const SECRET_FIELDS = ["code_verifier", "client_secret", "client_assertion", "refresh_token", "password", "code_challenge"];
export const PRESENT = "(present)";
const SAML_FIELDS = ["SAMLRequest", "SAMLResponse"];
/** What a sign-in brings back. Held when posted to the app (form_post), never from a request to the identity provider. */
const RETURNED_FIELDS = ["code", "id_token", "access_token"];
/** Harmless routing values an identity provider's token address may carry. */
const TOKEN_QUERY = ["p", "client-request-id", "api-version"];
/** What is held from a token reply. The refresh token is noted as "(issued)" and its value is never held. */
export const REPLY_FIELDS = ["token_type", "scope", "expires_in", "ext_expires_in", "access_token", "id_token", "error", "error_description", "error_codes", "error_uri", "suberror", "timestamp", "trace_id", "correlation_id"];
const MAX_ERROR_TEXT = 2000;

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

/** Is this address one of Federation 360's own pages? */
export function isF360Page(url) {
  const u = typeof url === "string" ? safeUrl(url) : null;
  return !!u && (F360_ORIGINS.includes(u.origin) || u.href.startsWith(F360_SITE));
}

/** webRequest formData ({ name: [values] }) to a urlencoded string. */
export function formText(formData) {
  if (!formData) return undefined;
  const q = new URLSearchParams();
  for (const [k, vs] of Object.entries(formData)) for (const v of vs) q.append(k, String(v));
  return q.toString();
}

const isAuthorize = (u) => /\/authorize\/?$/i.test(u.pathname) && u.searchParams.has("client_id");
const isTokenPath = (u) => /\/token\/?$/i.test(u.pathname);

/** "keep", "present" (note that it was sent, drop the value) or null (drop). */
function fieldRule(name, toApp) {
  if (SECRET_FIELDS.includes(name)) return "present";
  if (SHOWN_FIELDS.includes(name) || SAML_FIELDS.includes(name) || (toApp && RETURNED_FIELDS.includes(name))) return "keep";
  return null;
}

/**
 * The only part of a posted form the extension ever holds: the sign-in protocol's own fields. Every other field (a
 * password typed into a sign-in page, a one-time code, session and anti-forgery values, anything else) is dropped.
 * Takes and returns webRequest formData ({ name: [values] }).
 */
export function safeForm(url, formData) {
  if (!formData) return undefined;
  const u = safeUrl(url);
  const toApp = !!u && !isIdpHost(u.hostname);
  const out = {};
  for (const k of Object.keys(formData)) {
    const rule = fieldRule(k, toApp);
    if (rule === "present") out[k] = [PRESENT];
    else if (rule === "keep") out[k] = [].concat(formData[k]).map(String);
  }
  return out;
}

/** safeForm for a urlencoded string. */
export function safeFormText(url, text) {
  if (text === undefined || text === null) return undefined;
  const u = safeUrl(url);
  const toApp = !!u && !isIdpHost(u.hostname);
  const q = new URLSearchParams();
  for (const [k, v] of new URLSearchParams(String(text))) {
    const rule = fieldRule(k, toApp);
    if (rule === "present") q.set(k, PRESENT);
    else if (rule === "keep") q.append(k, v);
  }
  return q.toString();
}

/**
 * The address the extension holds for a request. A SAML message or an authorize request is the sign-in itself, so
 * that address is kept whole. Any other identity provider address (the page a password is posted to, an MFA step, the
 * hop that sends the user back) keeps its path only: its query holds the provider's own session values, which Flow
 * tracer never shows. Addresses outside the identity provider (the app, an API) are kept as they are.
 * samlInForm: the posted form carries the SAML message.
 */
export function safeRequestUrl(url, samlInForm = false) {
  const u = safeUrl(url);
  if (!u || !isIdpHost(u.hostname)) return url;
  const whole = String(url).split("#")[0];
  if (samlInForm || SAML_FIELDS.some((k) => u.searchParams.has(k)) || isAuthorize(u)) return whole;
  if (!isTokenPath(u)) return u.origin + u.pathname;
  let changed = false;
  const q = new URLSearchParams();
  for (const [k, v] of u.searchParams) {
    if (SECRET_FIELDS.includes(k)) {
      q.set(k, PRESENT);
      changed = changed || v !== PRESENT;
    } else if (SHOWN_FIELDS.includes(k) || TOKEN_QUERY.includes(k)) q.append(k, v);
    else changed = true;
  }
  if (!changed) return whole;
  const qs = q.toString();
  return u.origin + u.pathname + (qs ? `?${qs}` : "");
}

/** Where a hop sends the browser next. Back to the app it is kept whole (that is the code, token or error); to the identity provider, as safeRequestUrl. */
function safeRedirectUrl(base, loc) {
  if (!loc) return loc;
  let target;
  try {
    target = new URL(loc, base);
  } catch {
    return undefined;
  }
  return isIdpHost(target.hostname) ? safeRequestUrl(target.href) : loc;
}

/** A token reply cut down to REPLY_FIELDS. A reply that isn't JSON is not held. */
export function safeTokenReply(body) {
  let j;
  try {
    j = JSON.parse(body);
  } catch {
    return "";
  }
  if (!j || typeof j !== "object" || Array.isArray(j)) return "";
  const out = {};
  for (const k of REPLY_FIELDS) if (Object.hasOwn(j, k)) out[k] = j[k];
  if (j.refresh_token) out.refresh_token = "(issued)";
  return JSON.stringify(out);
}

const headerValue = (hs, name) => hs?.find((h) => h?.name?.toLowerCase() === name)?.value;

/**
 * A hop cut down to what the extension may hold. toEntry runs every hop through it, and the extension runs it again
 * over anything an older version left in memory. Running it twice changes nothing.
 */
export function scrubEntry(entry) {
  const req = entry.request ?? {};
  const res = entry.response ?? {};
  const method = String(req.method || "GET").toUpperCase();
  const rawUrl = String(req.url ?? "");
  const text = req.postData?.text === undefined ? undefined : safeFormText(rawUrl, req.postData.text);
  const form = new URLSearchParams(text ?? "");
  const url = safeRequestUrl(rawUrl, SAML_FIELDS.some((k) => form.has(k)));
  const u = safeUrl(url);
  const tokenCall = !!u && method === "POST" && isIdpHost(u.hostname) && isTokenPath(u);

  const headers = [];
  const auth = headerValue(req.headers, "authorization");
  if (auth && /^Bearer\s+ey/i.test(auth)) headers.push({ name: "Authorization", value: auth });
  const crid = headerValue(req.headers, "client-request-id");
  if (crid) headers.push({ name: "client-request-id", value: String(crid).slice(0, 100) });

  const redirect = safeRedirectUrl(rawUrl, res.redirectURL || headerValue(res.headers, "location"));
  const resHeaders = redirect ? [{ name: "Location", value: redirect }] : [];
  const rid = headerValue(res.headers, "x-ms-request-id");
  if (rid) resHeaders.push({ name: "x-ms-request-id", value: String(rid).slice(0, 100) });

  const body = res.content?.text;
  const content = !body ? undefined : tokenCall ? safeTokenReply(body) : String(body).slice(0, MAX_ERROR_TEXT);

  const out = {
    startedDateTime: entry.startedDateTime,
    request: { method, url, headers, ...(text !== undefined ? { postData: { mimeType: "application/x-www-form-urlencoded", text } } : {}) },
    response: {
      status: Number(res.status) || 0,
      ...(redirect ? { redirectURL: redirect } : {}),
      headers: resHeaders,
      ...(content ? { content: { mimeType: tokenCall ? "application/json" : res.content?.mimeType ?? "text/html", text: content } } : {}),
    },
  };
  for (const flag of ["_fromPage", "_paired", "_replied"]) if (entry[flag]) out[flag] = true;
  return out;
}

/** scrubEntry over everything held. Run when the extension starts, in case an older version left something behind. */
export function scrubState(state) {
  const flows = Array.isArray(state?.flows) ? state.flows : [];
  return { flows: flows.filter((f) => f && Array.isArray(f.entries)).map((f) => ({ ...f, entries: f.entries.map(scrubEntry) })) };
}

/**
 * One finished request as a HAR entry, cut down to what the extension may hold (scrubEntry).
 * req: { url, method, formData?, authorization?, time } from webRequest; res: { status, redirectUrl?, bodyText? }.
 */
export function toEntry(req, res) {
  const headers = req.authorization ? [{ name: "Authorization", value: req.authorization }] : [];
  // Entra records client-request-id as the sign-in log's correlation ID, and x-ms-request-id as its request ID.
  if (req.clientRequestId) headers.push({ name: "client-request-id", value: req.clientRequestId });
  const resHeaders = res.redirectUrl ? [{ name: "Location", value: res.redirectUrl }] : [];
  if (res.requestId) resHeaders.push({ name: "x-ms-request-id", value: res.requestId });
  const text = req.formText ?? formText(req.formData);
  return scrubEntry({
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
  });
}

/**
 * Worth looking at before the request finishes? Keeps the extension from holding every request on every site.
 * formData is the form after safeForm: a post with none of the sign-in protocol's fields is not remembered at all.
 */
export function mightMatter(url, method, formData) {
  const u = safeUrl(url);
  if (!u) return false;
  if (isIdpHost(u.hostname)) return true;
  if (u.searchParams.has("SAMLRequest") || u.searchParams.has("SAMLResponse")) return true;
  return method === "POST" && !!formData && Object.keys(safeForm(url, formData)).length > 0;
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
 * "whole": both in one hop. An authorize request answered straight away because the user is already signed in, or a
 *          request the identity provider refused on an error page at that same address.
 * A start after a return in the same tab begins a new flow, so back-to-back sign-ins are listed separately.
 */
export function phase(entry) {
  const u = safeUrl(entry.request.url);
  if (!u) return null;
  const idp = isIdpHost(u.hostname);
  const form = new URLSearchParams(entry.request.postData?.text ?? "");
  const refused = idp && /AADSTS\d{4,}/.test(entry.response.content?.text ?? ""); // the provider's error page
  if (u.searchParams.has("SAMLRequest") || form.has("SAMLRequest")) return refused ? "whole" : "start";
  if (idp && /\/authorize\/?$/i.test(u.pathname) && u.searchParams.has("client_id")) {
    const back = entry.response.redirectURL ? safeUrl(new URL(entry.response.redirectURL, u).href) : null;
    return refused || (back && !isIdpHost(back.hostname)) ? "whole" : "start";
  }
  if (refused) return "return";
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

const isTokenCall = (e) => {
  const u = safeUrl(e.request.url);
  return !!u && e.request.method === "POST" && /\/token\/?$/i.test(u.pathname) && isIdpHost(u.hostname);
};
const sameEndpoint = (a, b) => a.split("?")[0].toLowerCase() === b.split("?")[0].toLowerCase();
/** How close in time a token reply read in the page and the same call seen on the network must be to pair. */
export const PAIR_MS = 15 * 1000;

/** A form's fields, each with its values in a fixed order. Empty when the form isn't known. */
function formFields(text) {
  const out = new Map();
  for (const [k, v] of new URLSearchParams(text ?? "")) out.set(k, [...(out.get(k) ?? []), v].sort());
  return out;
}
/** No field the two forms share has different values. */
const agree = (a, b) => [...a].every(([k, v]) => !b.has(k) || b.get(k).join("\n") === v.join("\n"));

/**
 * A token call reaches the extension twice: once from the network (no reply body) and once from the page (the reply).
 * This picks which waiting copy belongs with the one that just arrived. Two copies of one call carry the same form,
 * so an exact match is tried first, then the oldest waiting copy that doesn't contradict it (copies arrive in the
 * order the calls finished, and a form that isn't known contradicts nothing). A copy that names a different scope,
 * client or grant belongs to another call and is never used, so an app that fetches several tokens at once doesn't
 * get a reply shown on the wrong hop.
 */
function pairFor(waiting, form) {
  const mine = formFields(form);
  const theirs = waiting.map((e) => formFields(e.request.postData?.text));
  let i = theirs.findIndex((f) => f.size === mine.size && agree(f, mine));
  if (i < 0) i = theirs.findIndex((f) => agree(f, mine));
  return i < 0 ? null : waiting[i];
}

/**
 * A token reply that token-hook.js read inside the page. It fills in the body of the token call the network
 * listener already recorded, or waits in the flow for that call to arrive.
 */
export function addTokenResponse(state, { tabId, tabTitle, url, request, status, body, now }) {
  const u = safeUrl(url);
  if (!u || !isIdpHost(u.hostname) || !/\/token\/?$/i.test(u.pathname)) return null;
  const flow = openFlow(state, tabId, now);
  const form = safeFormText(url, request);
  const waiting = flow ? flow.entries.filter((e) => isTokenCall(e) && !e._replied && sameEndpoint(e.request.url, url) && now - Date.parse(e.startedDateTime) < PAIR_MS) : [];
  const match = pairFor(waiting, form);
  if (match) {
    match._replied = true;
    const text = safeTokenReply(body);
    if (text) match.response.content = { mimeType: "application/json", text };
    if (!match.response.status) match.response.status = status;
    // The browser doesn't always hand the extension the posted form; the page's copy fills it in.
    if (form && !match.request.postData?.text) match.request.postData = { mimeType: "application/x-www-form-urlencoded", text: form };
    if (tabTitle) flow.tabTitle = flow.tabTitle || tabTitle;
    return flow;
  }
  const entry = toEntry({ url, method: "POST", formText: request, time: now }, { status, bodyText: body, mimeType: "application/json" });
  entry._fromPage = true;
  entry._replied = true;
  return addHop(state, { tabId, tabTitle, entry, kind: "signin", now });
}

/** Adds a hop to the tab's open flow, or starts a new flow. Returns the flow it went to, or null if dropped. */
export function addHop(state, { tabId, tabTitle, entry, kind, now }) {
  if (!kind) return null;
  // The network listener's copy of a token call whose reply the page already handed over: merge, don't repeat.
  if (isTokenCall(entry) && !entry._fromPage) {
    const open = openFlow(state, tabId, now);
    const waiting = open ? open.entries.filter((e) => e._fromPage && !e._paired && sameEndpoint(e.request.url, entry.request.url) && now - Date.parse(e.startedDateTime) < PAIR_MS) : [];
    const early = pairFor(waiting, entry.request.postData?.text);
    if (early) {
      early._paired = true;
      early.request = { ...entry.request, postData: entry.request.postData?.text ? entry.request.postData : early.request.postData };
      early.response = { ...entry.response, content: early.response.content };
      return open;
    }
  }
  // The network listener's copy of a page whose error the page reader already handed over: merge, don't repeat.
  if (!entry._fromPage && !isTokenCall(entry)) {
    const open = openFlow(state, tabId, now);
    const early = open?.entries.find((e) => e._fromPage && !e._paired && !isTokenCall(e) && e.request.url === entry.request.url && now - Date.parse(e.startedDateTime) < PAIR_MS);
    if (early) {
      early._paired = true;
      early.request = { ...entry.request, headers: mergeHeaders(entry.request.headers, early.request.headers) };
      early.response = { ...early.response, status: entry.response.status || early.response.status, headers: mergeHeaders(entry.response.headers, early.response.headers) };
      return open;
    }
  }
  const ph = phase(entry);
  let flow = openFlow(state, tabId, now);
  if (flow && flow.done && (ph === "start" || ph === "whole")) flow = null;
  if (!flow) {
    if (kind !== "signin") return null;
    flow = { id: `b-${now.toString(36)}-${Math.random().toString(36).slice(2, 7)}`, tabId, tabTitle: "", startedAt: new Date(now).toISOString(), updatedAt: now, entries: [] };
    state.flows.unshift(flow);
    state.flows.splice(MAX_FLOWS);
  }
  if (tabTitle) flow.tabTitle = tabTitle;
  if (flow.entries.length < MAX_HOPS) flow.entries.push(entry);
  if (kind === "signin") flow.updatedAt = now;
  if (ph === "return" || ph === "whole") flow.done = true;
  return flow;
}

/** Two header lists as one: every header of the first, then any the second has that the first lacks. */
function mergeHeaders(first = [], second = []) {
  return [...first, ...second.filter((h) => !headerValue(first, String(h.name).toLowerCase()))];
}

/**
 * The identity provider's error page (an AADSTS code), read from the page by idp-page.js. The page's address is the
 * request the network listener has already recorded, so the error goes onto that hop instead of repeating it. An
 * error page ends the tab's flow either way: the next sign-in in that tab is listed on its own.
 */
export function addIdpError(state, { tabId, tabTitle, url, text, requestId, correlationId, now }) {
  const u = safeUrl(url);
  const body = String(text ?? "").slice(0, MAX_ERROR_TEXT);
  if (!u || !isIdpHost(u.hostname) || !/AADSTS\d{4,}/.test(body)) return null;
  const entry = toEntry({ url, method: "GET", time: now, clientRequestId: correlationId }, { status: 200, bodyText: body, requestId });
  entry._fromPage = true;
  const flow = openFlow(state, tabId, now);
  const seen = flow && !flow.done ? [...flow.entries].reverse().find((e) => !e._fromPage && e.request.url === entry.request.url && !e.response.content?.text && !e.response.redirectURL) : null;
  if (!seen) return addHop(state, { tabId, tabTitle, entry, kind: "signin", now });
  seen.response.content = entry.response.content;
  seen.response.headers = mergeHeaders(seen.response.headers, entry.response.headers);
  seen.request.headers = mergeHeaders(seen.request.headers, entry.request.headers);
  if (tabTitle && !flow.tabTitle) flow.tabTitle = tabTitle;
  flow.updatedAt = now;
  flow.done = true;
  return flow;
}

/**
 * The app a sign-in hop belongs to, as a host name, or "" when the hop doesn't say. In order: an answer delivered to
 * the app is at the app's own address; an authorize request names where its answer goes (redirect_uri); a hop that
 * sends the browser back from the identity provider names the app it goes back to (`redirect`); otherwise it is
 * whoever sent the browser to the identity provider (`from`: the address that redirected there, or the page the
 * request came from). Identity provider hosts and addresses that aren't web addresses never count as the app.
 */
export function appHost(url, from, redirect) {
  const web = (x) => (x && /^https?:$/.test(x.protocol) && !isIdpHost(x.hostname) ? x.host : "");
  const u = safeUrl(url);
  if (!u) return "";
  if (!isIdpHost(u.hostname)) return web(u);
  let back = null;
  try {
    back = redirect ? new URL(redirect, u) : null;
  } catch {
    back = null;
  }
  return (isAuthorize(u) && web(safeUrl(u.searchParams.get("redirect_uri") ?? ""))) || web(back) || web(safeUrl(from ?? ""));
}

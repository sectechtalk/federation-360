# Federation 360 Capture

A browser extension for Microsoft Edge and Google Chrome that sends every SAML, OpenID Connect and OAuth sign-in in
that browser to Federation 360's **Flow tracer** page as it happens. Nothing to record, save or upload.

## Load it (one time)

| | Microsoft Edge | Google Chrome |
| --- | --- | --- |
| 1. Open | `edge://extensions` | `chrome://extensions` |
| 2. Turn on | **Developer mode** (left side) | **Developer mode** (top right) |
| 3. Click | **Load unpacked**, choose this `extension` folder | **Load unpacked**, choose this `extension` folder |
| 4. Private windows | **Details** > **Allow in InPrivate** | **Details** > **Allow in Incognito** |

Then open Flow tracer (`http://localhost:5173/#flowtracer`, or click the extension's toolbar button). A green
**Capturing** label means it's connected. After a `git pull` that changes this folder, click the reload arrow on the
extension's card. Flow tracer says when it's out of date.

## What it keeps

| Kept | Not kept |
| --- | --- |
| SAML requests and responses, authorize and token calls, token replies a page fetches from an identity provider, redirects that bring a code or token back, AADSTS error pages and their request and correlation IDs, API calls with a token while that tab is signing in | Every other request, cookies, page content |
| From a posted form: only the sign-in protocol's own fields (`client_id`, `scope`, `redirect_uri`, `state`, `grant_type`, `RelayState`, the SAML message, and the code or tokens posted back to the app) | Every other form field: a password typed into a sign-in page, a one-time code, the identity provider's session and anti-forgery values |
| That `client_secret`, `client_assertion`, `code_verifier`, `password` or `refresh_token` was sent, shown as "(present)" or "(issued)" | Their values |
| The whole address of a SAML or authorize request, and of the app and its APIs | The query of any other identity provider page (the page a password is posted to, an MFA step) |

Each sign-in is named after the app it is for. That is a host name only: where the request's answer goes, or the site
that sent the browser to the identity provider.

The list of fields is an allow-list in `capture-core.js` (`safeForm`, `scrubEntry`): anything not on it is dropped
before the request is even remembered. The codes and tokens a sign-in brings back are kept, because decoding them is
the point. Treat a browser with the extension loaded like any place that holds live tokens.

Hops stay in browser memory (`chrome.storage.session`) and are gone when the browser closes or the extension is
reloaded. They are handed only to Federation 360's own pages, and only after the page asks:

- `http://localhost:5173` and `http://localhost:8080` (and the same ports on `127.0.0.1`)
- the published site

No other page receives anything, including other tools on `localhost`. If you serve Federation 360 on another port,
add it in three places and reload the extension: `F360_ORIGINS` in `capture-core.js`, `ORIGINS` in `bridge.js` and the
first `matches` list in `manifest.json`. The extension makes no network requests.

Browsers don't let extensions read response bodies from the network, so `token-hook.js` runs inside each page and reads
the page's own copy of a reply, only for POST requests to a known identity provider's `/token` endpoint. Tokens an
app's own server requests never pass through the browser; Flow tracer's Entra's verdict covers those sign-ins.

## Versions

| Version | What changed |
| --- | --- |
| 0.2.2 | A sign-in the identity provider refuses on an error page is listed as a sign-in of its own, with the error on the request it answers, so the next attempt in the same tab no longer runs into it. Each sign-in is named after the app it is for. |
| 0.2.1 | Holds only the sign-in protocol's own form fields; a typed password is never remembered. Hands sign-ins only to Federation 360's own addresses, and only when the page asks. Flow tracer asks you to reload an older version. |
| 0.2.0 | Token replies a page fetches in the background, and the IDs that find a sign-in in Entra's sign-in log. |
| 0.1.0 | First version: SAML, OpenID Connect and OAuth hops, live. |

## Files

| File | What it does |
| --- | --- |
| `capture-core.js` | Which requests count as sign-in traffic, what may be held from each, and grouping them into one flow per sign-in. Unit tested in `tests/browser-capture.test.ts`. |
| `background.js` | Listens to the browser's requests and keeps the flows. |
| `bridge.js` | Passes flows to the Federation 360 page, after the page asks. |
| `idp-page.js` | Reads the AADSTS error, request ID and correlation ID shown on a Microsoft sign-in page. |
| `token-hook.js` | Runs inside each page and passes on token replies from identity providers' token endpoints. |
| `relay.js` | Passes what `token-hook.js` saw to the extension. |

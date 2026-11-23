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
| SAML requests and responses, authorize and token calls, token replies a page fetches from an identity provider (refresh token replaced with "(issued)"), redirects that bring a code or token back, AADSTS error pages and their request and correlation IDs, API calls with a token while that tab is signing in | Every other request, cookies, page content |

Hops stay in browser memory (`chrome.storage.session`) and are gone when the browser closes. They go only to
Federation 360 pages on `localhost`, `127.0.0.1` or the published site. The extension makes no network requests.

Browsers don't let extensions read response bodies from the network, so `token-hook.js` runs inside each page and reads
the page's own copy of a reply, only for POST requests to a known identity provider's `/token` endpoint. Tokens an
app's own server requests never pass through the browser; Flow tracer's Entra's verdict covers those sign-ins.

## Files

| File | What it does |
| --- | --- |
| `capture-core.js` | Which requests count as sign-in traffic, and grouping them into one flow per sign-in. Unit tested in `tests/browser-capture.test.ts`. |
| `background.js` | Listens to the browser's requests and keeps the flows. |
| `bridge.js` | Passes flows to the Federation 360 page. |
| `idp-page.js` | Reads the AADSTS error, request ID and correlation ID shown on a Microsoft sign-in page. |
| `token-hook.js` | Runs inside each page and passes on token replies from identity providers' token endpoints. |
| `relay.js` | Passes what `token-hook.js` saw to the extension. |

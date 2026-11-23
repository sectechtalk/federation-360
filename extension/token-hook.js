// Federation 360 Capture: runs inside each page (the page's own JavaScript world) and notices when the page itself
// asks an identity provider's token endpoint for tokens, as single-page apps do. Browsers don't let extensions read
// those responses from the network, so this reads the page's own copy of the reply.
//
// It only looks at POST requests to a /token endpoint on a known identity provider host. The refresh token is
// replaced with "(issued)" before anything leaves the page. Nothing else on the page is read or changed.
(() => {
  if (window.__f360TokenHook) return;
  window.__f360TokenHook = true;
  const HOSTS = [
    /(^|\.)login\.microsoftonline\.com$/i, /(^|\.)login\.microsoft\.com$/i, /(^|\.)login\.windows\.net$/i,
    /(^|\.)login\.live\.com$/i, /\.b2clogin\.com$/i, /\.ciamlogin\.com$/i, /\.okta(preview)?\.com$/i,
    /\.auth0\.com$/i, /(^|\.)oauth2\.googleapis\.com$/i,
  ];
  const isToken = (url, method) => {
    try {
      const u = new URL(url, location.href);
      return (method || "GET").toUpperCase() === "POST" && /\/token\/?$/i.test(u.pathname) && HOSTS.some((r) => r.test(u.hostname));
    } catch {
      return false;
    }
  };
  const bodyText = (b) => (typeof b === "string" ? b : b instanceof URLSearchParams ? b.toString() : "");
  const send = (url, request, status, text) => {
    let body = text;
    try {
      const j = JSON.parse(text);
      if (j.refresh_token) j.refresh_token = "(issued)";
      body = JSON.stringify(j);
    } catch {
      /* not JSON: send as is (error pages) */
    }
    const form = new URLSearchParams(request);
    for (const k of ["code", "code_verifier", "client_secret", "client_assertion", "refresh_token", "password"]) if (form.has(k)) form.set(k, "(present)");
    window.postMessage({ source: "f360-capture-page-hook", type: "token-response", url: String(url), request: form.toString(), status, body: body.slice(0, 200000) }, location.origin);
  };

  const origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function (input, init) {
      const p = origFetch.apply(this, arguments);
      try {
        const url = typeof input === "string" || input instanceof URL ? String(input) : input?.url;
        const method = init?.method || (typeof input === "object" && input?.method) || "GET";
        if (isToken(url, method)) {
          const req = bodyText(init?.body);
          p.then((r) => r.clone().text().then((t) => send(r.url || url, req, r.status, t))).catch(() => {});
        }
      } catch {
        /* never break the page */
      }
      return p;
    };
  }

  const XO = XMLHttpRequest.prototype.open;
  const XS = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__f360 = isToken(url, method) ? { url: String(url) } : null;
    return XO.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    if (this.__f360) {
      const info = this.__f360;
      info.req = bodyText(body);
      this.addEventListener("loadend", () => {
        try {
          const t = this.responseType === "" || this.responseType === "text" ? this.responseText : this.responseType === "json" ? JSON.stringify(this.response) : "";
          send(this.responseURL || info.url, info.req, this.status, t);
        } catch {
          /* ignore */
        }
      });
    }
    return XS.apply(this, arguments);
  };
})();

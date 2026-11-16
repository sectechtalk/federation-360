// Federation 360 lab test app, Azure host: runs core.mjs as one managed function on Azure Static Web Apps Free.
//
// Every request under /api comes here. Nothing is stored: captures go back to Federation 360 in the response, or
// in the URL fragment after a SAML sign-in. No npm packages (Azure Functions Node.js programming model v3).
//
// Settings (set by lab/testapp/azure/Deploy-F360TestAppAzure.ps1, never committed):
//   F360_TESTAPP_CONFIG   base64 of the same JSON as lab/testapp/.local/config.json, with publicUrl set to this site
//   F360_DAEMON_KEY       base64 of LAB-Daemon's private key (PEM), for the client credentials test
//   F360_DAEMON_CERT      base64 of LAB-Daemon's certificate (PEM)
//
// core.mjs is copied next to this file when the site is staged (lab/testapp/azure/stage.mjs).

let handler;

const fromB64 = (name) => (process.env[name] ? Buffer.from(process.env[name], "base64").toString("utf8") : "");

async function getHandler() {
  if (handler) return handler;
  const { createHandler } = await import("./core.mjs");
  let config = null;
  try {
    config = process.env.F360_TESTAPP_CONFIG ? JSON.parse(fromB64("F360_TESTAPP_CONFIG")) : null;
  } catch {
    config = null;
  }
  const keyPem = fromB64("F360_DAEMON_KEY");
  const certPem = fromB64("F360_DAEMON_CERT");
  handler = createHandler({
    config,
    store: null,
    samlPrefix: "/api",
    daemonKeys: () => (keyPem && certPem ? { keyPem, certPem } : null),
    log: (...a) => console.log(...a),
  });
  return handler;
}

module.exports = async function (context, req) {
  const handle = await getHandler();
  let path = "/api/" + String(req.params?.path ?? "").replace(/^\/+/, "");
  try {
    path = new URL(req.originalUrl || req.url).pathname;
  } catch {
    /* keep the route parameter */
  }
  const headers = {};
  for (const [k, v] of Object.entries(req.headers ?? {})) headers[k.toLowerCase()] = v;
  const query = new URLSearchParams();
  for (const [k, v] of Object.entries(req.query ?? {})) query.set(k, String(v));
  const body = typeof req.rawBody === "string" ? req.rawBody : req.rawBody ? Buffer.from(req.rawBody).toString("utf8") : "";

  const r = await handle({ method: String(req.method || "GET").toUpperCase(), path, query, headers, body });
  context.res = { status: r.status, headers: r.headers, body: r.body, isRaw: true };
};

#!/usr/bin/env node
// Federation 360 lab test app, local host: runs lab/testapp/core.mjs as a web server on your PC.
//
// Each run is saved as a capture (lab/testapp/captures, gitignored) in Federation 360's "f360.capture" format.
// Federation 360 reads them from /api/captures. Nothing here talks to anything but Microsoft and your browser.
// The same app also runs on Azure Static Web Apps Free: see lab/testapp/azure.
//
// No dependencies. Node 18 or later. Usually started in Docker by lab/testapp/Start-F360TestApp.ps1.
//
//   node lab/testapp/server.mjs              reads lab/testapp/.local/config.json
//   F360_TESTAPP_CONFIG=path node ...        another config file

import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHandler, MAX_BODY } from "./core.mjs";

export { buildAuthnRequest, CAPTURE_FORMAT, clientAssertion, decodeJwt, metadataCerts, newCaptureId, validateAccessToken } from "./core.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

// ------------------------------------------------------------------ captures

class CaptureStore {
  constructor(dir) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true });
  }
  file(id) {
    if (!/^[\w-]{6,64}$/.test(id)) throw Object.assign(new Error("Bad capture id"), { status: 400 });
    return join(this.dir, `${id}.json`);
  }
  get(id) {
    const f = this.file(id);
    return existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : null;
  }
  put(c) {
    writeFileSync(this.file(c.id), JSON.stringify(c, null, 2));
    return c;
  }
  list() {
    return readdirSync(this.dir)
      .filter((f) => f.endsWith(".json"))
      .map((f) => {
        try {
          const c = JSON.parse(readFileSync(join(this.dir, f), "utf8"));
          return { id: c.id, kind: c.kind, title: c.title, startedAt: c.startedAt, source: c.source, steps: c.steps?.length ?? 0 };
        } catch {
          return null;
        }
      })
      .filter(Boolean)
      .sort((a, b) => b.startedAt.localeCompare(a.startedAt))
      .slice(0, 50);
  }
  clear() {
    for (const f of readdirSync(this.dir)) if (f.endsWith(".json")) rmSync(join(this.dir, f));
  }
}

// ------------------------------------------------------------------ server

export function loadConfig(file = process.env.F360_TESTAPP_CONFIG || join(HERE, ".local", "config.json")) {
  if (!existsSync(file)) return null;
  const c = JSON.parse(readFileSync(file, "utf8"));
  const base = dirname(resolve(file));
  if (c.daemon?.keyFile) c.daemon.keyFile = resolve(base, c.daemon.keyFile);
  if (c.daemon?.certFile) c.daemon.certFile = resolve(base, c.daemon.certFile);
  return c;
}

const readBody = (req) =>
  new Promise((res, rej) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        rej(Object.assign(new Error("Request body too large"), { status: 413 }));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => res(Buffer.concat(chunks).toString("utf8")));
    req.on("error", rej);
  });

/**
 * options: { config, captureDir, fetch, quiet }
 * config: { tenantId, f360Url, publicUrl, saml: { entityId, appId }, liveTest: { clientId },
 *           api: { clientId, scope, role }, daemon: { clientId, keyFile, certFile } }
 */
export function createTestApp({ config, captureDir = join(HERE, "captures"), fetch: fetchImpl = globalThis.fetch, quiet = false } = {}) {
  const log = (...a) => !quiet && console.log(new Date().toLocaleTimeString(), ...a);
  const cfg = config ?? {};
  const publicUrl = (cfg.publicUrl || "http://localhost:5174").replace(/\/+$/, "");
  // The certificate is read on every run, so a new one from the start script is picked up without a restart.
  const daemonKeys = () => {
    const d = cfg.daemon;
    if (!d?.keyFile || !d.certFile || !existsSync(d.keyFile) || !existsSync(d.certFile)) return null;
    return { keyPem: readFileSync(d.keyFile, "utf8"), certPem: readFileSync(d.certFile, "utf8") };
  };
  const handle = createHandler({ config: cfg, store: new CaptureStore(captureDir), daemonKeys, fetch: fetchImpl, log });

  return createServer(async (req, res) => {
    let r;
    try {
      const url = new URL(req.url, publicUrl);
      const body = req.method === "POST" ? await readBody(req) : "";
      r = await handle({ method: req.method, path: url.pathname, query: url.searchParams, headers: req.headers, body });
    } catch (e) {
      r = { status: e.status ?? 500, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }, body: JSON.stringify({ error: e.message }) };
    }
    res.writeHead(r.status, r.headers);
    res.end(r.body);
  });
}

// ------------------------------------------------------------------ main

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const config = loadConfig();
  const port = Number(process.env.F360_TESTAPP_PORT || 5174);
  const host = process.env.F360_TESTAPP_HOST || "127.0.0.1";
  const server = createTestApp({ config });
  server.listen(port, host, () => {
    console.log(`Federation 360 test app on http://localhost:${port}`);
    console.log(config ? `Lab tenant ${config.tenantId}` : "No config yet: run lab/testapp/Start-F360TestApp.ps1 (it writes lab/testapp/.local/config.json).");
  });
}

#!/usr/bin/env node
// Assembles the Azure Static Web Apps site for the lab test app into one folder:
//   <out>/app   static page + staticwebapp.config.json
//   <out>/api   managed function (host.json, testapp/function.json, testapp/index.js, testapp/core.mjs)
//
//   node lab/testapp/azure/stage.mjs <out>
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export function stage(out) {
  out = resolve(out);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  cpSync(join(here, "app"), join(out, "app"), { recursive: true });
  cpSync(join(here, "api"), join(out, "api"), { recursive: true });
  cpSync(join(here, "..", "core.mjs"), join(out, "api", "testapp", "core.mjs"));
  return out;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = process.argv[2];
  if (!out) {
    console.error("Usage: node lab/testapp/azure/stage.mjs <out folder>");
    process.exit(1);
  }
  console.log(`Staged the test app site in ${stage(out)}`);
}

// Converts the single-file Vite build into the page body the Claude Artifact tool publishes
// (the tool adds its own <!doctype>, <head> and <body> skeleton).
import { readFileSync, writeFileSync } from "node:fs";

const html = readFileSync("dist/index.html", "utf8");
const pick = (re) => [...html.matchAll(re)].map((m) => m[0]).join("\n");
const title = html.match(/<title>[\s\S]*?<\/title>/)[0];
const metas = pick(/<meta name="claude:[^>]+>/g);
const links = pick(/<link [^>]*fonts\.googleapis[^>]*>/g);
const styles = pick(/<style[\s\S]*?<\/style>/g);
const scripts = pick(/<script[\s\S]*?<\/script>/g);
const out = [title, metas, links, styles, '<div id="root"></div>', scripts].join("\n");
writeFileSync("dist/federation-360.html", out);
console.log("wrote dist/federation-360.html", (out.length / 1024).toFixed(0) + " KB");

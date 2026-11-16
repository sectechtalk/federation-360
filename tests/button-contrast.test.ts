// House rule: every button stands out from the background, and clickable and disabled buttons look different.
import { readFileSync } from "node:fs";

const css = readFileSync("src/styles.css", "utf8");
const base = readFileSync("src/360/360-base.css", "utf8");

function tokens(block: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of block.matchAll(/--([\w-]+)\s*:\s*(#[0-9a-f]{6})/gi)) out[m[1]] = m[2].toLowerCase();
  return out;
}
const lum = (hex: string) => {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
};
const contrast = (a: string, b: string) => {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

// Light = the first :root block of each file; dark = the [data-theme="dark"] block of each file.
const light = { ...tokens(base.slice(base.indexOf("--bg:"), base.indexOf("}", base.indexOf("--bg:")))), ...tokens(css.slice(0, css.indexOf("}"))) };
const darkCss = css.slice(css.indexOf(':root[data-theme="dark"]'));
const darkBase = base.slice(base.lastIndexOf("--bg:"));
const dark = { ...tokens(darkBase.slice(0, darkBase.indexOf("}"))), ...tokens(darkCss.slice(0, darkCss.indexOf("}"))) };

describe.each([["light", light], ["dark", dark]] as const)("%s theme buttons", (_name, t) => {
  test("clickable button edges are at least 3:1 against the page and panels", () => {
    for (const bg of [t.bg, t.surface, t["surface-2"]]) {
      expect(contrast(t["btn-border"], bg)).toBeGreaterThanOrEqual(3);
      expect(contrast(t["accent-strong"], bg)).toBeGreaterThanOrEqual(3);
    }
  });
  test("button fills never match the page or panels", () => {
    for (const fill of [t["btn-bg"], t["btn-off-bg"]]) for (const bg of [t.bg, t.surface, t["surface-2"]]) expect(fill).not.toBe(bg);
  });
  test("disabled buttons have a visible edge and a different colour from clickable ones", () => {
    for (const bg of [t.bg, t.surface]) expect(contrast(t["btn-off-border"], bg)).toBeGreaterThanOrEqual(3);
    expect(t["btn-off-bg"]).not.toBe(t["btn-bg"]);
    expect(t["btn-off-border"]).not.toBe(t["btn-border"]);
  });
  test("button text is readable (4.5:1)", () => {
    expect(contrast(t["btn-fg"], t["btn-bg"])).toBeGreaterThanOrEqual(4.5);
    expect(contrast(t["btn-fg"], t["btn-hover-bg"])).toBeGreaterThanOrEqual(4.5);
    expect(contrast(t["accent-ink"], t["accent-strong"])).toBeGreaterThanOrEqual(4.5);
  });
});

test("no button style is transparent or borderless", () => {
  expect(css).not.toMatch(/\.btn[^{]*\{[^}]*background:\s*(none|transparent)/);
  expect(css).not.toMatch(/\.btn\.ghost \{[^}]*border-color:\s*transparent/);
  expect(css).toMatch(/\.btn:disabled[^{]*\{[^}]*dashed/);
});

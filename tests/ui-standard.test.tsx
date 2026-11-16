// 360 look-and-feel standard (2026-11-15): Inter, the shared type scale and colours, the violet Federation accent,
// the 360 app switcher under the brand, a theme toggle that follows the OS, and a menu drawer at phone width.
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { renderToStaticMarkup } from "react-dom/server";
import { AppSwitcher, NavSection } from "../src/360/Shell360";
import { ICONS_360 } from "../src/360/icons";
import { APPS_360 } from "../src/360/apps";
import { initialTheme, saveTheme, THEME_KEY } from "../src/360/theme";

// Paths are from the repo root (vitest runs there).
const read = (f: string) => readFileSync(resolve(process.cwd(), f), "utf8");
const base = read("src/360/360-base.css");
const css = read("src/styles.css");

describe("360 standard", () => {
  it("360-base.css: seven-step type scale with a 12px floor and Inter bundled with the app", () => {
    const steps: Record<string, string> = { xs: ".75rem", sm: ".8125rem", base: ".875rem", md: "1rem", lg: "1.25rem", xl: "1.5rem", "2xl": "1.875rem" };
    for (const [name, size] of Object.entries(steps)) expect(base).toMatch(new RegExp(`--text-${name}:${size.replace(".", "\\.")};`));
    expect(base).toContain("url(./fonts/InterVariable.woff2)");
    expect(existsSync(resolve(process.cwd(), "src/360/fonts/InterVariable.woff2"))).toBe(true);
  });

  it("styles.css imports the base, uses only the type tokens, Inter and weights 400/500/600, and sets the violet accent", () => {
    expect(css.startsWith('@import "./360/360-base.css";')).toBe(true);
    expect(css.match(/font(?:-size)?:[^;}]*\d(?:px|pt|rem)\b/g) ?? []).toEqual([]);
    expect(css).not.toMatch(/IBM Plex|Sora|--font-display|--font-body/);
    expect((css.match(/font-weight:\s*(\d+)/g) ?? []).filter((w) => !/(400|500|600)$/.test(w))).toEqual([]);
    expect(css).toContain("--accent: #6b3fc6;");
    expect(css).toContain(".btn.primary { background: var(--accent-strong)");
  });

  it("styles.css has balanced braces", () => {
    let depth = 0;
    for (const ch of css.replace(/\/\*[\s\S]*?\*\//g, "")) {
      if (ch === "{") depth++;
      if (ch === "}") depth--;
      expect(depth).toBeGreaterThanOrEqual(0);
    }
    expect(depth).toBe(0);
  });

  it("index.html no longer loads Google Fonts", () => {
    expect(read("index.html")).not.toContain("fonts.googleapis");
  });

  it("app switcher lists every 360 app, marks Federation 360 as here, and never links an app with no URL", () => {
    const out = renderToStaticMarkup(<AppSwitcher current="f-360" />);
    for (const a of APPS_360) expect(out).toContain(a.name);
    expect(out).toMatch(/<span class="app-switch-item" aria-current="page"><strong>Federation 360<\/strong>/);
    expect(out).not.toContain('href=""');
  });

  it("theme: a stored choice wins, otherwise the OS setting; the choice is stored under f360-theme", () => {
    const m: Record<string, string> = {};
    const store = { getItem: (k: string) => m[k] ?? null, setItem: (k: string, v: string) => void (m[k] = v) };
    const os = (dark: boolean) => ({ matchMedia: () => ({ matches: dark }) });
    expect(THEME_KEY).toBe("f360-theme");
    expect(initialTheme(store, os(true))).toBe("dark");
    saveTheme("light", store);
    expect(m["f360-theme"]).toBe("light");
    expect(initialTheme(store, os(true))).toBe("light");
  });

  it("rail: every page has its own icon from the shared set, and sections are collapsible buttons", () => {
    const app = read("src/App.tsx");
    const icons = [...app.matchAll(/icon: "([a-z0-9-]+)"/g)].map((m) => m[1]);
    expect(icons.length).toBe([...app.matchAll(/\{ id: "/g)].length);
    expect(icons.filter((n, i) => icons.indexOf(n) !== i)).toEqual([]);
    for (const n of icons) expect(ICONS_360[n], n).toBeTruthy();
    const out = renderToStaticMarkup(<NavSection title="Troubleshoot" current={false}><a className="nav-item">x</a></NavSection>);
    expect(out).toContain('<button type="button" class="nav-label" aria-expanded="true" data-section="troubleshoot"');
    expect(out).toContain('<span class="nav-chevron" aria-hidden="true"></span>');
    expect(css).not.toMatch(/\.nav-(label|item) \{[^}]*font-size/);
  });
});

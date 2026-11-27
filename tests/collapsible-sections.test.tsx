// House rule (2026-11-27): every section on every page is collapsible, and collapsed by default. Every panel is a <Section>; it starts collapsed and folds from its heading row or its
// Expand / Collapse button. Expand all and Collapse all sit above every page.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { Section, foldAll, openSection } from "../src/components/Section";

(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

function mount(el: React.ReactElement) {
  const div = document.createElement("div");
  document.body.appendChild(div);
  const root = createRoot(div);
  act(() => root.render(el));
  return { div, root };
}

const sample = (id?: string) => (
  <Section className="panel stack" id={id}>
    <div className="panel-head"><h2>Load logs</h2><button className="btn sm" id="head-action">Clear</button></div>
    <p id="inside">Body text</p>
  </Section>
);

describe("Section", () => {
  it("starts collapsed, with the heading visible and an Expand button", () => {
    const { div } = mount(sample());
    expect(div.querySelector("h2")?.textContent).toBe("Load logs");
    const body = div.querySelector(".fold-body") as HTMLElement;
    expect(body.hidden).toBe(true);
    const btn = div.querySelector(".fold-btn") as HTMLButtonElement;
    expect(btn.getAttribute("aria-expanded")).toBe("false");
    expect(btn.textContent).toContain("Expand");
    expect(btn.className).toContain("btn");
  });

  it("opens and closes from the button or the heading row, but not from a button in the heading row", () => {
    const { div } = mount(sample());
    const body = () => div.querySelector(".fold-body") as HTMLElement;
    act(() => (div.querySelector(".fold-btn") as HTMLButtonElement).click());
    expect(body().hidden).toBe(false);
    expect(div.querySelector(".fold-btn")?.textContent).toContain("Collapse");
    act(() => (div.querySelector("h2") as HTMLElement).click());
    expect(body().hidden).toBe(true);
    act(() => (div.querySelector("#head-action") as HTMLElement).click());
    expect(body().hidden).toBe(true);
  });

  it("follows Expand all / Collapse all", () => {
    const { div } = mount(sample());
    act(() => void foldAll(true));
    expect((div.querySelector(".fold-body") as HTMLElement).hidden).toBe(false);
    act(() => void foldAll(false));
    expect((div.querySelector(".fold-body") as HTMLElement).hidden).toBe(true);
  });

  it("opens when a link asks for it, even if it appears a moment later", () => {
    act(() => openSection("later"));
    const { div } = mount(sample("later"));
    expect((div.querySelector(".fold-body") as HTMLElement).hidden).toBe(false);
  });
});

test("a collapsed body is hidden even when it is a flex stack", () => {
  const css = readFileSync("src/styles.css", "utf8");
  expect(css).toMatch(/\.fold-body\[hidden\] \{ display: none !important; \}/);
});

test("App shows Expand all and Collapse all above every page", () => {
  expect(readFileSync("src/App.tsx", "utf8")).toContain("<FoldAllBar toast={toast} />");
});

// Sweep guard over every page and component.
function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => (statSync(join(dir, f)).isDirectory() ? files(join(dir, f)) : /\.tsx$/.test(f) ? [join(dir, f)] : []));
}
const SRC = files("src").filter((f) => !f.endsWith("Section.tsx") && !f.includes("/360/"));

test("every panel section is a collapsible <Section> (no plain <section className=\"panel…\">)", () => {
  const bad = SRC.flatMap((f) => [...readFileSync(f, "utf8").matchAll(/<section\b[^>]*>/g)].map((m) => `${f}: ${m[0]}`));
  expect(bad).toEqual([]);
});

test("no fold-out starts open (no <details open>)", () => {
  const bad = SRC.flatMap((f) => [...readFileSync(f, "utf8").matchAll(/<details\b[^>]*\bopen\b[^>]*>/g)].map((m) => `${f}: ${m[0]}`));
  expect(bad).toEqual([]);
});

test("every <Section> starts with a heading, so a collapsed section still says what it holds", () => {
  const bad: string[] = [];
  for (const f of SRC) {
    const src = readFileSync(f, "utf8");
    for (const m of src.matchAll(/<Section\b[^>]*>/g)) {
      const next = src.slice(m.index! + m[0].length).split("\n").slice(1, 7).join("\n");
      if (!/<h[23][\s>]|\{head\}|className="eyebrow"/.test(next)) bad.push(`${f}: ${next.trim().split("\n")[0].slice(0, 100)}`);
    }
  }
  expect(bad).toEqual([]);
});

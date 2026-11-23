// House rule (2026-11-21): every button on every page gives feedback that it is doing something.
// ActionButton shows a verb with a spinner and a seconds counter while it works, then "✓ <what happened>" or
// "✗ <the exact error>". A busy button must never look like a disabled one (grey, dashed).
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { ActionButton, downloadFile } from "../src/components/busy";

(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

function mount(el: React.ReactElement) {
  const div = document.createElement("div");
  document.body.appendChild(div);
  const root = createRoot(div);
  act(() => root.render(el));
  return { div, root, button: () => div.querySelector("button")! };
}

describe("ActionButton", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("shows the busy verb right away, keeps the button enabled (not the disabled look), then reports success", async () => {
    let finish!: (v: string) => void;
    const { div, button } = mount(<ActionButton busy="Saving…" onClick={() => new Promise<string>((r) => (finish = r))}>Save tenant</ActionButton>);
    expect(button().textContent).toBe("Save tenant");
    act(() => button().click());
    expect(button().textContent).toContain("Saving…");
    expect(button().className).toContain("is-busy");
    expect(button().getAttribute("aria-busy")).toBe("true");
    expect(button().disabled).toBe(false);
    expect(div.querySelector(".spin")).not.toBeNull();
    await act(async () => vi.advanceTimersByTime(2100));
    expect(button().textContent).toMatch(/Saving…\s*2s/);
    await act(async () => { finish("Tenant saved"); await Promise.resolve(); vi.advanceTimersByTime(500); });
    expect(button().textContent).toBe("Save tenant");
    expect(div.querySelector(".act-msg.ok")?.textContent).toBe("✓ Tenant saved");
  });

  it("shows the exact error when the work fails", async () => {
    const { div, button } = mount(<ActionButton busy="Fetching…" onClick={async () => { throw new Error("HTTP 404"); }}>Load</ActionButton>);
    await act(async () => { button().click(); await Promise.resolve(); vi.advanceTimersByTime(500); });
    const err = div.querySelector(".act-msg.err");
    expect(err?.textContent).toBe("✗ HTTP 404");
    expect(err?.getAttribute("role")).toBe("alert");
  });

  it("ignores a second click while busy", async () => {
    const fn = vi.fn(() => new Promise<void>(() => {}));
    const { button } = mount(<ActionButton busy="Working…" onClick={fn}>Go</ActionButton>);
    act(() => button().click());
    act(() => button().click());
    expect(fn).toHaveBeenCalledTimes(1);
  });
});

test("downloadFile says the file name and size", () => {
  (URL as any).createObjectURL ??= () => "blob:x";
  (URL as any).revokeObjectURL ??= () => {};
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  expect(downloadFile("detect.ps1", "x".repeat(2048))).toBe("Downloaded detect.ps1 (2.0 KB). Look in your Downloads folder.");
  expect(click).toHaveBeenCalledTimes(1);
  click.mockRestore();
});

test("a busy button keeps a solid edge and never uses the disabled look", () => {
  const css = readFileSync("src/styles.css", "utf8");
  const busy = css.match(/\.btn\.is-busy, \.btn\.is-busy:hover \{([^}]*)\}/)?.[1] ?? "";
  expect(busy).toContain("border-style: solid");
  expect(busy).toContain("cursor: progress");
  expect(busy).not.toMatch(/btn-off|dashed/);
  expect(css).toMatch(/@keyframes spin/);
  expect(css).toMatch(/\.acked \{/);
});

test("App pulses every other button and says which page a button opened", () => {
  const app = readFileSync("src/App.tsx", "utf8");
  expect(app).toContain("useClickAck(toast)");
  expect(app).toMatch(/toast\("Opened " \+/);
});

// Sweep guard: a plain <button> may navigate, open a drawer or flip a setting (the click pulse and the page change are the
// feedback). Anything that saves, downloads, copies, fetches, signs in or loads must be an ActionButton.
const WORK = /\b(save|download\w*|copy\w*|apply|refresh|checkNow|run[A-Z]\w*|doImport|tryFetch|fetch|loadExamples|loadSample|sample|trySample|clearExamples|del|signIn|startSignIn|open)\s*\(|onClick=\{(save|download\w*|apply|refresh|checkNow|run[A-Z]\w*|doImport|loadExamples|clearExamples|del|clear|signIn)\}/;
function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => (statSync(join(dir, f)).isDirectory() ? files(join(dir, f)) : /\.tsx$/.test(f) ? [join(dir, f)] : []));
}
test("no plain <button> does work without the busy pattern", () => {
  const bad: string[] = [];
  for (const f of files("src")) {
    const src = readFileSync(f, "utf8");
    for (const m of src.matchAll(/<button\b[\s\S]*?<\/button>/g)) {
      const tag = m[0];
      if (WORK.test(tag) && !tag.includes("toast(")) bad.push(`${f}: ${tag.slice(0, 120)}`);
    }
  }
  expect(bad).toEqual([]);
});

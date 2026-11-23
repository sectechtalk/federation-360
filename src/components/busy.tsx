// House rule (2026-11-21): every button gives feedback that it is doing something.
//
// One shared pattern for the whole app:
// - ActionButton: for anything that does work (saves, fetches, signs in, builds a file, copies). The moment it is
//   clicked the label changes to a verb ("Saving…", "Fetching…") with a spinner, and after a second a seconds counter.
//   When the work ends it shows a green "✓ <what happened>" or a red "✗ <the exact error>" next to the button.
//   A busy button is NOT greyed out: it keeps its solid edge, gets a moving stripe and a progress cursor, so it never
//   looks like a disabled (grey, dashed) button.
// - BusyNote: the same spinner and counter for work the page starts on its own (coming back from a sign-in).
// - useClickAck: every other button (page links, tabs, toggles, Back/Next) gets a short pulse when clicked, so even
//   instant actions visibly react.
import { useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { Ctx } from "./ui";

/** What an action returns: a sentence saying what happened, or nothing for a plain "Done". */
export type ActionResult = string | void | undefined;

const MIN_BUSY_MS = 400; // long enough to read the busy label, even when the work is instant
const OK_CLEAR_MS = 8000; // success lines fade after a while; error lines stay until the next click

export const errorText = (e: unknown) => String((e as any)?.message ?? e ?? "Unknown error");

/** Seconds since `since` (or null), ticking once a second. */
export function useSeconds(since: number | null) {
  const [, tick] = useState(0);
  useEffect(() => {
    if (since === null) return;
    const t = window.setInterval(() => tick((n) => n + 1), 1000);
    return () => window.clearInterval(t);
  }, [since]);
  return since === null ? 0 : Math.floor((Date.now() - since) / 1000);
}

export function Spinner() {
  return <span className="spin" aria-hidden="true" />;
}

export function ActionButton(props: {
  /** The verb shown while the work runs, ending in "…", e.g. "Saving…". */
  busy: string;
  onClick: () => ActionResult | Promise<ActionResult>;
  children: ReactNode;
  className?: string;
  disabled?: boolean;
  title?: string;
  /** "inline" (default) writes the result next to the button; "toast" shows it at the bottom of the page. */
  report?: "inline" | "toast";
  /** Hide the success line (the page shows the result itself). Errors are always shown. */
  quietOk?: boolean;
}) {
  const { busy: busyLabel, onClick, children, className = "btn", disabled, title, report = "inline", quietOk } = props;
  const app = useContext(Ctx);
  const [since, setSince] = useState<number | null>(null);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  const alive = useRef(true);
  const clearT = useRef(0);
  const secs = useSeconds(since);
  useEffect(() => () => {
    alive.current = false;
    window.clearTimeout(clearT.current);
  }, []);

  const busy = since !== null;
  const click = async () => {
    if (busy || disabled) return;
    window.clearTimeout(clearT.current);
    setResult(null);
    const start = Date.now();
    setSince(start);
    let r: { ok: boolean; text: string };
    try {
      const out = await onClick();
      r = { ok: true, text: typeof out === "string" && out ? out : "Done" };
    } catch (e) {
      r = { ok: false, text: errorText(e) };
    }
    const wait = MIN_BUSY_MS - (Date.now() - start);
    if (wait > 0) await new Promise((res) => setTimeout(res, wait));
    if (!alive.current) return; // the page moved on (navigation, dialog closed): nothing left to update
    setSince(null);
    if (report === "toast" && app?.toast) {
      if (!r.ok || !quietOk) app.toast((r.ok ? "✓ " : "✗ ") + r.text);
      return;
    }
    if (r.ok && quietOk) return;
    setResult(r);
    if (r.ok) clearT.current = window.setTimeout(() => alive.current && setResult(null), OK_CLEAR_MS);
  };

  return (
    <span className="act">
      <button
        type="button"
        data-action=""
        className={busy ? `${className} is-busy` : className}
        aria-busy={busy || undefined}
        aria-disabled={busy || undefined}
        disabled={disabled}
        title={title}
        onClick={click}
      >
        {busy ? (
          <>
            <Spinner />
            {busyLabel}
            {secs >= 1 && <span className="secs">{secs}s</span>}
          </>
        ) : (
          children
        )}
      </button>
      {result && (
        <span className={`act-msg ${result.ok ? "ok" : "err"}`} role={result.ok ? "status" : "alert"}>
          {result.ok ? "✓ " : "✗ "}
          {result.text}
        </span>
      )}
    </span>
  );
}

/** A status line with a spinner and seconds counter, for work the page started by itself. */
export function BusyNote({ children, className = "callout" }: { children: ReactNode; className?: string }) {
  const [since] = useState(() => Date.now());
  const secs = useSeconds(since);
  return (
    <div className={`${className} busy-note`} role="status" aria-busy="true">
      <Spinner />
      <span>{children}</span>
      {secs >= 1 && <span className="secs">{secs}s</span>}
    </div>
  );
}

const fmtSize = (n: number) => (n < 1024 ? `${n} bytes` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`);

/** Hands a file to the browser's downloads and returns the sentence to show. */
export function downloadFile(name: string, content: string, type = "text/plain"): string {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return `Downloaded ${name} (${fmtSize(blob.size)}). Look in your Downloads folder.`;
}

/** Copies to the clipboard; resolves with the sentence to show or throws the reason it couldn't. */
export async function copyNow(text: string): Promise<string> {
  if (!navigator.clipboard?.writeText) throw new Error("Copy isn't allowed here. Select the text and copy it manually.");
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    throw new Error("Copy isn't allowed here. Select the text and copy it manually.");
  }
  return "Copied to the clipboard";
}

/**
 * A link styled as a button that leaves this page (a sign-in run). On click it shows a spinner and "Opening…" until
 * the browser navigates away; if the browser stays (blocked, or you come back with Back), the label returns.
 */
export function LeaveLink({ href, className = "btn", title, children }: { href: string; className?: string; title?: string; children: ReactNode }) {
  const [since, setSince] = useState<number | null>(null);
  const secs = useSeconds(since);
  useEffect(() => {
    if (since === null) return;
    const back = () => setSince(null);
    const t = window.setTimeout(back, 20000);
    addEventListener("pageshow", back);
    return () => {
      window.clearTimeout(t);
      removeEventListener("pageshow", back);
    };
  }, [since]);
  const busy = since !== null;
  return (
    <a
      href={href}
      data-action=""
      className={busy ? `${className} is-busy` : className}
      aria-busy={busy || undefined}
      title={title}
      onClick={() => setSince(Date.now())}
    >
      {busy ? (
        <>
          <Spinner />
          Opening Microsoft sign-in…
          {secs >= 1 && <span className="secs">{secs}s</span>}
        </>
      ) : (
        children
      )}
    </a>
  );
}

const ACK_SELECTOR = "button, a.btn, label.btn";

/**
 * Every button that isn't an ActionButton pulses when clicked, so even instant actions (page links, tabs, toggles,
 * Back and Next) visibly react. Button-styled links that open a new tab also say so at the bottom of the page.
 */
export function useClickAck(toast: (m: string) => void) {
  const say = useRef(toast);
  say.current = toast;
  useEffect(() => {
    const on = (e: MouseEvent) => {
      const el = (e.target as Element | null)?.closest?.(ACK_SELECTOR) as HTMLElement | null;
      if (!el || el.hasAttribute("data-action") || (el as HTMLButtonElement).disabled) return;
      el.classList.remove("acked");
      void el.offsetWidth; // restart the animation on a quick second click
      el.classList.add("acked");
      window.setTimeout(() => el.classList.remove("acked"), 700);
      if (el instanceof HTMLAnchorElement && el.target === "_blank") say.current("Opening in a new tab: " + (el.textContent ?? "").replace(/\s*↗\s*$/, ""));
    };
    document.addEventListener("click", on, true);
    return () => document.removeEventListener("click", on, true);
  }, []);
}

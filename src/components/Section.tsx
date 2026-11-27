// House rule (2026-11-27): every section on every page is collapsible, and collapsed by default.
//
// Every panel on every page is a <Section>. Its first child is the heading row (a panel-head, an h2/h3, or a spread with
// the heading and a few action buttons); the heading row stays visible and the rest folds away. Every Section starts
// collapsed. Clicking the heading row or the Expand button opens it; Collapse closes it again. The bar at the top of each
// page has "Expand all" and "Collapse all".
//
// A section opens by itself only when you ask for it: a link to it (openSection), or Expand all.
import { Children, useEffect, useId, useState, type CSSProperties, type MouseEvent, type ReactNode } from "react";

const OPEN_ONE = "f360:open-section";
const FOLD_ALL = "f360:fold-all";

// Sections asked for before they were on the page (a result still being built): they open when they mount.
const pending = new Set<string>();

/** Opens the section with this id (if it is collapsed) and scrolls to it. */
export function openSection(id: string, smooth = false) {
  pending.add(id);
  window.setTimeout(() => pending.delete(id), 5000);
  window.dispatchEvent(new CustomEvent(OPEN_ONE, { detail: id }));
  // Let React show the body before scrolling, so the page lands on the opened section. A result that is still being
  // worked out isn't on the page yet, so look again for a moment before giving up.
  let tries = 0;
  const land = () => {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView?.({ behavior: smooth ? "smooth" : "auto", block: "start" });
    else if (++tries < 40 && pending.has(id)) window.setTimeout(land, 50);
  };
  window.setTimeout(land, 30);
}

/** Opens or closes every section on the page. Returns how many sections it changed. */
export function foldAll(open: boolean): number {
  window.dispatchEvent(new CustomEvent(FOLD_ALL, { detail: open }));
  // The smaller fold-outs inside sections (<details>) follow too.
  const details = document.querySelectorAll<HTMLDetailsElement>("main details:not(.app-switcher-menu)");
  details.forEach((d) => (d.open = open));
  return document.querySelectorAll("section.fold").length + details.length;
}

// Clicks on these inside the heading row do their own job and don't fold the section.
const INTERACTIVE = "button, a, input, select, textarea, label, summary, [role=button]";

export function Section(props: {
  children: ReactNode;
  /** The panel's classes, as on the <section> it replaces, e.g. "panel stack". */
  className?: string;
  id?: string;
  style?: CSSProperties;
  "aria-label"?: string;
}) {
  const { children, className = "panel stack", id, style } = props;
  // Collapsed by default, always. The only exception is a section you just asked for by link (openSection).
  const [open, setOpen] = useState(() => Boolean(id && pending.delete(id)));
  const bodyId = useId();
  useEffect(() => {
    const one = (e: Event) => {
      if (id && (e as CustomEvent<string>).detail === id) setOpen(true);
    };
    const all = (e: Event) => setOpen(Boolean((e as CustomEvent<boolean>).detail));
    window.addEventListener(OPEN_ONE, one);
    window.addEventListener(FOLD_ALL, all);
    return () => {
      window.removeEventListener(OPEN_ONE, one);
      window.removeEventListener(FOLD_ALL, all);
    };
  }, [id]);

  const [head, ...rest] = Children.toArray(children);
  const toggleFromHead = (e: MouseEvent<HTMLDivElement>) => {
    const t = e.target as Element;
    if (t.closest(INTERACTIVE)) return; // a button or link in the heading row (Expand included) does its own job
    setOpen((o) => !o);
  };
  const stack = /\bstack\b/.test(className);
  return (
    <section id={id} aria-label={props["aria-label"]} style={style} className={`${className} fold${open ? " is-open" : ""}`}>
      <div className="fold-head" onClick={toggleFromHead}>
        <div className="fold-title">{head}</div>
        <button
          type="button"
          className="btn sm fold-btn"
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={() => setOpen((o) => !o)}
          title={open ? "Hide this section" : "Show this section"}
        >
          <span className="fold-chev" aria-hidden="true">{open ? "▾" : "▸"}</span>
          {open ? "Collapse" : "Expand"}
        </button>
      </div>
      <div id={bodyId} className={`fold-body${stack ? " stack" : ""}`} hidden={!open}>
        {rest}
      </div>
    </section>
  );
}

/** "Expand all" and "Collapse all" for the page, shown above every page. */
export function FoldAllBar({ toast }: { toast: (m: string) => void }) {
  return (
    <div className="fold-all" role="group" aria-label="Sections on this page">
      <button type="button" className="btn sm" onClick={() => toast(`Expanded ${foldAll(true)} sections`)}>
        Expand all sections
      </button>
      <button type="button" className="btn sm" onClick={() => toast(`Collapsed ${foldAll(false)} sections`)}>
        Collapse all sections
      </button>
    </div>
  );
}

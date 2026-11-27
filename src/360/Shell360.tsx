// 360 standard shell pieces for Federation 360: the app switcher under the brand, the light/dark toggle,
// and the menu button that opens the rail as a drawer at phone width. Same behaviour as shell.js in the other 360 apps.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { APPS_360, type App360 } from "./apps";
import { toggleTheme, type Theme } from "./theme";
import { iconSvg } from "./icons";

export function AppSwitcher({ current, apps = APPS_360 }: { current: string; apps?: App360[] }) {
  const ref = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    const menu = ref.current;
    if (!menu) return;
    const click = (e: MouseEvent) => {
      if (menu.open && !menu.contains(e.target as Node)) menu.open = false;
    };
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape" && menu.open) {
        menu.open = false;
        menu.querySelector("summary")?.focus();
      }
    };
    document.addEventListener("click", click);
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("click", click);
      document.removeEventListener("keydown", key);
    };
  }, []);
  return (
    <div className="app-switcher">
      <details className="app-switcher-menu" ref={ref}>
        <summary className="app-switcher-toggle">360 apps</summary>
        <ul className="app-switch-list">
          {apps.map((a) => {
            const label = (
              <>
                <strong>{a.name}</strong>
                <small>{a.id === current ? "You are here" : a.url ? a.about : "Not linked yet"}</small>
              </>
            );
            if (a.id === current)
              return (
                <li key={a.id}>
                  <span className="app-switch-item" aria-current="page">{label}</span>
                </li>
              );
            if (!a.url)
              return (
                <li key={a.id}>
                  <span className="app-switch-item is-unlinked">{label}</span>
                </li>
              );
            return (
              <li key={a.id}>
                <a className="app-switch-item" href={a.url}>{label}</a>
              </li>
            );
          })}
        </ul>
      </details>
    </div>
  );
}

const currentTheme = (): Theme => (document.documentElement.dataset.theme === "dark" ? "dark" : "light");

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(currentTheme);
  useEffect(() => {
    // Follow changes made elsewhere (the OS switching while no choice is stored).
    const obs = new MutationObserver(() => setTheme(currentTheme()));
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => obs.disconnect();
  }, []);
  const next = theme === "dark" ? "light" : "dark";
  return (
    <button id="theme-toggle" className="btn" type="button" aria-pressed={theme === "dark"} title={`Switch to ${next} mode`} onClick={() => setTheme(toggleTheme())}>
      <span className="theme-label">{theme === "dark" ? "Light mode" : "Dark mode"}</span>
    </button>
  );
}

// Phone-width drawer: returns the menu button. Closes on a rail link, a click outside, or Escape.
export function useNavDrawer(railId: string) {
  const [open, setOpen] = useState(false);
  const btn = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    document.body.classList.toggle("nav-open", open);
    if (!open) return;
    const rail = document.getElementById(railId);
    const click = (e: MouseEvent) => {
      const t = e.target as Element;
      if (rail?.contains(t) ? t.closest("a[href]") && !t.closest(".app-switcher") : !btn.current?.contains(t)) setOpen(false);
    };
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        btn.current?.focus();
      }
    };
    document.addEventListener("click", click);
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("click", click);
      document.removeEventListener("keydown", key);
    };
  }, [open, railId]);
  const button = (
    <button ref={btn} id="nav-toggle" className="btn nav-toggle" type="button" aria-controls={railId} aria-expanded={open} onClick={() => setOpen((o) => !o)}>
      Menu
    </button>
  );
  return button;
}

// Rail page icon from the shared 360 icon set (static SVG markup from icons.ts, never user input).
export function NavIcon({ name }: { name: string }) {
  return <span className="nav-icon" dangerouslySetInnerHTML={{ __html: iconSvg(name) }} />;
}

// Collapsible rail section: an uppercase header button with a chevron over its page links, remembered per app
// under f360.nav.collapsed like nav-sections.js in the other 360 apps. The section holding the current page always opens.
export const NAV_COLLAPSE_KEY = "f360.nav.collapsed"; // gitleaks:allow (a browser storage key name, not a secret)
const sectionKey = (title: string) => title.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
function readCollapsed(): string[] {
  try {
    const v = JSON.parse(localStorage.getItem(NAV_COLLAPSE_KEY) || "[]");
    return Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];
  } catch {
    return [];
  }
}
function writeCollapsed(keys: string[]) {
  try {
    localStorage.setItem(NAV_COLLAPSE_KEY, JSON.stringify(keys));
  } catch {
    /* storage blocked */
  }
}

export function NavSection({ title, current, children }: { title: string; current: boolean; children: ReactNode }) {
  const key = sectionKey(title);
  const [closed, setClosed] = useState(() => readCollapsed().includes(key));
  useEffect(() => {
    if (current && closed) setClosed(false);
  }, [current]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    const rest = readCollapsed().filter((k) => k !== key);
    writeCollapsed(closed ? [...rest, key] : rest);
  }, [closed, key]);
  return (
    <div className="nav-group">
      <button type="button" className="nav-label" aria-expanded={!closed} data-section={key} title={`${closed ? "Expand" : "Collapse"} ${title}`} onClick={() => setClosed((c) => !c)}>
        <span>{title}</span>
        <span className="nav-chevron" aria-hidden="true" />
      </button>
      {!closed && children}
    </div>
  );
}

// Theme: a stored choice ("light" | "dark") wins; otherwise follow the OS setting (360 standard).
// Imported first in main.tsx so the theme is set before the app renders.
export type Theme = "light" | "dark";
export const THEME_KEY = "f360-theme";

type Storage = { getItem(k: string): string | null; setItem(k: string, v: string): void } | null | undefined;
type Win = { matchMedia?: (q: string) => { matches: boolean } } | null | undefined;

export function storedTheme(storage: Storage): Theme | null {
  try {
    const v = storage?.getItem(THEME_KEY);
    return v === "light" || v === "dark" ? v : null;
  } catch {
    return null;
  }
}

export function osTheme(win: Win): Theme {
  try {
    return win?.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  } catch {
    return "light";
  }
}

export const initialTheme = (storage: Storage, win: Win): Theme => storedTheme(storage) || osTheme(win);

export function applyTheme(theme: Theme, doc: Document = document) {
  doc.documentElement.dataset.theme = theme;
}

export function saveTheme(theme: Theme, storage: Storage) {
  try {
    storage?.setItem(THEME_KEY, theme);
  } catch {
    /* storage blocked: still switch for this page */
  }
}

function safeStorage(): Storage {
  try {
    return localStorage;
  } catch {
    return null;
  }
}

export function startTheme() {
  if (typeof document === "undefined") return;
  const ls = safeStorage();
  applyTheme(initialTheme(ls, window));
  // With no stored choice, keep following the OS when it switches between light and dark.
  try {
    matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
      if (!storedTheme(ls)) applyTheme(osTheme(window));
    });
  } catch {
    /* matchMedia unavailable */
  }
}

export function toggleTheme(): Theme {
  const next: Theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  saveTheme(next, safeStorage());
  applyTheme(next);
  return next;
}

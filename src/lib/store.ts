/**
 * Storage adapter. When the page runs as a published Claude artifact, inventory is
 * kept in the artifact's database (follows you across devices). Anywhere else
 * (local dev, a saved copy) it falls back to this browser's localStorage.
 */
import { useEffect, useState } from "react";

export type Collection = "tenants" | "apps";
type Row = { id: string } & Record<string, any>;

export interface Store {
  kind: "cloud" | "local";
  subscribe(col: Collection, cb: (rows: Row[]) => void, onError?: (msg: string) => void): () => void;
  put(col: Collection, row: Row): Promise<void>;
  remove(col: Collection, id: string): Promise<void>;
}

const LS_KEY = (c: Collection) => `f360:${c}`;

function readLocal(c: Collection): Row[] {
  try {
    return JSON.parse(localStorage.getItem(LS_KEY(c)) || "[]");
  } catch {
    return [];
  }
}

export function localStore(): Store {
  const listeners: Record<string, Set<(rows: Row[]) => void>> = { tenants: new Set(), apps: new Set() };
  const write = (c: Collection, rows: Row[]) => {
    try {
      localStorage.setItem(LS_KEY(c), JSON.stringify(rows));
    } catch {
      /* storage blocked: keep in memory only */
    }
    mem[c] = rows;
    listeners[c].forEach((l) => l(rows));
  };
  const mem: Record<Collection, Row[]> = { tenants: readLocal("tenants"), apps: readLocal("apps") };
  return {
    kind: "local",
    subscribe(c, cb) {
      listeners[c].add(cb);
      cb(mem[c]);
      return () => listeners[c].delete(cb);
    },
    async put(c, row) {
      const rows = mem[c].filter((r) => r.id !== row.id);
      write(c, [...rows, row]);
    },
    async remove(c, id) {
      write(c, mem[c].filter((r) => r.id !== id));
    },
  };
}

function cloudStore(db: any): Store {
  return {
    kind: "cloud",
    subscribe(c, cb, onError) {
      return db.collection(c).onSnapshot(
        (snap: any) => cb(snap.docs.map((d: any) => ({ ...(d.data() as object), id: d.id }))),
        (e: any) => onError?.(e?.message ?? "The saved inventory couldn't be loaded."),
      );
    },
    async put(c, row) {
      const { id, ...data } = row;
      await db.collection(c).doc(id).set(JSON.parse(JSON.stringify(data)));
    },
    async remove(c, id) {
      await db.collection(c).doc(id).delete();
    },
  };
}

let storePromise: Promise<Store> | null = null;

export function getStore(): Promise<Store> {
  if (!storePromise) {
    storePromise = (async () => {
      const claude = (window as any).claude;
      if (!claude?.use) return localStore();
      try {
        const db = await claude.use("db");
        return db ? cloudStore(db) : localStore();
      } catch {
        return localStore();
      }
    })();
  }
  return storePromise;
}

export function useStore(): Store | null {
  const [s, setS] = useState<Store | null>(null);
  useEffect(() => {
    let live = true;
    getStore().then((x) => live && setS(x));
    return () => {
      live = false;
    };
  }, []);
  return s;
}

export function useCollection<T>(store: Store | null, col: Collection) {
  const [rows, setRows] = useState<T[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!store) return;
    const timer = setTimeout(() => setRows((r) => r ?? []), 10000);
    const unsub = store.subscribe(
      col,
      (r) => {
        clearTimeout(timer);
        setRows(r as T[]);
      },
      (m) => {
        clearTimeout(timer);
        setError(m);
        setRows((r) => r ?? []);
      },
    );
    return () => {
      clearTimeout(timer);
      unsub();
    };
  }, [store, col]);
  return { rows, error };
}

/** Per-viewer convenience storage (drafts, remembered choices). */
export function usePref<T>(key: string, initial: T): [T, (v: T) => void] {
  const [v, setV] = useState<T>(() => {
    try {
      const s = localStorage.getItem("f360:pref:" + key);
      return s ? (JSON.parse(s) as T) : initial;
    } catch {
      return initial;
    }
  });
  const set = (nv: T) => {
    setV(nv);
    try {
      localStorage.setItem("f360:pref:" + key, JSON.stringify(nv));
    } catch {
      /* ignore */
    }
  };
  return [v, set];
}

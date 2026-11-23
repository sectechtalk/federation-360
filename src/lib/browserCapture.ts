/**
 * Flows recorded live by the Federation 360 Capture browser extension (extension/ in this repo).
 *
 * The extension's bridge script posts messages into this page; nothing goes over the network. Each flow holds HAR
 * entries, so it's decoded by the same code as a saved HAR file.
 */
import { useCallback, useEffect, useState } from "react";
import { parseHarEntries, type HarEntry } from "./har";
import type { FlowCapture } from "./flow";

export const EXTENSION_TAG = "f360-capture-extension";
const PAGE_TAG = "f360-page";

export interface BrowserFlow {
  id: string;
  tabTitle?: string;
  startedAt: string;
  updatedAt: number;
  entries: HarEntry[];
}

const cache = new Map<string, { n: number; capture: FlowCapture }>();

/** A flow as a capture. The same object comes back while the flow hasn't grown, so the view doesn't re-analyze. */
export function flowToCapture(f: BrowserFlow): FlowCapture {
  const hit = cache.get(f.id);
  if (hit && hit.n === f.entries.length) return hit.capture;
  const capture = parseHarEntries(f.entries, { title: f.tabTitle ? `Sign-in on ${f.tabTitle}` : "Sign-in in this browser", source: "extension", id: f.id });
  capture.startedAt = f.startedAt;
  cache.set(f.id, { n: f.entries.length, capture });
  return capture;
}

const post = (type: "hello" | "clear") => window.postMessage({ source: PAGE_TAG, type }, location.origin);

/** Whether the extension is installed on this browser, and the flows it has recorded (newest first). */
export function useBrowserCaptures() {
  const [connected, setConnected] = useState(false);
  const [version, setVersion] = useState<string>();
  const [flows, setFlows] = useState<BrowserFlow[]>([]);

  useEffect(() => {
    const on = (e: MessageEvent) => {
      if (e.source !== window || e.origin !== location.origin || e.data?.source !== EXTENSION_TAG || e.data.type !== "flows") return;
      setConnected(true);
      if (e.data.version) setVersion(e.data.version);
      if (Array.isArray(e.data.flows)) setFlows(e.data.flows);
    };
    window.addEventListener("message", on);
    post("hello");
    return () => window.removeEventListener("message", on);
  }, []);

  const clear = useCallback(() => post("clear"), []);
  return { connected, version, flows, clear };
}

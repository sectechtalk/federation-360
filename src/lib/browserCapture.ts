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

/**
 * The oldest extension this page is happy with. Since 0.2.1 the extension holds only the sign-in protocol's own form
 * fields (never a typed password) and hands sign-ins only to Federation 360's own pages. 0.2.2 lists a sign-in the
 * identity provider refuses as a sign-in of its own and names each sign-in after its app. Older ones still work,
 * with a warning.
 */
export const MIN_EXTENSION = "0.2.2";

/** Is this extension version older than the minimum? Compares the numbers, so 0.10.0 is newer than 0.2.1. */
export function extensionOutOfDate(version: string | undefined, min = MIN_EXTENSION): boolean {
  if (!version) return false; // not heard yet: every version says which it is in its first message
  const a = version.split(".").map((n) => parseInt(n, 10) || 0);
  const b = min.split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) < (b[i] ?? 0);
  }
  return false;
}

const PAGE_TAG = "f360-page";

export interface BrowserFlow {
  id: string;
  tabTitle?: string;
  startedAt: string;
  updatedAt: number;
  entries: HarEntry[];
}

const cache = new Map<string, { sig: string; capture: FlowCapture }>();

/**
 * Changes when a flow gains a hop, and also when a hop it already has changes: a token reply read inside the page can
 * arrive after the hop itself (and must show even on the last hop), and the network's copy of that hop adds the
 * request ID that finds the sign-in in Entra's log.
 */
const signature = (f: BrowserFlow) =>
  `${f.tabTitle ?? ""}#` +
  f.entries
    .map((e) => [e.request.url.length, e.request.postData?.text?.length ?? 0, (e.request.headers ?? []).map((h) => h.value.length).join("+"), e.response.status, (e.response.headers ?? []).map((h) => h.value).join("+"), e.response.content?.text?.length ?? 0].join("."))
    .join("|");

/** A flow as a capture. The same object comes back while nothing in the flow has changed, so the view doesn't re-analyze. */
export function flowToCapture(f: BrowserFlow): FlowCapture {
  const sig = signature(f);
  const hit = cache.get(f.id);
  if (hit && hit.sig === sig) return hit.capture;
  const capture = parseHarEntries(f.entries, { title: f.tabTitle ? `Sign-in on ${f.tabTitle}` : "Sign-in in this browser", source: "extension", id: f.id });
  capture.startedAt = f.startedAt;
  cache.set(f.id, { sig, capture });
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

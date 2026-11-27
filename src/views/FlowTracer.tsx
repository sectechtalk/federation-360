import { useEffect, useMemo, useState } from "react";
import { useApp } from "../components/ui";
import { ActionButton } from "../components/busy";
import { FlowView } from "../components/FlowView";
import { EntraVerdict } from "../components/EntraVerdict";
import { parseHar } from "../lib/har";
import { CAPTURE_FORMAT, KIND_LABEL, type FlowCapture } from "../lib/flow";
import { extensionOutOfDate, flowToCapture, MIN_EXTENSION, useBrowserCaptures } from "../lib/browserCapture";
import { HAR_SAMPLES } from "../data/harSamples";
import { Section, openSection } from "../components/Section";

const time = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

/**
 * The recording or example that is open. It stays open while you read a playbook and come back, so the finding and the
 * fix can be compared. Held in this tab's memory only: gone when the tab is reloaded or closed.
 */
let lastLoaded: FlowCapture | null = null;

/** The result's summary opens when you ask for a result, and the page moves to it. */
const showResult = () => openSection("flow-summary", true);

export default function FlowTracer() {
  const { toast, go } = useApp();
  const live = useBrowserCaptures();
  const [capture, setCaptureState] = useState<FlowCapture | null>(lastLoaded);
  const setCapture = (c: FlowCapture | null) => {
    lastLoaded = c;
    setCaptureState(c);
  };
  const [error, setError] = useState<string | null>(null);
  const [over, setOver] = useState(false);
  /** Which recorded sign-in is open. "latest" follows each new sign-in as it happens. */
  const [pick, setPick] = useState<string | "latest">("latest");

  const liveCaptures = useMemo(() => live.flows.map(flowToCapture), [live.flows]);
  const shown: FlowCapture | null = capture ?? (pick === "latest" ? liveCaptures[0] : liveCaptures.find((c) => c.id === pick)) ?? null;

  const load = (text: string, name: string) => {
    setError(null);
    try {
      const j = JSON.parse(text);
      // A redacted copy saved from this page or from Live test opens as-is.
      if (j?.format === CAPTURE_FORMAT) {
        setCapture(j as FlowCapture);
        showResult();
        return;
      }
    } catch {
      /* parseHar explains */
    }
    try {
      const c = parseHar(text, name);
      setCapture(c);
      if (!c.steps.length) toast("No sign-in traffic found in this recording");
      showResult();
    } catch (e: any) {
      setCapture(null);
      setError(e.message);
    }
  };

  // Ctrl+V anywhere on the page: DevTools > Network > right-click > Copy > Copy all as HAR, then paste here.
  useEffect(() => {
    const onPaste = (e: ClipboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
      const text = e.clipboardData?.getData("text") ?? "";
      if (!/^\s*\{/.test(text)) return;
      e.preventDefault();
      load(text, "Pasted from DevTools");
    };
    document.addEventListener("paste", onPaste);
    return () => document.removeEventListener("paste", onPaste);
  });

  const openFile = async (f: File | undefined) => {
    if (!f) return;
    if (f.size > 200 * 1024 * 1024) {
      setError("This file is over 200 MB. Record just the sign-in: clear the Network list, tick Preserve log, then sign in.");
      return;
    }
    load(await f.text(), f.name);
  };

  const sample = async (id: string) => {
    const s = HAR_SAMPLES.find((x) => x.id === id)!;
    load(JSON.stringify(await s.build()), `Example: ${s.label}`);
  };

  const openLive = (id: string | "latest") => {
    toast(id === "latest" ? "Following new sign-ins: the newest one opens by itself" : "Opening that sign-in below");
    setCapture(null);
    setError(null);
    setPick(id);
    showResult();
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Flow tracer</h1>
          <p>Every hop between the app, your browser and the identity provider, with each SAML message and token decoded and anything wrong flagged. With the Federation 360 Capture extension, sign-ins appear here by themselves as they happen.</p>
        </div>
        <button className="btn" onClick={() => go("learn", { section: "flow-training" })}>New here? Take the training</button>
      </div>

      {live.connected && extensionOutOfDate(live.version) && (
        <div className="callout warn" role="alert">
          <strong>Reload the capture extension.</strong> This browser is running Federation 360 Capture {live.version}, and this page expects {MIN_EXTENSION} or later.
          Open <span className="mono">edge://extensions</span> or <span className="mono">chrome://extensions</span>, click <strong>Reload</strong> on the Federation 360 Capture card (in Chrome it is the circular arrow), then reload this page.
          The current version keeps only the sign-in's own fields from a posted form, never a typed password, hands sign-ins only to Federation 360's own pages, and lists every sign-in attempt on its own. Reloading also empties what the older version was holding.
        </div>
      )}

      {live.connected ? (
        <Section className="panel stack" aria-label="Sign-ins in this browser">
          <div className="spread">
            <h2>Sign-ins in this browser</h2>
            <span className="row">
              <span className="chip" style={{ color: "var(--ok)" }}>● Capturing</span>
              <span className="small muted" role="status">{liveCaptures.length === 0 ? "No sign-ins yet" : `${liveCaptures.length} sign-in${liveCaptures.length === 1 ? "" : "s"}`}</span>
            </span>
          </div>
          <div className="spread">
            <div className="row">
              <span className="small muted">Federation 360 Capture {live.version} is recording sign-ins in this browser, including the tokens apps fetch in the background. Sign in to any app in another tab or window and it appears here.</span>
            </div>
            <div className="row">
              <button className="btn sm" onClick={() => openLive("latest")} disabled={pick === "latest" && !capture}>Follow new sign-ins</button>
              <button className="btn sm danger" onClick={() => { const n = live.flows.length; live.clear(); toast(`Cleared ${n} sign-in${n === 1 ? "" : "s"} from the list`); }} disabled={!live.flows.length}>Clear list</button>
            </div>
          </div>
          {liveCaptures.length ? (
            <div className="row" role="list">
              {liveCaptures.map((c, i) => {
                const on = !capture && (pick === c.id || (pick === "latest" && i === 0));
                // Which app it was for, when the sign-in says, and the error that stopped it, so attempts can be told apart.
                const app = c.title.startsWith("Sign-in on ") ? c.title.slice("Sign-in on ".length) : "";
                const stopped = c.steps.find((s) => s.error)?.error?.code;
                return (
                  <button key={c.id} role="listitem" className={`btn sm${on ? " on" : ""}`} onClick={() => openLive(c.id)} title={`${c.steps.length} hops`}>
                    {time(c.startedAt)} · {KIND_LABEL[c.kind]}{app && ` · ${app}`}{stopped && ` · error ${stopped}`}
                  </button>
                );
              })}
            </div>
          ) : (
            <p className="small muted" style={{ margin: 0 }}>No sign-ins yet. Open an app in another tab and sign in; the flow shows up here within a second.</p>
          )}
          <p className="small muted" style={{ margin: 0 }}>
            Tokens an app's own server asks for (a web app with a client secret or certificate) never pass through this browser, so no browser tool can show them. Entra's verdict, under each sign-in, still covers those.
          </p>
        </Section>
      ) : (
        <Section className="panel stack" aria-label="Automatic capture">
          <h2>Turn on automatic capture</h2>
          <div className="callout">
            <strong>Turn on automatic capture (one time).</strong> Load the Federation 360 Capture extension in Edge or Chrome and every sign-in appears on this page as it happens, decoded, with nothing to save or upload.
          </div>
          <details>
            <summary>How to load the extension</summary>
            <ol className="small" style={{ margin: "8px 0 0", paddingLeft: 20, display: "grid", gap: 4 }}>
              <li>Open <span className="mono">edge://extensions</span> in Edge or <span className="mono">chrome://extensions</span> in Chrome.</li>
              <li>Turn on <strong>Developer mode</strong>.</li>
              <li>Click <strong>Load unpacked</strong> and choose the <span className="mono">extension</span> folder inside your Federation 360 folder.</li>
              <li>Edge only, for InPrivate windows: click <strong>Details</strong> under Federation 360 Capture and turn on <strong>Allow in InPrivate</strong>. In Chrome the setting is <strong>Allow in Incognito</strong>.</li>
              <li>Reload this page. A green <strong>Capturing</strong> label replaces this box.</li>
            </ol>
            <p className="small muted" style={{ margin: "8px 0 0" }}>
              The extension keeps only sign-in hops (SAML messages, authorize and token calls, redirects that carry a code or token, AADSTS error pages). From a posted form it keeps only the sign-in's own fields, never a typed password. It holds the hops in browser memory until the browser closes, hands them only to Federation 360's own pages when one asks, and sends nothing over the network.
            </p>
          </details>
        </Section>
      )}

      <Section className="panel stack">
        <h2>Load a recording</h2>
        <div className="spread">
          <span className="eyebrow">Or load a recording</span>
          <div className="row">
            {HAR_SAMPLES.map((s) => (
              <ActionButton key={s.id} className="btn sm" busy="Building example…" report="toast" onClick={async () => { await sample(s.id); return `Loaded example: ${s.label}`; }}>{s.label}</ActionButton>
            ))}
          </div>
        </div>
        <label
          className={`dropzone${over ? " over" : ""}`}
          onDragOver={(e) => { e.preventDefault(); setOver(true); }}
          onDragLeave={() => setOver(false)}
          onDrop={(e) => { e.preventDefault(); setOver(false); openFile(e.dataTransfer.files[0]); }}
        >
          <strong>Press Ctrl+V to paste a recording, drop a .har recording file (HTTP Archive) here, or click to choose one</strong>
          <span className="small muted">Read in this tab only. Nothing is uploaded or saved.</span>
          <input type="file" accept=".har,.json,application/json" style={{ display: "none" }} onChange={(e) => openFile(e.target.files?.[0])} />
        </label>
        <details>
          <summary>Without the extension: copy a sign-in from the browser's developer tools</summary>
          <ol className="small" style={{ margin: "8px 0 0", paddingLeft: 20, display: "grid", gap: 4 }}>
            <li>Go to the app's address, press F12 and open the <strong>Network</strong> tab.</li>
            <li>Tick <strong>Preserve log</strong>. Without it the list clears at every redirect and the SAML post is lost.</li>
            <li>Sign in to the app as you normally would, until you see the app or the error.</li>
            <li>Right-click anywhere in the request list and choose <strong>Copy</strong> &gt; <strong>Copy all as HAR (sanitized)</strong>. HAR stands for HTTP Archive, the browser's standard recording of network traffic. Older versions call it <strong>Copy all as HAR</strong>. Sanitized leaves out cookies and the API call tokens, and keeps every SAML message and sign-in step.</li>
            <li>Come back to this page and press <strong>Ctrl+V</strong>.</li>
          </ol>
          <p className="small muted" style={{ margin: "8px 0 0" }}>
            A recording holds live session cookies and tokens. Treat it like a password: don't email it or attach it to tickets. To share what you found, use <strong>Download redacted copy</strong> below; it keeps only the sign-in hops and removes codes, token signatures and SAML signature values.
          </p>
        </details>
      </Section>

      {error && <div className="callout warn">{error}</div>}
      {shown && <EntraVerdict key={shown.id} capture={shown} />}
      {shown && <FlowView capture={shown} />}
    </div>
  );
}

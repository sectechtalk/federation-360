import { useState } from "react";
import { useApp } from "../components/ui";
import { FlowView } from "../components/FlowView";
import { parseHar } from "../lib/har";
import { CAPTURE_FORMAT, type FlowCapture } from "../lib/flow";
import { HAR_SAMPLES } from "../data/harSamples";

export default function FlowTracer() {
  const { toast } = useApp();
  const [capture, setCapture] = useState<FlowCapture | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [over, setOver] = useState(false);

  const load = (text: string, name: string) => {
    setError(null);
    try {
      const j = JSON.parse(text);
      // A redacted copy saved from this page or from Live test opens as-is.
      if (j?.format === CAPTURE_FORMAT) {
        setCapture(j as FlowCapture);
        return;
      }
    } catch {
      /* parseHar explains */
    }
    try {
      const c = parseHar(text, name);
      setCapture(c);
      if (!c.steps.length) toast("No sign-in traffic found in this file");
    } catch (e: any) {
      setCapture(null);
      setError(e.message);
    }
  };

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

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Flow tracer</h1>
          <p>Record a sign-in in your browser and drop the recording here. Federation 360 lays out every hop between the app, your browser and the identity provider, decodes each SAML message and token, and flags what's wrong.</p>
        </div>
      </div>

      <section className="panel stack">
        <div className="spread">
          <span className="eyebrow">Try an example</span>
          <div className="row">
            {HAR_SAMPLES.map((s) => (
              <button key={s.id} className="btn sm" onClick={() => sample(s.id)}>{s.label}</button>
            ))}
          </div>
        </div>
        <label
          className={`dropzone${over ? " over" : ""}`}
          onDragOver={(e) => { e.preventDefault(); setOver(true); }}
          onDragLeave={() => setOver(false)}
          onDrop={(e) => { e.preventDefault(); setOver(false); openFile(e.dataTransfer.files[0]); }}
        >
          <strong>Drop a .har file here, or click to choose one</strong>
          <span className="small muted">The file is read in this tab only. Nothing is uploaded or saved.</span>
          <input type="file" accept=".har,.json,application/json" style={{ display: "none" }} onChange={(e) => openFile(e.target.files?.[0])} />
        </label>
        <details>
          <summary>How to record a sign-in (Edge or Chrome)</summary>
          <ol className="small" style={{ margin: "8px 0 0", paddingLeft: 20, display: "grid", gap: 4 }}>
            <li>Open a new InPrivate (Edge) or Incognito (Chrome) window, so an existing session doesn't skip the sign-in.</li>
            <li>Go to the app's address, press F12 and open the <strong>Network</strong> tab.</li>
            <li>Tick <strong>Preserve log</strong>. Without it the list clears at every redirect and the SAML post is lost.</li>
            <li>Sign in to the app as you normally would, until you see the app or the error.</li>
            <li>Right-click anywhere in the request list and choose <strong>Save all as HAR with content</strong>.</li>
            <li>Drop the saved file above.</li>
          </ol>
          <p className="small muted" style={{ margin: "8px 0 0" }}>
            A HAR file holds live session cookies and tokens. Treat it like a password: don't email it or attach it to tickets. To share what you found, use <strong>Download redacted copy</strong> below; it keeps only the sign-in hops and removes codes, token signatures and SAML signature values.
          </p>
        </details>
      </section>

      {error && <div className="callout warn">{error}</div>}
      {capture && <FlowView capture={capture} />}
    </div>
  );
}

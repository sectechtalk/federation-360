import { useEffect, useState } from "react";
import { useApp, AppPicker, FindingList, SummaryBar, CodeBlock, Seg } from "../components/ui";
import { ActionButton } from "../components/busy";
import { checkSaml, decodeSamlInput, parseSaml, type ParsedSaml } from "../lib/saml";
import { SAML_SAMPLES } from "../data/samples";
import type { Finding } from "../lib/types";

const prettyXml = (xml: string) => {
  let out = "";
  let pad = 0;
  xml
    .replace(/>\s*</g, "><")
    .replace(/(>)(<)(\/*)/g, "$1\n$2$3")
    .split("\n")
    .forEach((line) => {
      if (/^<\/\w/.test(line)) pad = Math.max(pad - 1, 0);
      out += "  ".repeat(pad) + line + "\n";
      if (/^<\w[^>]*[^/]>.*$/.test(line) && !/<\/\w/.test(line)) pad++;
    });
  return out.trim();
};

const d = (x?: Date) => (x ? x.toISOString().replace(".000", "") : "—");

export default function SamlTool() {
  const { params, apps } = useApp();
  const [input, setInput] = useState("");
  const [appId, setAppId] = useState(params.app ?? "");
  const [evalMode, setEvalMode] = useState<"now" | "issued">("now");
  const [skew, setSkew] = useState("300");
  const [parsed, setParsed] = useState<ParsedSaml | null>(null);
  const [xml, setXml] = useState("");
  const [steps, setSteps] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [sampleNote, setSampleNote] = useState<string | null>(null);

  const loadSample = async (id: string) => {
    const s = SAML_SAMPLES.find((x) => x.id === id)!;
    setInput(await s.build());
    setAppId(s.appId);
    setEvalMode("now");
    setSampleNote(`Example loaded: ${s.label}. Fictional data, generated just now.`);
  };

  // Open with a working example so the screen shows what it does.
  useEffect(() => {
    if (!input && !params.app) loadSample("healthy");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let live = true;
    (async () => {
      if (!input.trim()) {
        setParsed(null);
        setError(null);
        return;
      }
      try {
        const r = await decodeSamlInput(input);
        const p = await parseSaml(r.xml);
        if (!live) return;
        setXml(r.xml);
        setSteps(r.steps);
        setParsed(p);
        setError(null);
      } catch (e: any) {
        if (!live) return;
        setParsed(null);
        setError(e.message);
      }
    })();
    return () => {
      live = false;
    };
  }, [input]);

  const app = apps.find((a) => a.id === appId);
  const at = evalMode === "issued" && parsed?.issueInstant ? new Date(parsed.issueInstant.getTime() + 1000) : new Date();
  const findings: Finding[] = parsed
    ? checkSaml(parsed, app ? { spEntityId: app.saml.entityId, acsUrl: app.saml.acsUrl, idpEntityId: app.saml.idpEntityId, certThumbprint: app.saml.certThumbprint } : {}, { at, skewSeconds: Number(skew) || 0 })
    : [];
  const a = parsed?.assertion;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>SAML decoder</h1>
          <p>Paste a SAMLResponse or SAMLRequest in any form: base64 from the browser's Network tab, a full URL, or raw XML. It decodes it, explains each part, and compares it with the app in your inventory.</p>
        </div>
      </div>

      <section className="panel stack">
        <div className="spread">
          <span className="eyebrow">Try an example</span>
          <div className="row">
            {SAML_SAMPLES.map((s) => <ActionButton key={s.id} className="btn sm" busy="Loading…" report="toast" onClick={async () => { await loadSample(s.id); return `Loaded example: ${s.label}`; }}>{s.label}</ActionButton>)}
          </div>
        </div>
        <label className="field" htmlFor="saml-in">
          <span>SAML message</span>
          <textarea id="saml-in" className="input" rows={6} value={input} onChange={(e) => { setInput(e.target.value); setSampleNote(null); }} placeholder="PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPS... or https://login.microsoftonline.com/.../saml2?SAMLRequest=..." spellCheck={false} />
          <span className="hint">
            {sampleNote ?? "How to capture: open developer tools (F12) > Network > tick Preserve log > sign in > select the POST to the app's ACS URL > Payload > copy SAMLResponse."}
          </span>
        </label>
        <div className="grid-3">
          <AppPicker id="saml-app" value={appId} onChange={setAppId} protocols={["saml"]} />
          <label className="field">
            <span>Check time conditions as of</span>
            <Seg label="Evaluation time" value={evalMode} onChange={setEvalMode} options={[{ v: "now", l: "Now" }, { v: "issued", l: "When it was issued" }]} />
            <span className="hint">Use “when it was issued” for older captures.</span>
          </label>
          <label className="field" htmlFor="saml-skew">
            <span>Allowed clock skew (seconds)</span>
            <input id="saml-skew" className="input" inputMode="numeric" value={skew} onChange={(e) => setSkew(e.target.value)} />
          </label>
        </div>
      </section>

      {error && <div className="callout warn">{error}</div>}

      {parsed && (
        <>
          <section className="stack">
            <div className="spread">
              <h2>{parsed.kind === "AuthnRequest" ? "Request findings" : "Findings"}</h2>
              <SummaryBar findings={findings} />
            </div>
            {!app && <p className="small muted">Pick an app above to compare Audience, ACS, Issuer and certificate with your inventory.</p>}
            <FindingList findings={findings} />
          </section>

          <div className="grid-2">
            <section className="panel">
              <div className="panel-head"><h2>What's inside</h2><span className="sub">{parsed.kind}</span></div>
              <dl className="kv">
                <dt>Issuer</dt><dd>{a?.issuer || parsed.issuer || "—"}</dd>
                <dt>Destination</dt><dd>{parsed.destination || "—"}</dd>
                <dt>IssueInstant</dt><dd>{d(parsed.issueInstant)}</dd>
                <dt>InResponseTo</dt><dd>{parsed.inResponseTo || "—"}</dd>
                {parsed.request && (
                  <>
                    <dt>ACS URL requested</dt><dd>{parsed.request.acsUrl || "—"}</dd>
                    <dt>Binding</dt><dd>{parsed.request.protocolBinding.split(":").pop() || "—"}</dd>
                    <dt>NameID policy</dt><dd>{parsed.request.nameIdPolicy || "—"}</dd>
                    <dt>AuthnContext</dt><dd>{parsed.request.requestedAuthnContext.join(", ") || "none requested"}</dd>
                  </>
                )}
                {a && (
                  <>
                    <dt>NameID</dt><dd>{a.nameId}</dd>
                    <dt>NameID format</dt><dd>{a.nameIdFormat || "—"}</dd>
                    <dt>Audience</dt><dd>{a.audiences.join(", ") || "—"}</dd>
                    <dt>Recipient</dt><dd>{a.recipient || "—"}</dd>
                    <dt>Valid from</dt><dd>{d(a.notBefore)}</dd>
                    <dt>Valid until</dt><dd>{d(a.notOnOrAfter)}</dd>
                    <dt>Authn context</dt><dd>{a.authnContext || "—"}</dd>
                    <dt>Session index</dt><dd>{a.sessionIndex || "—"}</dd>
                  </>
                )}
              </dl>
            </section>
            <section className="panel stack">
              <div className="panel-head"><h2>Signature</h2><span className="sub">{parsed.signatures.length} found</span></div>
              {parsed.signatures.length === 0 && <p className="muted">No XML signature in this message.{parsed.kind === "AuthnRequest" ? " Requests are often unsigned; that's normal unless the IdP requires signed requests." : ""}</p>}
              {parsed.signatures.map((s, i) => (
                <dl className="kv" key={i}>
                  <dt>Signs</dt><dd>{s.location}</dd>
                  <dt>Algorithm</dt><dd>{s.signatureAlgorithm.split("#").pop()}</dd>
                  {s.cert && (
                    <>
                      <dt>Certificate</dt><dd>{s.cert.subject}</dd>
                      <dt>Expires</dt><dd>{s.cert.notAfter.toISOString().slice(0, 10)} ({s.cert.daysLeft} days)</dd>
                      <dt>SHA-1 thumbprint</dt><dd>{s.cert.sha1}</dd>
                      <dt>SHA-256</dt><dd>{s.cert.sha256}</dd>
                    </>
                  )}
                </dl>
              ))}
            </section>
          </div>

          {a && a.attributes.length > 0 && (
            <section className="stack">
              <h2>Attributes (claims)</h2>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Name</th><th>Value(s)</th></tr></thead>
                  <tbody>
                    {a.attributes.map((x) => (
                      <tr key={x.name}><td className="mono small" style={{ overflowWrap: "anywhere" }}>{x.name}</td><td className="mono small" style={{ overflowWrap: "anywhere" }}>{x.values.join("\n")}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          <details>
            <summary>Decoded XML</summary>
            <p className="small muted" style={{ margin: "6px 0" }}>{steps.join(" ")}</p>
            <CodeBlock code={prettyXml(xml)} />
          </details>
        </>
      )}
    </div>
  );
}

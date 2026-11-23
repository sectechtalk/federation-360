import { useEffect, useState } from "react";
import { useApp, AppPicker, FindingList, SummaryBar, CodeBlock, Seg, Sev } from "../components/ui";
import { checkJwt, CLAIM_HELP, decodeJwt, verifyJwt, type DecodedJwt, type VerifyResult } from "../lib/jwt";
import { makeJwtSample } from "../data/samples";
import { ActionButton } from "../components/busy";

const TIME_CLAIMS = ["exp", "nbf", "iat", "auth_time"];

export default function JwtTool() {
  const { params, apps } = useApp();
  const [input, setInput] = useState("");
  const [appId, setAppId] = useState(params.app ?? "");
  const [evalMode, setEvalMode] = useState<"now" | "issued">("now");
  const [keys, setKeys] = useState("");
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const loadSample = async (kind: "id" | "access" | "graph") => {
    const s = await makeJwtSample(kind);
    setInput(s.token);
    setKeys(s.jwks);
    setAppId(s.appId);
    setVerify(null);
    setNote(
      kind === "id"
        ? "Example ID token, signed just now with a throwaway key. Its public key is in the JWKS box below."
        : kind === "access"
          ? "Example access token for a custom API. It expired a couple of minutes ago and its audience doesn't match the app."
          : "Example app-only Microsoft Graph token from a client credentials flow.",
    );
  };

  useEffect(() => {
    if (!input && !params.app) loadSample("id");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  let t: DecodedJwt | null = null;
  let error: string | null = null;
  if (input.trim()) {
    try {
      t = decodeJwt(input);
    } catch (e: any) {
      error = e.message;
    }
  }
  const app = apps.find((a) => a.id === appId);
  const at = evalMode === "issued" && typeof t?.payload.iat === "number" ? new Date(t.payload.iat * 1000 + 1000) : new Date();
  const findings = t ? checkJwt(t, app ? { audience: app.oidc.audience, issuer: app.oidc.issuer, clientId: app.oidc.clientId } : {}, at, 300) : [];
  const parts = t?.raw.split(".") ?? [];

  const runVerify = async () => {
    if (!t) throw new Error("Paste a token first.");
    const r = await verifyJwt(t, keys.trim());
    setVerify(r);
    if (!r.ok) throw new Error("Signature not verified. See the reason below.");
    return "Signature verified";
  };
  const sample = (kind: "id" | "access" | "graph", label: string) => async () => {
    await loadSample(kind);
    return `Loaded: ${label}`;
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>JWT decoder</h1>
          <p>Paste an ID token or access token. It explains every claim, checks issuer, audience and expiry against your app, and verifies the signature with the identity provider's public keys.</p>
        </div>
      </div>

      <section className="panel stack">
        <div className="spread">
          <span className="eyebrow">Try an example</span>
          <div className="row">
            <ActionButton className="btn sm" busy="Signing sample…" report="toast" onClick={sample("id", "Valid ID token")}>Valid ID token</ActionButton>
            <ActionButton className="btn sm" busy="Signing sample…" report="toast" onClick={sample("access", "Expired API token")}>Expired API token</ActionButton>
            <ActionButton className="btn sm" busy="Signing sample…" report="toast" onClick={sample("graph", "Graph app-only token")}>Graph app-only token</ActionButton>
          </div>
        </div>
        <label className="field" htmlFor="jwt-in">
          <span>Token</span>
          <textarea id="jwt-in" className="input" rows={5} value={input} onChange={(e) => { setInput(e.target.value); setVerify(null); setNote(null); }} placeholder="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..." spellCheck={false} />
          <span className="hint">{note ?? "A 'Bearer …' header, a URL fragment with id_token=…, or the bare token all work. Tokens are bearer credentials: only paste test tokens or expired ones, and never share them."}</span>
        </label>
        <div className="grid-2">
          <AppPicker id="jwt-app" value={appId} onChange={setAppId} protocols={["oidc", "oauth"]} />
          <label className="field">
            <span>Check expiry as of</span>
            <Seg label="Evaluation time" value={evalMode} onChange={setEvalMode} options={[{ v: "now", l: "Now" }, { v: "issued", l: "When it was issued" }]} />
          </label>
        </div>
      </section>

      {error && <div className="callout warn">{error}</div>}

      {t && (
        <>
          <div className="jwt-raw panel">
            <span className="jwt-h">{parts[0]}</span>.<span className="jwt-p">{parts[1]}</span>.<span className="jwt-s">{parts[2]}</span>
            <div className="row small" style={{ marginTop: 8 }}>
              <span className="jwt-h">■ header</span><span className="jwt-p">■ payload (claims)</span><span className="jwt-s">■ signature</span>
            </div>
          </div>

          <section className="stack">
            <div className="spread"><h2>Findings</h2><SummaryBar findings={findings} /></div>
            <FindingList findings={findings} />
          </section>

          <section className="stack">
            <h2>Claims</h2>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Claim</th><th>Value</th><th>Meaning</th></tr></thead>
                <tbody>
                  {Object.entries(t.payload).map(([k, v]) => (
                    <tr key={k}>
                      <td className="claim-key">{k}</td>
                      <td className="mono small" style={{ overflowWrap: "anywhere", maxWidth: 360 }}>
                        {typeof v === "object" ? JSON.stringify(v) : String(v)}
                        {TIME_CLAIMS.includes(k) && typeof v === "number" && <div className="muted">{new Date(v * 1000).toISOString().replace(".000", "")}</div>}
                      </td>
                      <td className="small muted">{CLAIM_HELP[k] ?? ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <div className="grid-2">
            <section className="panel stack">
              <div className="panel-head"><h2>Header</h2></div>
              <CodeBlock code={JSON.stringify(t.header, null, 2)} />
            </section>
            <section className="panel stack">
              <div className="panel-head"><h2>Verify signature</h2>{verify && <Sev s={verify.ok ? "ok" : "critical"} label={verify.ok ? "Valid" : "Failed"} />}</div>
              <p className="small muted">
                {/^HS/.test(t.header.alg)
                  ? "This token uses a shared secret. Paste the secret to check it."
                  : "Paste the JWKS from the issuer's jwks_uri (find it in the Metadata checker). For Entra: https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"}
              </p>
              <textarea aria-label="JWKS or secret" className="input" rows={6} value={keys} onChange={(e) => { setKeys(e.target.value); setVerify(null); }} placeholder='{"keys":[{"kty":"RSA","kid":"…","n":"…","e":"AQAB"}]}' spellCheck={false} />
              <div className="row"><ActionButton className="btn primary" busy="Verifying…" onClick={runVerify} disabled={!keys.trim()}>Verify</ActionButton></div>
              {verify && <div className={`callout ${verify.ok ? "" : "warn"} small`}>{verify.message}</div>}
            </section>
          </div>
        </>
      )}
    </div>
  );
}

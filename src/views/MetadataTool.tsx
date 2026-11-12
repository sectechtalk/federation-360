import { Fragment, useEffect, useState } from "react";
import { useApp, FindingList, SummaryBar, Seg } from "../components/ui";
import { checkDiscovery, checkSamlMetadata, jwksSummary, parseSamlMetadata, wellKnownUrls, type SamlMetadata } from "../lib/metadata";
import { SAMPLE_DISCOVERY, SAMPLE_IDP_METADATA } from "../data/samples";
import { PLATFORM_LABEL, type Finding } from "../lib/types";
import type { CertInfo } from "../lib/x509";

type Mode = "saml" | "oidc" | "jwks";

export default function MetadataTool() {
  const { tenants, params } = useApp();
  const [mode, setMode] = useState<Mode>("saml");
  const [text, setText] = useState("");
  const [url, setUrl] = useState("");
  const [fetchMsg, setFetchMsg] = useState<string | null>(null);
  const [tenantId, setTenantId] = useState(params.tenant ?? "");
  const [samlMd, setSamlMd] = useState<SamlMetadata | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [disc, setDisc] = useState<Record<string, any> | null>(null);
  const [keys, setKeys] = useState<{ kid: string; kty: string; alg?: string; use?: string; cert?: CertInfo }[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isSample, setIsSample] = useState(false);

  const tenant = tenants.find((t) => t.id === tenantId) ?? tenants.find((t) => t.platform === "entra");
  const urls = tenant ? wellKnownUrls(tenant.platform, tenant.tenantRef) : wellKnownUrls("entra", "");

  useEffect(() => {
    if (!text) {
      setText(SAMPLE_IDP_METADATA);
      setIsSample(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let live = true;
    (async () => {
      setError(null);
      setSamlMd(null);
      setDisc(null);
      setKeys([]);
      setFindings([]);
      if (!text.trim()) return;
      try {
        if (mode === "saml") {
          const m = await parseSamlMetadata(text);
          if (!live) return;
          setSamlMd(m);
          setFindings(checkSamlMetadata(m));
        } else if (mode === "oidc") {
          const d = JSON.parse(text);
          if (!live) return;
          setDisc(d);
          setFindings(checkDiscovery(d, url || undefined));
        } else {
          const j = JSON.parse(text);
          const k = await jwksSummary(j);
          if (!live) return;
          setKeys(k);
          const f: Finding[] = [{ severity: k.length ? "ok" : "critical", title: `${k.length} signing key${k.length === 1 ? "" : "s"} published` }];
          k.forEach((x) => {
            if (x.cert && x.cert.daysLeft < 0) f.push({ severity: "warn", title: `Key ${x.kid}: certificate wrapper expired`, detail: "Entra keeps publishing keys with expired x5c certificates; token validation uses the key itself, so this is usually harmless." });
          });
          f.push({ severity: "info", title: "Keys roll over", detail: "Apps should cache keys and re-fetch the JWKS when a token arrives with an unknown kid. Never pin a single key." });
          setFindings(f);
        }
      } catch (e: any) {
        if (!live) return;
        setError(mode === "saml" ? e.message : "This isn't valid JSON. Paste the whole document.");
      }
    })();
    return () => {
      live = false;
    };
  }, [text, mode, url]);

  const switchMode = (m: Mode) => {
    setMode(m);
    setIsSample(false);
    if (m === "oidc") {
      setText(SAMPLE_DISCOVERY);
      setIsSample(true);
    } else if (m === "saml") {
      setText(SAMPLE_IDP_METADATA);
      setIsSample(true);
    } else setText("");
  };

  const tryFetch = async (u: string, m: Mode) => {
    setUrl(u);
    setMode(m);
    setFetchMsg("Fetching…");
    try {
      const r = await fetch(u);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setText(await r.text());
      setIsSample(false);
      setFetchMsg("Loaded from " + u);
    } catch {
      setFetchMsg("This page can't reach that site directly (browser security blocks it). Open the link, copy everything on the page, and paste it below.");
    }
  };

  const modeFor = (label: string): Mode => (/SAML|Federation metadata/i.test(label) ? "saml" : /JWKS|keys/i.test(label) ? "jwks" : "oidc");

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Metadata checker</h1>
          <p>Check an identity provider's or app's published configuration: SAML metadata (entity ID, endpoints, certificates and expiry), OIDC discovery documents, and JWKS signing keys.</p>
        </div>
      </div>

      <section className="panel stack">
        <div className="spread">
          <h3>Where to find it</h3>
          {tenants.length > 0 && (
            <select aria-label="Tenant" className="input" style={{ width: 260 }} value={tenant?.id ?? ""} onChange={(e) => setTenantId(e.target.value)}>
              {tenants.map((t) => <option key={t.id} value={t.id}>{t.name} ({PLATFORM_LABEL[t.platform]})</option>)}
            </select>
          )}
        </div>
        {urls.length ? (
          <div className="table-wrap">
            <table>
              <tbody>
                {urls.map((u) => (
                  <tr key={u.url}>
                    <td style={{ whiteSpace: "nowrap" }}>{u.label}</td>
                    <td className="mono small" style={{ overflowWrap: "anywhere" }}><a href={u.url} target="_blank" rel="noreferrer">{u.url}</a></td>
                    <td><button className="btn sm" onClick={() => tryFetch(u.url, modeFor(u.label))}>Load</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="muted small">{tenant?.platform === "aws-idc" ? "AWS IAM Identity Center doesn't publish metadata at a public URL. Download it from IAM Identity Center > Settings > Identity source > Actions > Change identity source, and paste it below." : "No standard URLs for this platform. Paste the document below."}</p>
        )}
        {fetchMsg && <p className="small muted">{fetchMsg}</p>}
      </section>

      <section className="panel stack">
        <div className="spread">
          <Seg label="Document type" value={mode} onChange={switchMode} options={[{ v: "saml", l: "SAML metadata (XML)" }, { v: "oidc", l: "OIDC discovery (JSON)" }, { v: "jwks", l: "JWKS keys (JSON)" }]} />
          {isSample && <span className="example-flag">Example document</span>}
        </div>
        <textarea aria-label="Metadata document" className="input" rows={8} value={text} onChange={(e) => { setText(e.target.value); setIsSample(false); }} spellCheck={false} placeholder={mode === "saml" ? "<EntityDescriptor …>" : "{ … }"} />
      </section>

      {error && <div className="callout warn">{error}</div>}

      {findings.length > 0 && (
        <section className="stack">
          <div className="spread"><h2>Findings</h2><SummaryBar findings={findings} /></div>
          <FindingList findings={findings} />
        </section>
      )}

      {samlMd && (
        <div className="grid-2">
          <section className="panel stack">
            <div className="panel-head"><h2>Endpoints</h2><span className="sub">{samlMd.roles.join(" + ")}</span></div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Service</th><th>Binding</th><th>Location</th></tr></thead>
                <tbody>
                  {samlMd.endpoints.map((e, i) => (
                    <tr key={i}><td>{e.kind}</td><td>{e.binding}</td><td className="mono small" style={{ overflowWrap: "anywhere" }}>{e.location}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
            {samlMd.nameIdFormats.length > 0 && <p className="small"><strong>NameID formats:</strong> {samlMd.nameIdFormats.map((n) => n.split(":").pop()).join(", ")}</p>}
          </section>
          <section className="panel stack">
            <div className="panel-head"><h2>Certificates</h2><span className="sub">{samlMd.certs.length}</span></div>
            {samlMd.certs.map((c, i) => (
              <dl className="kv" key={i}>
                <dt>Use</dt><dd>{c.role} {c.use}</dd>
                {c.cert ? (
                  <>
                    <dt>Subject</dt><dd>{c.cert.subject}</dd>
                    <dt>Valid</dt><dd>{c.cert.notBefore.toISOString().slice(0, 10)} → {c.cert.notAfter.toISOString().slice(0, 10)}</dd>
                    <dt>Days left</dt><dd>{c.cert.daysLeft}</dd>
                    <dt>SHA-1</dt><dd>{c.cert.sha1}</dd>
                    <dt>Key</dt><dd>{c.cert.keyType}, {c.cert.signatureAlgorithm}</dd>
                  </>
                ) : <><dt>Error</dt><dd>{c.error}</dd></>}
              </dl>
            ))}
          </section>
        </div>
      )}

      {disc && (
        <section className="panel">
          <div className="panel-head"><h2>Discovery document</h2></div>
          <dl className="kv">
            {["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "end_session_endpoint", "device_authorization_endpoint"].filter((k) => disc[k]).map((k) => (
              <Fragment key={k}><dt>{k}</dt><dd>{disc[k]}</dd></Fragment>
            ))}
            {["scopes_supported", "response_types_supported", "grant_types_supported", "token_endpoint_auth_methods_supported", "claims_supported"].filter((k) => disc[k]).map((k) => (
              <Fragment key={k}><dt>{k}</dt><dd>{[].concat(disc[k]).join(", ")}</dd></Fragment>
            ))}
          </dl>
          {disc.jwks_uri && <div className="row" style={{ marginTop: 12 }}><button className="btn sm" onClick={() => tryFetch(disc.jwks_uri, "jwks")}>Load the JWKS</button></div>}
        </section>
      )}

      {keys.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>kid</th><th>Type</th><th>Use</th><th>Cert subject</th><th>Cert expires</th></tr></thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.kid}><td className="mono small">{k.kid}</td><td>{k.kty}{k.alg ? ` / ${k.alg}` : ""}</td><td>{k.use ?? "—"}</td><td className="small">{k.cert?.subject ?? "—"}</td><td className="mono small">{k.cert ? k.cert.notAfter.toISOString().slice(0, 10) : "—"}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

import { useEffect, useState } from "react";
import { useApp, FindingList, SummaryBar, CodeBlock, Sev } from "../components/ui";
import { checkScim, describeScim, flattenScim, KIND_LABEL, parseScim, parseScimPath, SCIM_ATTR_HELP, userIdentifiers, type ScimMessage } from "../lib/scim";
import { SCIM_SAMPLES } from "../data/scimSamples";

const opText = (o: any) => {
  const op = String(o?.op ?? "").toLowerCase();
  const path = o?.path ? String(o.path) : "";
  const p = path ? parseScimPath(path) : null;
  const target = !path
    ? "several attributes at once"
    : p?.filter
      ? `the ${p.attr} entry whose ${p.filter.attr} is “${p.filter.value}”${p.sub ? ` (its ${p.sub})` : ""}`
      : path;
  if (op === "remove") return `Remove ${target}`;
  if (op === "add") return `Add to ${target}`;
  if (op === "replace") return typeof o?.value === "object" ? `Set ${target}` : `Set ${target} to ${JSON.stringify(o?.value)}`;
  return "Unknown operation";
};

export default function ScimTool() {
  const { params, apps, go } = useApp();
  const [input, setInput] = useState("");
  const [signInId, setSignInId] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const [sample, setSample] = useState("");

  const load = (id: string) => {
    const s = SCIM_SAMPLES.find((x) => x.id === id)!;
    setInput(s.text);
    setSignInId(s.signInId ?? "");
    setNote(s.note);
    setSample(id);
  };

  useEffect(() => {
    if (!input) load("create");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  let m: ScimMessage | null = null;
  let error: string | null = null;
  if (input.trim()) {
    try {
      m = parseScim(input);
    } catch (e: any) {
      error = e.message;
    }
  }
  const findings = m ? checkScim(m, { signInId }) : [];
  const app = apps.find((a) => a.id === params.app);
  const record = m?.kind === "user" ? m.body : m?.kind === "list" && m.body?.Resources?.length === 1 ? m.body.Resources[0] : null;
  const ids = record ? userIdentifiers(record).filter((i) => i.label !== "id") : [];
  const ops: any[] = m?.kind === "patch" && Array.isArray(m.body?.Operations) ? m.body.Operations : [];
  const rows = m?.body ? flattenScim(m.body) : [];
  const disabled = record && (record.active === false || String(record.active).toLowerCase() === "false");
  const want = signInId.trim();
  const gate2 = !record || !want ? null : disabled ? "critical" : ids.some((i) => i.value === want) ? "ok" : ids.some((i) => i.value.toLowerCase() === want.toLowerCase()) ? "warn" : "critical";

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>SCIM checker</h1>
          <p>
            Paste a SCIM request or response from the Entra provisioning logs or an app's API log. It explains what the message does, checks it against the
            SCIM standard and Entra's known quirks, and compares the provisioned account with the identifier sent at sign-in.
          </p>
        </div>
        <button className="btn" onClick={() => go("playbooks", { proto: "scim" })}>SCIM playbooks</button>
      </div>

      <section className="panel stack">
        <div className="spread">
          <span className="eyebrow">Try an example</span>
          <div className="row">
            {SCIM_SAMPLES.map((s) => (
              <button key={s.id} className={`btn sm${sample === s.id ? " on" : ""}`} aria-pressed={sample === s.id} onClick={() => load(s.id)}>{s.label}</button>
            ))}
          </div>
        </div>
        <label className="field" htmlFor="scim-in">
          <span>SCIM message</span>
          <textarea id="scim-in" className="input" rows={12} value={input} onChange={(e) => { setInput(e.target.value); setNote(null); setSample(""); }} placeholder={'{\n  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],\n  "userName": "avery.lee@contoso.example"\n}'} spellCheck={false} />
          <span className="hint">{note ?? "A JSON body on its own works. You can also include the request line (PATCH /Users/123) or status line (HTTP/1.1 409) above it. Remove any Authorization header first: the bearer token is a secret."}</span>
        </label>
        <label className="field" htmlFor="scim-signin">
          <span>Identifier the app receives at sign-in (optional)</span>
          <input id="scim-signin" className="input" value={signInId} onChange={(e) => setSignInId(e.target.value)} placeholder="The SAML NameID, or the token claim the app matches on" spellCheck={false} />
          <span className="hint">
            {app?.protocol === "saml" && app.saml.nameIdSource
              ? `${app.name} sends ${app.saml.nameIdSource} as the NameID. Paste a real value from the SAML decoder.`
              : "Copy the NameID from the SAML decoder, or the preferred_username, email or sub claim from the JWT decoder."}
          </span>
        </label>
      </section>

      {error && <div className="callout warn">{error}</div>}

      {m && (
        <>
          <section className="panel stack">
            <div className="row">
              <span className="chip proto-scim">{KIND_LABEL[m.kind]}</span>
              {m.method && <span className="tag mono">{m.method} {m.path?.split("?")[0]}</span>}
              {m.status && <Sev s={m.status >= 400 ? "critical" : "ok"} label={`HTTP ${m.status}`} />}
            </div>
            <p style={{ margin: 0, fontSize: "1.05rem" }}>{describeScim(m)}</p>
          </section>

          <section className="stack">
            <div className="spread"><h2>Findings</h2><SummaryBar findings={findings} /></div>
            <FindingList findings={findings} />
          </section>

          {record && (
            <section className="panel stack">
              <div className="panel-head">
                <h2>Can this user get in?</h2>
                <span className="sub">Two separate gates</span>
              </div>
              <div className="grid-2">
                <div className="stack" style={{ gap: 6 }}>
                  <div className="spread"><strong>Gate 1: Entra lets them sign in</strong><Sev s="info" label="Check in Entra" /></div>
                  <span className="small muted">Decided by app assignment and Conditional Access. A failure here shows an AADSTS error on the Microsoft sign-in page (AADSTS50105 when the user isn't assigned). This checker can't see it; use the sign-in logs.</span>
                </div>
                <div className="stack" style={{ gap: 6 }}>
                  <div className="spread">
                    <strong>Gate 2: the app has a matching, enabled account</strong>
                    {gate2 ? <Sev s={gate2} label={gate2 === "ok" ? "Match" : gate2 === "warn" ? "Case differs" : disabled ? "Disabled" : "No match"} /> : <Sev s="info" label="Enter the sign-in identifier" />}
                  </div>
                  <span className="small muted">Decided by what SCIM wrote into the app. A failure here appears on the app's own page after Entra sign-in succeeded: “user not found” or “account disabled”.</span>
                </div>
              </div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Where</th><th>Attribute</th><th>Value</th><th>Same as sign-in?</th></tr></thead>
                  <tbody>
                    <tr>
                      <td>Sent at sign-in</td>
                      <td className="claim-key">NameID / claim</td>
                      <td className="mono small" style={{ overflowWrap: "anywhere" }}>{want || <span className="muted">not entered</span>}</td>
                      <td />
                    </tr>
                    {ids.map((i) => (
                      <tr key={i.label + i.value}>
                        <td>In the app (SCIM)</td>
                        <td className="claim-key">{i.label}</td>
                        <td className="mono small" style={{ overflowWrap: "anywhere" }}>{i.value}</td>
                        <td>{!want ? "" : i.value === want ? <Sev s="ok" label="Exact" /> : i.value.toLowerCase() === want.toLowerCase() ? <Sev s="warn" label="Case differs" /> : <Sev s="info" label="Different" />}</td>
                      </tr>
                    ))}
                    <tr>
                      <td>In the app (SCIM)</td>
                      <td className="claim-key">active</td>
                      <td className="mono small">{record.active === undefined ? "not set" : String(record.active)}</td>
                      <td>{disabled ? <Sev s="critical" label="Disabled" /> : <Sev s="ok" label="Enabled" />}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {ops.length > 0 && (
            <section className="stack">
              <h2>Operations</h2>
              <div className="table-wrap">
                <table style={{ minWidth: 620 }}>
                  <thead><tr><th className="num">#</th><th>op</th><th>path</th><th>value</th><th>In plain words</th></tr></thead>
                  <tbody>
                    {ops.map((o, i) => (
                      <tr key={i}>
                        <td className="num">{i + 1}</td>
                        <td className="claim-key">{String(o?.op ?? "")}</td>
                        <td className="mono small" style={{ overflowWrap: "anywhere" }}>{o?.path ?? <span className="muted">none</span>}</td>
                        <td className="mono small" style={{ overflowWrap: "anywhere", maxWidth: 320 }}>{o?.value === undefined ? "" : typeof o.value === "string" ? `"${o.value}"` : JSON.stringify(o.value)}</td>
                        <td className="small muted">{opText(o)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {rows.length > 0 && m.kind !== "patch" && (
            <section className="stack">
              <h2>Attributes</h2>
              <div className="table-wrap">
                <table style={{ minWidth: 560 }}>
                  <thead><tr><th>Attribute</th><th>Value</th><th>Meaning</th></tr></thead>
                  <tbody>
                    {rows.map((r) => (
                      <tr key={r.key}>
                        <td className="claim-key" style={{ overflowWrap: "anywhere" }}>{r.key.replace(/^urn:ietf:params:scim:schemas:extension:enterprise:2\.0:User\./, "enterprise:")}</td>
                        <td className="mono small" style={{ overflowWrap: "anywhere", maxWidth: 380 }}>{r.value}</td>
                        <td className="small muted">{SCIM_ATTR_HELP[r.key] ?? ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {m.filter && (
            <section className="panel stack">
              <div className="panel-head"><h2>Search filter</h2></div>
              <CodeBlock code={m.filter} />
            </section>
          )}
        </>
      )}

      <section className="panel stack">
        <div className="panel-head"><h2>Where to capture SCIM messages</h2></div>
        <ul className="plain small">
          <li><strong>Entra provisioning logs:</strong> Enterprise apps &gt; your app &gt; Provisioning &gt; Provisioning logs. Open an entry, then Troubleshooting &amp; Recommendations and Modified Properties.</li>
          <li><strong>Provision on demand:</strong> Provisioning &gt; Provision on demand. Pick one user and Entra shows each step with the request it sent and the response it got.</li>
          <li><strong>The app's side:</strong> its audit or API log, if the vendor exposes one.</li>
          <li><strong>By hand:</strong> call the app's SCIM endpoint yourself with a test token, for example GET /Users?filter=userName eq "name@example.com".</li>
        </ul>
      </section>
    </div>
  );
}

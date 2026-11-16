import { CodeBlock, ProtoChip, useApp } from "../components/ui";
import { LAB_BUILDS, LAB_REPO, LAB_STEPS } from "../data/lab";

const linkify = (text: string) =>
  text.split(/(https?:\/\/[^\s)]+)/g).map((part, i) =>
    /^https?:\/\//.test(part) ? (
      <a key={i} href={part.replace(/[.,]$/, "")} target="_blank" rel="noreferrer">{part}</a>
    ) : (
      part
    ),
  );

export default function Lab() {
  const { go } = useApp();
  const total = LAB_STEPS.reduce((n, s) => n + s.minutes, 0);
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Build your lab</h1>
          <p>
            Stand up your own free Microsoft Entra tenant with ready-made SAML, OpenID Connect and OAuth test apps, so you can run
            real sign-ins and troubleshoot them here. About {total} minutes. You create the tenant and two free accounts by hand, then a script and Terraform do the rest. Every command is copy and paste.
          </p>
        </div>
        <a className="btn primary" href={`${LAB_REPO}/tree/main/lab`} target="_blank" rel="noreferrer">Get the lab kit on GitHub ↗</a>
      </div>

      <div className="callout warn">
        <strong>Use a tenant made only for this.</strong> Never run the kit against a production tenant. It costs nothing as long as the lab tenant has no Azure subscription or paid licences.
      </div>

      <section className="stack">
        <h2>What gets built</h2>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Object</th><th>Type</th><th>What it's for</th></tr></thead>
            <tbody>
              {LAB_BUILDS.map((b) => (
                <tr key={b.name}>
                  <td className="mono nowrap">{b.name}</td>
                  <td>{b.protocol === "scim" ? <span className="tag">Group</span> : <ProtoChip p={b.protocol} />}</td>
                  <td>{b.what}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="small muted">No client secrets are created, so the Terraform state holds nothing sensitive.</p>
      </section>

      <section className="stack">
        <h2>Steps</h2>
        {LAB_STEPS.map((s, i) => (
          <div key={s.title} className="panel stack">
            <div className="spread">
              <div>
                <div className="eyebrow">Step {i + 1} of {LAB_STEPS.length}</div>
                <h3>{s.title}</h3>
              </div>
              <span className="tag">~{s.minutes} min</span>
            </div>
            <p className="muted" style={{ maxWidth: "75ch" }}>{s.why}</p>
            <ol className="actions">
              {s.actions.map((a) => <li key={a}>{linkify(a)}</li>)}
            </ol>
            {s.code?.map((c) => (
              <div key={c.title} className="stack" style={{ gap: 6 }}>
                <span className="eyebrow">{c.title}</span>
                <CodeBlock code={c.body} />
              </div>
            ))}
            {s.note && <div className="callout small">{linkify(s.note)}</div>}
          </div>
        ))}
      </section>

      <div className="row">
        <button className="btn" onClick={() => go("inventory")}>Open Inventory to import</button>
        <button className="btn" onClick={() => go("saml")}>SAML decoder</button>
        <button className="btn" onClick={() => go("jwt")}>JWT decoder</button>
        <button className="btn" onClick={() => go("scim")}>SCIM checker</button>
        <button className="btn" onClick={() => go("playbooks")}>Playbooks</button>
      </div>
    </div>
  );
}

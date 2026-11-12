import { useState } from "react";
import { useApp, ProtoChip, SequenceDiagram, Seg } from "../components/ui";
import { FLOWS, GLOSSARY, METHOD, SKILLS_MAP } from "../data/learn";
import { PROTOCOLS } from "../lib/protocols";

export default function Learn() {
  const { go } = useApp();
  const [flowId, setFlowId] = useState(FLOWS[0].id);
  const [q, setQ] = useState("");
  const flow = FLOWS.find((f) => f.id === flowId)!;
  const terms = GLOSSARY.filter((g) => !q || (g.term + g.def).toLowerCase().includes(q.toLowerCase()));

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Learn</h1>
          <p>The minimum theory you need to configure and troubleshoot federation confidently: what each protocol is for, how its messages flow, and a method that works on any sign-in problem.</p>
        </div>
      </div>

      <div className="grid-2">
        {PROTOCOLS.map((p) => (
          <section key={p.id} className="panel stack" style={p.status === "planned" ? { borderStyle: "dashed" } : undefined}>
            <div className="spread"><h3>{p.name}</h3><ProtoChip p={p.id} /></div>
            <p>{p.purpose}</p>
            <p className="small muted"><strong>Answers:</strong> {p.answers}</p>
            {p.status === "planned" && <span className="tag">Module planned</span>}
          </section>
        ))}
      </div>
      <div className="callout">
        <strong>The one distinction to remember:</strong> SAML and OIDC are about <em>authentication</em> (who is the user). OAuth is about <em>authorization</em> (what may this app do). OIDC adds an ID token on top of OAuth so one protocol can do both.
      </div>

      <section className="panel stack">
        <div className="spread">
          <h2>How the messages flow</h2>
          <Seg label="Flow" value={flowId} onChange={setFlowId} options={FLOWS.map((f) => ({ v: f.id, l: f.title.replace("SAML, ", "SAML ").replace(" sign-in", "") }))} />
        </div>
        <p style={{ maxWidth: "75ch" }}>{flow.intro}</p>
        <SequenceDiagram flow={flow} />
        <div className="callout warn small">
          <strong>Where it usually breaks:</strong>
          <ul className="plain" style={{ marginTop: 4 }}>{flow.watch.map((w) => <li key={w}>{w}</li>)}</ul>
        </div>
      </section>

      <section className="stack">
        <h2>A troubleshooting method that works every time</h2>
        <div className="grid-3">
          {METHOD.map((m, i) => (
            <div key={m.title} className="panel stack">
              <div className="eyebrow">Step {i + 1}</div>
              <h3>{m.title}</h3>
              <p className="small">{m.body}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="stack">
        <div className="spread">
          <h2>Glossary</h2>
          <input aria-label="Search glossary" className="input" style={{ width: 240 }} placeholder="Filter terms…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="table-wrap">
          <table>
            <tbody>
              {terms.map((g) => (
                <tr key={g.term}>
                  <td style={{ width: "26%" }}><strong>{g.term}</strong><div className="row" style={{ marginTop: 4 }}>{g.protocols.map((p) => <ProtoChip key={p} p={p} />)}</div></td>
                  <td>{g.def}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="stack">
        <h2>Job skills to practice here</h2>
        <p className="muted">How the IAM engineering skills in your target role map to this dashboard.</p>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Skill</th><th>Where to practice</th><th></th></tr></thead>
            <tbody>
              {SKILLS_MAP.map((s) => (
                <tr key={s.skill}>
                  <td>{s.skill}</td>
                  <td className="muted">{s.where}</td>
                  <td><button className="btn sm" onClick={() => go(s.route)}>Open</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

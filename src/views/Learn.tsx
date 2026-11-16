import { useState } from "react";
import { useApp, ProtoChip, SequenceDiagram, Seg, Field, CodeBlock } from "../components/ui";
import { FLOWS, GLOSSARY, METHOD } from "../data/learn";
import { LIFECYCLES, SCENARIO, fillLab, type LifeStage } from "../data/lifecycle";
import { PROTOCOLS } from "../lib/protocols";
import { usePref } from "../lib/store";

const GUID = /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
const STAGES: { v: LifeStage["id"]; l: string }[] = [
  { v: "create", l: "1. Create" },
  { v: "maintain", l: "2. Maintain" },
  { v: "remove", l: "3. Remove" },
];

function Lifecycle() {
  const { go, tenants } = useApp();
  const lab = tenants.find((t) => t.platform === "entra" && GUID.test(t.tenantRef) && !t.example);
  const [tenant, setTenant] = usePref("learn-lab-tenant", lab?.tenantRef ?? "");
  const [domain, setDomain] = usePref("learn-lab-domain", lab?.domain ?? "");
  const [lcId, setLcId] = usePref("learn-lifecycle", LIFECYCLES[0].id);
  const [stageId, setStageId] = usePref<LifeStage["id"]>("learn-lifecycle-stage", "create");
  const lc = LIFECYCLES.find((l) => l.id === lcId) ?? LIFECYCLES[0];
  const stageIdx = Math.max(0, lc.stages.findIndex((x) => x.id === stageId));
  const stage = lc.stages[stageIdx];
  const next = lc.stages[stageIdx + 1];
  const f = (t: string) => fillLab(t, tenant, domain);

  return (
    <section className="panel stack" id="lifecycle">
      <h2>Lifecycle: from creation to removal</h2>
      <p style={{ maxWidth: "75ch" }}>
        Every SAML, OpenID Connect, OAuth and SCIM integration lives through the same three stages. You create it, you keep it working for years, and one day you switch it off. Follow one real-world scenario through all three in your free lab tenant. Every step says where to click, what to paste and what success looks like.
      </p>
      <div className="callout">
        <strong>{SCENARIO.title}</strong>
        <p style={{ marginTop: 4 }}>{f(SCENARIO.body)}</p>
      </div>
      <h3>Your lab</h3>
      <div className="grid-2">
        <Field id="lc-tenant" label="Your lab tenant ID" value={tenant} onChange={setTenant} placeholder="00000000-0000-0000-0000-000000000000" error={tenant && !GUID.test(tenant.trim()) ? "A tenant ID is a GUID." : null} hint="Entra admin center > Overview > Tenant ID. Fills in every step below." />
        <Field id="lc-domain" label="Your lab domain" value={domain} onChange={setDomain} placeholder="yourlab.onmicrosoft.com" hint="The part after @ in lab.user1's sign-in name." />
      </div>
      <details>
        <summary><strong>Before you start</strong></summary>
        <ul className="plain small" style={{ marginTop: 6 }}>{SCENARIO.before.map((b) => <li key={b}>{f(b)}</li>)}</ul>
      </details>
      <p className="small muted">Work through it the way a real app's life goes: the Create stage of all three, then Maintain, then Remove.</p>

      <div className="spread">
        <Seg label="Protocol" value={lc.id} onChange={setLcId} options={LIFECYCLES.map((l) => ({ v: l.id, l: l.title }))} />
        <Seg label="Stage" value={stage.id} onChange={setStageId} options={STAGES} />
      </div>
      <div className="row">{lc.protocols.map((p) => <ProtoChip key={p} p={p} />)}<span className="small">{f(lc.story)}</span></div>
      <p className="muted" style={{ maxWidth: "75ch" }}>{stage.summary}</p>

      <ol className="plain stack" style={{ paddingLeft: 0 }}>
        {stage.steps.map((st, i) => (
          <li key={st.title} className="panel stack">
            <div className="eyebrow">{stage.title} · step {i + 1} of {stage.steps.length}</div>
            <h3>{st.title}</h3>
            <p className="small" style={{ maxWidth: "75ch" }}>{f(st.why)}</p>
            {st.code && (
              <div className="stack" style={{ gap: 4 }}>
                <span className="small muted">{st.code.title}</span>
                <CodeBlock code={f(st.code.body)} />
              </div>
            )}
            {st.clicks && <ol className="actions">{st.clicks.map((c) => <li key={c}>{f(c)}</li>)}</ol>}
            <div className="callout small"><strong>What success looks like:</strong> {f(st.success)}</div>
            {st.realWorld && <div className="callout warn small"><strong>At work:</strong> {f(st.realWorld)}</div>}
            {st.open && <div><button className="btn sm" onClick={() => go(st.open!.route, st.open!.params)}>{st.open.label}</button></div>}
          </li>
        ))}
      </ol>
      {next && (
        <div>
          <button className="btn primary" onClick={() => { setStageId(next.id); document.getElementById("lifecycle")?.scrollIntoView(); }}>Next: {next.title}</button>
        </div>
      )}
    </section>
  );
}

export default function Learn() {
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

      <Lifecycle />

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
    </div>
  );
}

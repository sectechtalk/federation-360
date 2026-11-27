import { useEffect, useState } from "react";
import { useApp, ProtoChip, SequenceDiagram, Seg, Field, CodeBlock } from "../components/ui";
import { FLOWS, GLOSSARY, METHOD } from "../data/learn";
import { LIFECYCLES, SCENARIO, fillLab, type LifeStage } from "../data/lifecycle";
import { TRAINING, TRAINING_BEFORE, TRAINING_CHECK, TRAINING_INTRO } from "../data/flowTraining";
import { PROTOCOLS } from "../lib/protocols";
import { DEVICE_SSO_TITLE, DEVICE_SSO_INTRO, DEVICE_FLOWS, DEVICE_SSO_FACTS, DEVICE_SSO_CHECKS, DEVICE_SSO_PORTALS, DEVICE_SSO_SOURCES } from "../data/deviceSso";
import { usePref } from "../lib/store";
import { BASICS_ID, BASICS_TITLE, BASICS_INTRO, BASICS_ALT, BASICS_CARDS, BASICS_TOGETHER } from "../data/identityBasics";
import gifDark from "../assets/learn/sso-oauth-oidc-saml-dark.gif";
import stillDark from "../assets/learn/sso-oauth-oidc-saml-dark.png";
import { Section, openSection } from "../components/Section";

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
    <Section className="panel stack" id="lifecycle">
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
          <button className="btn primary" onClick={() => { setStageId(next.id); openSection("lifecycle"); }}>Next: {next.title}</button>
        </div>
      )}
    </Section>
  );
}

/** **Label** in training text becomes bold. */
function Bold({ text }: { text: string }) {
  return <>{text.split("**").map((part, i) => (i % 2 ? <strong key={i}>{part}</strong> : part))}</>;
}

export const FLOW_TRAINING_ID = "flow-training";

function FlowTraining() {
  const { tenants } = useApp();
  const lab = tenants.find((t) => t.platform === "entra" && GUID.test(t.tenantRef) && !t.example);
  const [domain] = usePref("learn-lab-domain", lab?.domain ?? "");
  const [done, setDone] = usePref<string[]>("learn-flow-training-done", []);
  const f = (t: string) => fillLab(t, "", domain);
  const toggle = (id: string) => setDone(done.includes(id) ? done.filter((d) => d !== id) : [...done, id]);
  const finished = TRAINING.filter((t) => done.includes(t.id)).length;

  return (
    <Section className="panel stack" id={FLOW_TRAINING_ID}>
      <div className="spread">
        <h2>Flow tracer training: troubleshoot a sign-in</h2>
        <span className="chip" style={{ color: finished === TRAINING.length ? "var(--ok)" : "var(--muted)" }}>{finished} of {TRAINING.length} exercises done</span>
      </div>
      <p style={{ maxWidth: "75ch" }}>{TRAINING_INTRO}</p>
      <p className="small muted" style={{ margin: 0 }}>Your progress is saved in this browser. Lab sign-in names use the domain typed into “Your lab” in the section above.</p>
      <div className="callout small">
        <strong>Before you start</strong>
        <ul className="plain" style={{ marginTop: 6 }}>{TRAINING_BEFORE.map((b) => <li key={b}><Bold text={f(b)} /></li>)}</ul>
      </div>

      <ol className="plain stack" style={{ paddingLeft: 0 }}>
        {TRAINING.map((ex, i) => (
          <li key={ex.id} className="panel stack" id={`flow-training-${ex.id}`}>
            <div className="eyebrow">Exercise {i + 1} of {TRAINING.length} · about {ex.minutes} minutes{done.includes(ex.id) ? " · done" : ""}</div>
            <h3>{ex.title}</h3>
            <p className="small" style={{ maxWidth: "75ch" }}><strong>Goal:</strong> {ex.goal}</p>
            {ex.needs && <p className="small muted" style={{ maxWidth: "75ch" }}><strong>You need:</strong> <Bold text={f(ex.needs)} /></p>}
            <div className="row">
              <a className="btn sm" href={`#${ex.open.route}`} target="_blank" rel="noreferrer">Open {ex.open.name} in a new tab ↗</a>
            </div>
            {ex.code && (
              <div className="stack" style={{ gap: 4 }}>
                <span className="small muted">{ex.code.title}</span>
                <CodeBlock code={ex.code.body} />
              </div>
            )}
            <ol className="actions">{ex.steps.map((c) => <li key={c}><Bold text={f(c)} /></li>)}</ol>
            <div className="callout small"><strong>What success looks like:</strong> <Bold text={f(ex.success)} /></div>
            <div className="callout small"><strong>What you learned:</strong> <Bold text={f(ex.learned)} /></div>
            <div className="row">
              <button className={`btn sm${done.includes(ex.id) ? " on" : ""}`} aria-pressed={done.includes(ex.id)} onClick={() => toggle(ex.id)}>
                {done.includes(ex.id) ? "Done ✓ (click to undo)" : "Mark as done"}
              </button>
            </div>
          </li>
        ))}
      </ol>

      <h3>Check yourself</h3>
      <p className="small muted">Answer each question out loud, then open it. If you couldn't answer, redo the exercise it names.</p>
      {TRAINING_CHECK.map((c) => (
        <details key={c.q}>
          <summary>{c.q}</summary>
          <p className="small" style={{ margin: "6px 0 0" }}>{c.a} <span className="muted">(Exercise {TRAINING.findIndex((t) => t.id === c.exercise) + 1}: {TRAINING.find((t) => t.id === c.exercise)?.title})</span></p>
        </details>
      ))}
    </Section>
  );
}

function DeviceSso() {
  const [id, setId] = usePref("learn-device-sso", DEVICE_FLOWS[0].id);
  const flow = DEVICE_FLOWS.find((f) => f.id === id) ?? DEVICE_FLOWS[0];
  return (
    <Section className="panel stack" id="device-sso">
      <h2>{DEVICE_SSO_TITLE}</h2>
      <p style={{ maxWidth: "75ch" }}>{DEVICE_SSO_INTRO}</p>
      <div className="callout small">
        <strong>Read-only topic.</strong> Trying this needs Microsoft Intune and a Mac or an Entra joined Windows PC. The free lab tenant has neither, so there is no lab step here. Your SAML and OIDC apps need no changes for device SSO to work.
      </div>
      <div className="grid-3">
        {DEVICE_SSO_FACTS.map((f) => (
          <div key={f.title} className="panel stack">
            <h3>{f.title}</h3>
            <p className="small">{f.body}</p>
          </div>
        ))}
      </div>
      <div className="spread">
        <h3>How it flows</h3>
        <Seg label="Device flow" value={flow.id} onChange={setId} options={DEVICE_FLOWS.map((f) => ({ v: f.id, l: f.title }))} />
      </div>
      <p style={{ maxWidth: "75ch" }}>{flow.intro}</p>
      <SequenceDiagram flow={flow} />
      <div className="callout warn small">
        <strong>Where it usually breaks:</strong>
        <ul className="plain" style={{ marginTop: 4 }}>{flow.watch.map((w) => <li key={w}>{w}</li>)}</ul>
      </div>
      <h3>Check it on a device</h3>
      <div className="grid-2">
        {DEVICE_SSO_CHECKS.map((c) => (
          <div key={c.title} className="panel stack">
            <strong>{c.title}</strong>
            <CodeBlock code={c.body} />
            <div className="callout small"><strong>What success looks like:</strong> {c.success}</div>
          </div>
        ))}
      </div>
      <h3>Where to look in the portals</h3>
      <ul className="plain stack small">
        {DEVICE_SSO_PORTALS.map((p) => (
          <li key={p.url} className="row">
            <a className="btn sm" href={p.url} target="_blank" rel="noreferrer">Open {p.label} ↗</a>
            <span>{p.what}</span>
          </li>
        ))}
      </ul>
      <details>
        <summary><strong>Sources on Microsoft Learn</strong></summary>
        <ul className="plain small" style={{ marginTop: 6 }}>
          {DEVICE_SSO_SOURCES.map((s) => <li key={s.url}><a href={s.url} target="_blank" rel="noreferrer">{s.label}</a></li>)}
        </ul>
      </details>
    </Section>
  );
}

function IdentityBasics() {
  return (
    <Section className="panel stack" id={BASICS_ID}>
      <h2>{BASICS_TITLE}</h2>
      <p style={{ maxWidth: "75ch" }}>{BASICS_INTRO}</p>
      <figure className="learn-anim">
        {/* The dark version in both themes (chosen over a light version); a still picture for reduced motion. */}
        <img className="anim-moving" src={gifDark} alt={BASICS_ALT} width={960} height={540} />
        <img className="anim-still" src={stillDark} alt={BASICS_ALT} width={960} height={540} />
        <figcaption className="small muted">The animation loops through seven scenes in about two and a half minutes. Everything in it is written out below.</figcaption>
      </figure>
      <details>
        <summary><strong>Read it as text</strong></summary>
        <div className="grid-2" style={{ marginTop: 8 }}>
          {BASICS_CARDS.map((c) => (
            <div key={c.name} className="panel stack">
              <div className="spread"><h3>{c.name}</h3>{c.protocol ? <ProtoChip p={c.protocol} /> : <span className="tag">{c.role}</span>}</div>
              <p className="small"><strong>What it is:</strong> {c.what}</p>
              <p className="small"><strong>Token:</strong> {c.token}</p>
              <p className="small"><strong>Typical use:</strong> {c.use}</p>
              <ol className="small" style={{ margin: 0, paddingLeft: 20 }}>{c.steps.map((s) => <li key={s}>{s}</li>)}</ol>
              <div className="callout small"><strong>Remember:</strong> {c.takeaway}</div>
            </div>
          ))}
        </div>
        <h3 style={{ marginTop: 12 }}>How they work together</h3>
        <ol className="small">{BASICS_TOGETHER.map((s) => <li key={s}>{s}</li>)}</ol>
      </details>
    </Section>
  );
}

export default function Learn() {
  const { params } = useApp();
  useEffect(() => {
    if (params.section) openSection(params.section);
  }, [params.section]);
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

      <IdentityBasics />

      <Lifecycle />

      <FlowTraining />

      <div className="grid-2">
        {PROTOCOLS.map((p) => (
          <Section key={p.id} className="panel stack" style={p.status === "planned" ? { borderStyle: "dashed" } : undefined}>
            <div className="spread"><h3>{p.name}</h3><ProtoChip p={p.id} /></div>
            <p>{p.purpose}</p>
            <p className="small muted"><strong>Answers:</strong> {p.answers}</p>
            {p.status === "planned" && <span className="tag">Module planned</span>}
          </Section>
        ))}
      </div>
      <div className="callout">
        <strong>The one distinction to remember:</strong> SAML and OIDC are about <em>authentication</em> (who is the user). OAuth is about <em>authorization</em> (what may this app do). OIDC adds an ID token on top of OAuth so one protocol can do both.
      </div>

      <Section className="panel stack">
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
      </Section>

      <DeviceSso />

      <Section className="stack">
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
      </Section>

      <Section className="stack">
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
      </Section>
    </div>
  );
}

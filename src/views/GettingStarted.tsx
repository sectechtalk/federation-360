import { useApp, ProtoChip } from "../components/ui";
import { usePref } from "../lib/store";
import { ASK_YOUR_TEAM, BASICS, PHASES, SITUATIONS, START_STEPS } from "../data/gettingStarted";

export default function GettingStarted() {
  const { go, toast } = useApp();
  const [done, setDone] = usePref<string[]>("start-done", []);
  const toggle = (id: string) => setDone(done.includes(id) ? done.filter((d) => d !== id) : [...done, id]);
  const doneCount = START_STEPS.filter((s) => done.includes(s.id)).length;
  const nextStep = START_STEPS.find((s) => !done.includes(s.id));

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Getting started</h1>
          <p>
            You've just been told you own SAML, OIDC or SCIM, and you've maybe only heard the names. That's fine. This page explains what they are in plain
            words and gives you a path: what to do first, what to do next, and what to keep doing. Every step opens the page in Federation 360 that does it.
          </p>
        </div>
        {nextStep && (
          <button className="btn primary" onClick={() => go(nextStep.open.route, nextStep.open.params)}>
            {doneCount === 0 ? "Start step 1" : "Continue where I left off"}
          </button>
        )}
      </div>

      <div className="callout">
        <strong>What Federation 360 is for.</strong> It's one place for everything about how people sign in to your company's apps: a list of every app and who owns
        it (Inventory), what's broken or about to expire (Overview), tools that explain sign-in errors (Troubleshoot), step-by-step guides (Learn and Setup
        wizards), and a free practice tenant (Build your lab). It never changes anything in your company's tenant; it only reads.
      </div>

      <section className="stack">
        <h2>The three things you now own, in plain words</h2>
        <p className="muted" style={{ maxWidth: "75ch" }}>
          All three exist so people use one work account everywhere, instead of a different username and password for every app. Your company's directory
          (usually Microsoft Entra ID, sometimes Okta) is the <em>identity provider</em>: the one place that knows who everyone is. Each app trusts it.
        </p>
        <div className="grid-3">
          {BASICS.map((b) => (
            <section key={b.id} className="panel stack">
              <div className="spread"><h3>{b.name}</h3><ProtoChip p={b.id} /></div>
              <strong className="small">{b.short}</strong>
              <p className="small">{b.oneLine}</p>
              <p className="small muted"><strong>Think of it as:</strong> {b.analogy}</p>
              <p className="small muted">{b.atWork}</p>
            </section>
          ))}
        </div>
        <div><button className="btn" onClick={() => go("learn")}>Go deeper on Learn</button></div>
      </section>

      <section className="stack" id="path">
        <div className="spread">
          <h2>Your path: first, next, ongoing</h2>
          <span className="small muted" aria-live="polite">{doneCount} of {START_STEPS.length} done{doneCount === START_STEPS.length ? ". You're up and running." : ""}</span>
        </div>
        <p className="muted" style={{ maxWidth: "75ch" }}>Tick each step as you finish it. Your ticks are saved in this browser so you can come back to it.</p>
        {PHASES.map((ph) => (
          <div key={ph.id} className="stack">
            <div>
              <h3>{ph.title}</h3>
              <span className="small muted">{ph.sub}</span>
            </div>
            {START_STEPS.filter((s) => s.phase === ph.id).map((s) => {
              const n = START_STEPS.indexOf(s) + 1;
              const isDone = done.includes(s.id);
              return (
                <div key={s.id} className="panel stack" style={isDone ? { opacity: 0.75 } : undefined}>
                  <div className="spread">
                    <div className="eyebrow">Step {n} · {s.minutes}</div>
                    <label className="row small">
                      <input type="checkbox" checked={isDone} onChange={() => toggle(s.id)} aria-label={`Step ${n} done`} /> Done
                    </label>
                  </div>
                  <h3>{s.title}</h3>
                  <p className="small" style={{ maxWidth: "75ch" }}><strong>Why:</strong> {s.why}</p>
                  <p className="small" style={{ maxWidth: "75ch" }}><strong>How:</strong> {s.how}</p>
                  <div><button className={`btn sm${s.id === nextStep?.id ? " primary" : ""}`} onClick={() => go(s.open.route, s.open.params)}>{s.open.label}</button></div>
                </div>
              );
            })}
          </div>
        ))}
        {doneCount > 0 && <div><button className="btn sm" onClick={() => { setDone([]); toast("Ticks cleared"); }}>Clear my ticks</button></div>}
      </section>

      <section className="stack">
        <h2>Someone just asked me to…</h2>
        <p className="muted" style={{ maxWidth: "75ch" }}>The requests a new owner gets most, and the one page that answers each.</p>
        <div className="grid-2">
          {SITUATIONS.map((s) => (
            <div key={s.when} className="panel stack">
              <h3>{s.when}</h3>
              <p className="small">{s.do}</p>
              <div><button className="btn sm" onClick={() => go(s.open.route, s.open.params)}>{s.open.label}</button></div>
            </div>
          ))}
        </div>
      </section>

      <section className="panel stack">
        <h2>Questions to ask your team in your first week</h2>
        <p className="small muted">Your manager or whoever owned this before you can answer these. Write the answers in Inventory, under each tenant's Notes.</p>
        <ul className="plain">{ASK_YOUR_TEAM.map((q) => <li key={q}>{q}</li>)}</ul>
      </section>

      <div className="callout warn">
        <strong>One rule above all:</strong> practise in your lab tenant, never in your company's live tenant. A mistake on a live SAML or OIDC app can stop
        everyone signing in to that app. When you do change a live app, follow your company's change process and test with one user first.
      </div>
    </div>
  );
}

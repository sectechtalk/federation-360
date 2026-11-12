import { useState } from "react";
import { useApp, ProtoChip, Field, CodeBlock } from "../components/ui";
import { WIZARDS, type Wizard } from "../data/wizards";
import { usePref } from "../lib/store";
import { blankApp } from "./Inventory";
import { PROTOCOLS } from "../lib/protocols";

function Runner({ w, onExit }: { w: Wizard; onExit: () => void }) {
  const { tenants, store, toast, go } = useApp();
  const [values, setValues] = usePref<Record<string, string>>("wizard:" + w.id, {});
  const [step, setStep] = usePref<number>("wizard-step:" + w.id, 0);
  const [tenantId, setTenantId] = useState(tenants[0]?.id ?? "");
  const [env, setEnv] = useState("test");
  const total = w.steps.length + 1; // + summary
  const s = Math.min(step, total - 1);
  const isSummary = s === w.steps.length;
  const cur = w.steps[s];
  const set = (k: string, v: string) => setValues({ ...values, [k]: v });
  const filled = (i: number) => (w.steps[i]?.fields ?? []).every((f) => !f.validate || !f.validate(values[f.key] ?? "", values));

  const save = async () => {
    if (!store || !tenantId) return toast("Add a tenant in the inventory first");
    const app = { ...blankApp(tenantId), ...w.toApp(values), environment: env as any, updatedAt: new Date().toISOString() };
    await store.put("apps", app);
    toast(`Saved “${app.name}” to the inventory`);
    go("inventory", { app: app.id });
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <button className="btn ghost sm" style={{ paddingLeft: 0 }} onClick={onExit}>← All wizards</button>
          <h1>{w.title}</h1>
          <p>{w.summary}</p>
        </div>
        <div className="row"><ProtoChip p={w.protocol} /><span className="tag">{w.platform}</span><span className="tag">~{w.minutes} min</span></div>
      </div>
      <div className="wiz">
        <nav className="steps" aria-label="Steps">
          {[...w.steps.map((x) => x.title), "Summary and save"].map((t, i) => (
            <button key={i} aria-current={i === s ? "step" : undefined} className={i < s && filled(i) ? "done" : ""} onClick={() => setStep(i)}>
              <span className="num">{i + 1}</span>
              <span>{t}</span>
            </button>
          ))}
        </nav>
        <section className="panel stack">
          {!isSummary ? (
            <>
              <div className="eyebrow">Step {s + 1} of {total}</div>
              <h2>{cur.title}</h2>
              {cur.where && <div className="where">{cur.where}</div>}
              <p style={{ maxWidth: "70ch" }}>{cur.explain}</p>
              {cur.actions && (
                <ol className="actions">
                  {cur.actions.map((a, i) => <li key={i}>{a}</li>)}
                </ol>
              )}
              {cur.fields?.map((f) => (
                <div key={f.key} className="stack" style={{ gap: 6 }}>
                  <Field
                    id={`wf-${w.id}-${f.key}`}
                    label={f.label}
                    value={values[f.key] ?? (f.options ? f.options[0] : "")}
                    onChange={(v) => set(f.key, v)}
                    placeholder={f.placeholder}
                    multiline={f.multiline}
                    type={f.type === "date" ? "date" : undefined}
                    options={f.options}
                    hint={f.help}
                    error={f.validate ? f.validate(values[f.key] ?? "", values) : null}
                  />
                  {f.pitfall && <div className="callout warn small"><strong>If this is wrong:</strong> {f.pitfall}</div>}
                </div>
              ))}
              {cur.why && <div className="callout small"><strong>Why it matters:</strong> {cur.why}</div>}
              <div className="spread" style={{ marginTop: 8 }}>
                <button className="btn" disabled={s === 0} onClick={() => setStep(s - 1)}>Back</button>
                <button className="btn primary" onClick={() => setStep(s + 1)}>{s === w.steps.length - 1 ? "Review summary" : "Next step"}</button>
              </div>
            </>
          ) : (
            <>
              <div className="eyebrow">Summary</div>
              <h2>Your configuration sheet</h2>
              <p className="muted">Keep this with the change record. Values you skipped show as placeholders.</p>
              {w.outputs(values).map((o) => (
                <div key={o.title} className="stack" style={{ gap: 6 }}>
                  <h3>{o.title}</h3>
                  <CodeBlock code={o.body} />
                </div>
              ))}
              <h3>Test plan</h3>
              <ol className="actions">{w.testPlan.map((t, i) => <li key={i}>{t}</li>)}</ol>
              <div className="panel stack" style={{ background: "var(--surface-2)" }}>
                <h3>Save to inventory</h3>
                {tenants.length ? (
                  <div className="grid-2">
                    <label className="field" htmlFor="wz-tenant">
                      <span>Tenant</span>
                      <select id="wz-tenant" className="input" value={tenantId} onChange={(e) => setTenantId(e.target.value)}>
                        {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                      </select>
                    </label>
                    <Field id="wz-env" label="Environment" value={env} onChange={setEnv} options={["test", "dev", "prod"]} />
                  </div>
                ) : <p className="muted">Add a tenant in the inventory first.</p>}
                <div className="row">
                  <button className="btn primary" onClick={save} disabled={!tenants.length}>Save as a new integration</button>
                  <button className="btn" onClick={() => { setValues({}); setStep(0); toast("Wizard cleared"); }}>Start over</button>
                </div>
              </div>
            </>
          )}
        </section>
      </div>
    </div>
  );
}

export default function Wizards() {
  const [active, setActive] = usePref<string>("wizard-active", "");
  const w = WIZARDS.find((x) => x.id === active);
  if (w) return <Runner w={w} onExit={() => setActive("")} />;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Setup wizards</h1>
          <p>Step-by-step builds with the reason behind every field and what breaks when it's wrong. Each one ends with a configuration sheet, a test plan, and an entry in your inventory. Progress is kept in this browser.</p>
        </div>
      </div>
      <div className="grid-2">
        {WIZARDS.map((x) => (
          <button key={x.id} className="panel card-btn" onClick={() => setActive(x.id)}>
            <div className="row"><ProtoChip p={x.protocol} /><span className="tag">{x.platform}</span><span className="tag">~{x.minutes} min</span></div>
            <h3>{x.title}</h3>
            <span className="muted small">{x.summary}</span>
            <ul className="plain small">{x.youWillLearn.map((l) => <li key={l}>{l}</li>)}</ul>
          </button>
        ))}
        {PROTOCOLS.filter((p) => p.status === "planned").map((p) => (
          <div key={p.id} className="panel" style={{ borderStyle: "dashed" }}>
            <div className="row"><ProtoChip p={p.id} /><span className="tag">Planned</span></div>
            <h3 style={{ marginTop: 8 }}>{p.name} provisioning</h3>
            <p className="muted small" style={{ marginTop: 4 }}>{p.purpose} Next module: SCIM endpoint tester, attribute mapping guide and provisioning-log playbooks.</p>
          </div>
        ))}
      </div>
    </div>
  );
}

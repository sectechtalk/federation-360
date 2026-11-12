import { useApp, ProtoChip, Sev } from "../components/ui";
import { appHealth, daysUntil, nextExpiry, worst } from "../lib/health";
import { PROTOCOLS } from "../lib/protocols";
import { ENV_LABEL, PLATFORM_LABEL, type Severity } from "../lib/types";

export default function Overview() {
  const { tenants, apps, go, loading, loadExamples } = useApp();
  const scored = apps.map((a) => ({ app: a, findings: appHealth(a), sev: worst(appHealth(a)) }));
  const rank: Record<Severity, number> = { critical: 0, warn: 1, info: 2, ok: 3 };
  const attention = scored.filter((s) => s.sev === "critical" || s.sev === "warn").sort((x, y) => rank[x.sev] - rank[y.sev]);
  const expiries = apps
    .map((a) => ({ app: a, exp: nextExpiry(a) }))
    .filter((x) => x.exp)
    .map((x) => ({ ...x, days: daysUntil(x.exp!.date) }))
    .filter((x) => x.days <= 180)
    .sort((x, y) => x.days - y.days);
  const tenantName = (id: string) => tenants.find((t) => t.id === id)?.name ?? "No tenant";
  const anyExamples = apps.some((a) => a.example) || tenants.some((t) => t.example);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          <p>Health of every SSO and API integration you track, across tenants and environments. Start with anything marked as a problem.</p>
        </div>
        <div className="row">
          <button className="btn" onClick={() => go("wizards")}>Set up an integration</button>
          <button className="btn primary" onClick={() => go("saml")}>Troubleshoot a sign-in</button>
        </div>
      </div>

      {!loading && apps.length === 0 && (
        <div className="empty">
          <h3>Your inventory is empty</h3>
          <p className="muted">Add the tenants and apps you manage, or load a set of fictional examples to explore every screen first.</p>
          <div className="row">
            <button className="btn primary" onClick={() => go("inventory", { add: "tenant" })}>Add a tenant</button>
            <button className="btn" onClick={loadExamples}>Load example data</button>
          </div>
        </div>
      )}

      {apps.length > 0 && (
        <>
          {anyExamples && <p className="small muted">Showing fictional example data (marked “Example”). Delete it from the inventory when you add your own.</p>}
          <div className="statline">
            <div><span className="n">{tenants.length}</span><span className="l">Tenants</span></div>
            <div><span className="n">{apps.length}</span><span className="l">Integrations</span></div>
            <div><span className="n" style={{ color: attention.some((s) => s.sev === "critical") ? "var(--crit)" : undefined }}>{scored.filter((s) => s.sev === "critical").length}</span><span className="l">With problems</span></div>
            <div><span className="n" style={{ color: expiries.some((e) => e.days <= 30) ? "var(--warn)" : undefined }}>{expiries.filter((e) => e.days <= 30).length}</span><span className="l">Credentials expiring ≤ 30 days</span></div>
          </div>

          <div className="grid-2">
            <section className="panel">
              <div className="panel-head">
                <h2>Needs attention</h2>
                <span className="sub">{attention.length} integration{attention.length === 1 ? "" : "s"}</span>
              </div>
              {attention.length === 0 ? (
                <p className="muted">Nothing flagged. Every integration passes its configuration checks.</p>
              ) : (
                <div className="stack">
                  {attention.map(({ app, findings, sev }) => (
                    <button key={app.id} className="panel card-btn" style={{ padding: 12 }} onClick={() => go("inventory", { app: app.id })}>
                      <div className="spread">
                        <div className="row">
                          <strong>{app.name}</strong>
                          <ProtoChip p={app.protocol} />
                        </div>
                        <Sev s={sev} />
                      </div>
                      <span className="small muted">{tenantName(app.tenantId)} · {ENV_LABEL[app.environment]}</span>
                      <ul className="plain small">
                        {findings.filter((f) => f.severity === "critical" || f.severity === "warn").slice(0, 3).map((f, i) => (
                          <li key={i}>{f.title}</li>
                        ))}
                      </ul>
                    </button>
                  ))}
                </div>
              )}
            </section>

            <section className="panel">
              <div className="panel-head">
                <h2>Upcoming expirations</h2>
                <span className="sub">Next 180 days</span>
              </div>
              {expiries.length === 0 ? (
                <p className="muted">No certificates or secrets expire in the next 180 days (based on dates recorded in the inventory).</p>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Integration</th><th>Credential</th><th>Expires</th><th className="num">Days</th></tr></thead>
                    <tbody>
                      {expiries.map(({ app, exp, days }) => (
                        <tr key={app.id} className="clickable" onClick={() => go("inventory", { app: app.id })}>
                          <td>{app.name}</td>
                          <td>{exp!.what}</td>
                          <td className="mono nowrap">{exp!.date}</td>
                          <td className="num"><Sev s={days < 0 ? "critical" : days <= 30 ? "warn" : "info"} label={days < 0 ? `${-days} ago` : String(days)} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </div>

          <section className="panel">
            <div className="panel-head">
              <h2>Coverage by tenant</h2>
              <span className="sub">Integrations per protocol</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Tenant</th><th>Platform</th><th>Env</th>
                    {PROTOCOLS.map((p) => <th key={p.id} className="num">{p.short}{p.status === "planned" ? " (planned)" : ""}</th>)}
                    <th>Health</th>
                  </tr>
                </thead>
                <tbody>
                  {tenants.map((t) => {
                    const mine = scored.filter((s) => s.app.tenantId === t.id);
                    return (
                      <tr key={t.id} className="clickable" onClick={() => go("inventory", { tenant: t.id })}>
                        <td><strong>{t.name}</strong>{t.example && <> <span className="example-flag">Example</span></>}</td>
                        <td>{PLATFORM_LABEL[t.platform]}</td>
                        <td>{ENV_LABEL[t.environment]}</td>
                        {PROTOCOLS.map((p) => <td key={p.id} className="num">{mine.filter((s) => s.app.protocol === p.id || (p.id === "scim" && s.app.provisioning === "scim")).length || "–"}</td>)}
                        <td>{mine.length ? <Sev s={worst(mine.flatMap((m) => m.findings))} /> : <span className="muted small">No apps</span>}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>New to this? Start here</h2>
          <span className="sub">About an hour, in order</span>
        </div>
        <div className="grid-3">
          {[
            { t: "1. Learn the flows", d: "See how SAML, OIDC and OAuth messages move between browser, app and identity provider.", r: "learn" },
            { t: "2. Decode the examples", d: "Load the sample SAML responses and tokens. Read every finding and open its playbook.", r: "saml" },
            { t: "3. Walk a wizard", d: "Follow the Entra SAML wizard with a test app, then save it to the inventory.", r: "wizards" },
          ].map((c) => (
            <button key={c.r} className="panel card-btn" onClick={() => go(c.r)}>
              <h3>{c.t}</h3>
              <span className="muted small">{c.d}</span>
            </button>
          ))}
        </div>
      </section>
    </div>
  );
}

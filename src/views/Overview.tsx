import { useApp, ProtoChip, Sev } from "../components/ui";
import { ActionButton } from "../components/busy";
import { appHealth, daysUntil, nextExpiry, worst } from "../lib/health";
import { grantRows, grantSummary } from "../lib/grants";
import { PROTOCOLS } from "../lib/protocols";
import { usePref } from "../lib/store";
import { ENV_LABEL, PLATFORM_LABEL, type Severity } from "../lib/types";
import { Section } from "../components/Section";

export default function Overview() {
  const { tenants, apps, go, loading, loadExamples, toast } = useApp();
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

  const critical = scored.filter((s) => s.sev === "critical");
  const warned = scored.filter((s) => s.sev === "warn");
  const soon = expiries.filter((e) => e.days <= 30);
  const noOwner = apps.filter((a) => !a.owner.trim());
  const [welcomeHidden, setWelcomeHidden] = usePref("overview-welcome-hidden", false);

  // Plain-words "what to do today", most urgent first. Each item points at the one place that fixes it.
  const today: { tone: "crit" | "warn" | "info"; text: string; btn?: { label: string; run: () => void } }[] = [];
  if (critical.length)
    today.push({ tone: "crit", text: `${critical.length} app${critical.length === 1 ? " has a problem" : "s have a problem"} that will probably stop people signing in. Start with ${critical[0].app.name}: open it, read what's wrong and follow its playbook.`, btn: { label: `Open ${critical[0].app.name}`, run: () => go("inventory", { app: critical[0].app.id }) } });
  if (soon.length)
    today.push({ tone: "warn", text: `${soon.length} certificate${soon.length === 1 ? " or secret has" : "s or secrets have"} expired or will expire within 30 days. When one expires, sign-in to that app stops. Contact the app's owner and plan the renewal.`, btn: { label: "How to renew without an outage", run: () => go("learn") } });
  if (warned.length)
    today.push({ tone: "warn", text: `${warned.length} app${warned.length === 1 ? " has a warning" : "s have warnings"}: working today, but set up in a way that is risky or will break later. Fix these when nothing is on fire.` });
  const grants = grantSummary(grantRows(apps));
  if (grants.takeoverApps || grants.bulkApps || grants.shadowApps) {
    const parts = [
      grants.takeoverApps && `${grants.takeoverApps} could take over the tenant`,
      grants.bulkApps && `${grants.bulkApps} read${grants.bulkApps === 1 ? "s" : ""} everyone's data with no user signed in`,
      grants.shadowApps && `${grants.shadowApps} third-party app${grants.shadowApps === 1 ? " was" : "s were"} approved by users without IT`,
    ].filter(Boolean);
    today.push({ tone: grants.takeoverApps ? "crit" : "warn", text: `Risky app permissions: ${parts.join("; ")}. Review them and remove what isn't needed.`, btn: { label: "Open OAuth grants", run: () => go("grants") } });
  }
  if (noOwner.length)
    today.push({ tone: "info", text: `${noOwner.length} app${noOwner.length === 1 ? " has" : "s have"} no owner recorded. Add one in Inventory so you know who on the app side to call when it breaks.`, btn: { label: "Open Inventory", run: () => go("inventory") } });
  if (anyExamples)
    today.push({ tone: "info", text: "Everything on this page is made-up example data, so you can see what healthy and broken apps look like. When you're ready, Discover reads your real apps; then delete the examples (marked Example) in Inventory.", btn: { label: "Open Discover", run: () => go("discover") } });

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          <p>
            Today's health of every app that signs people in through your directory, in one place. Anything that needs you is listed first, in plain words,
            with a button that takes you to the fix.
          </p>
        </div>
        <div className="row">
          <button className="btn" onClick={() => go("wizards")}>Set up a new app</button>
          <button className="btn primary" onClick={() => go("playbooks")}>Fix a sign-in problem</button>
        </div>
      </div>

      {!welcomeHidden && (
        <Section className="panel stack" aria-label="Welcome">
          <h2>New to SAML, OIDC and SCIM?</h2>
          <p style={{ maxWidth: "75ch" }}>
            Start on Getting started. It explains what they are in plain words, gives you a step-by-step path for your first weeks, and tells you which page to
            open when someone asks you for something. This page is the one you'll come back to every week once you're set up.
          </p>
          <div className="row">
            <button className="btn primary" onClick={() => go("start")}>Open Getting started</button>
            <button className="btn" onClick={() => { setWelcomeHidden(true); toast("Welcome box hidden. Getting started is still in the left menu."); }}>Hide this</button>
          </div>
        </Section>
      )}

      {!loading && apps.length === 0 && (
        <div className="empty">
          <h3>Nothing here yet</h3>
          <p className="muted" style={{ maxWidth: "60ch" }}>
            This page fills in once Federation 360 knows about your apps. The quickest way is Discover, which reads them from your tenant without changing
            anything. You can also add them by hand, or load made-up examples to see what every screen looks like first.
          </p>
          <div className="row">
            <button className="btn primary" onClick={() => go("discover")}>Read my apps with Discover</button>
            <button className="btn" onClick={() => go("inventory", { add: "tenant" })}>Add a tenant by hand</button>
            <ActionButton busy="Loading examples…" onClick={loadExamples}>Load example data</ActionButton>
          </div>
        </div>
      )}

      {apps.length > 0 && (
        <>
          <Section className="panel stack">
            <div className="panel-head">
              <h2>What to do today</h2>
              <span className="sub">Most urgent first</span>
            </div>
            {today.length === 0 ? (
              <p>All clear. Every app passes its checks and nothing expires in the next 30 days. Check back next week.</p>
            ) : (
              <div className="stack">
                {today.map((t) => (
                  <div key={t.text} className={`today today-${t.tone}`}>
                    <p>{t.text}</p>
                    {t.btn && <div><button className="btn sm" onClick={t.btn.run}>{t.btn.label}</button></div>}
                  </div>
                ))}
              </div>
            )}
          </Section>

          <div className="statline">
            <div><span className="n">{tenants.length}</span><span className="l">Tenants (directories)</span></div>
            <div><span className="n">{apps.length}</span><span className="l">Apps connected</span></div>
            <div><span className="n" style={{ color: critical.length ? "var(--crit)" : undefined }}>{critical.length}</span><span className="l">Apps with problems</span></div>
            <div><span className="n" style={{ color: soon.length ? "var(--warn)" : undefined }}>{soon.length}</span><span className="l">Expiring within 30 days</span></div>
          </div>

          <details className="panel">
            <summary><strong>What do these words mean?</strong></summary>
            <dl className="kv glance">
              <dt>Tenant</dt><dd>Your company's directory: the one place that knows every user and lets them sign in, usually Microsoft Entra ID. Big companies often have a production tenant and one or more test tenants.</dd>
              <dt>App (integration)</dt><dd>One app that trusts your directory for sign-in (SAML or OIDC), API access (OAuth) or user accounts (SCIM). The same app in test and production counts twice.</dd>
              <dt><Sev s="critical" /></dt><dd>Something is set up wrong in a way that will probably stop people signing in, or already has.</dd>
              <dt><Sev s="warn" /></dt><dd>Works today, but is risky or will break later, for example a certificate that expires soon.</dd>
              <dt>Certificate or secret</dt><dd>A long password-like value an app and your directory use to prove messages are genuine. They expire on a fixed date, and when one does, sign-in to that app stops for everyone until it's renewed.</dd>
            </dl>
          </details>

          <div className="grid-2">
            <Section className="panel">
              <div className="panel-head">
                <h2>Needs attention</h2>
                <span className="sub">{attention.length} app{attention.length === 1 ? "" : "s"}</span>
              </div>
              <p className="small muted">Apps whose setup has a problem or a warning. Click one to see every check and the playbook that fixes it.</p>
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
            </Section>

            <Section className="panel">
              <div className="panel-head">
                <h2>Upcoming expirations</h2>
                <span className="sub">Next 180 days</span>
              </div>
              <p className="small muted">When a certificate or secret expires, sign-in to that app stops. Renew anything under 30 days with the app's owner now.</p>
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
            </Section>
          </div>

          <Section className="panel">
            <div className="panel-head">
              <h2>Apps per tenant</h2>
              <span className="sub">How many of each kind every directory has</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Tenant</th><th>Platform</th><th>Environment</th>
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
          </Section>
        </>
      )}

    </div>
  );
}

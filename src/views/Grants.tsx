import { useMemo, useState } from "react";
import { Seg, Sev, useApp } from "../components/ui";
import { ActionButton, downloadFile } from "../components/busy";
import {
  CONSENT_SETTINGS_URL, grantPortalLinks, grantRows, grantsCsv, grantSummary, RISK_LABEL, RISK_ORDER, RISK_SEVERITY,
  type GrantRisk, type GrantRow,
} from "../lib/grants";
import { Section } from "../components/Section";

type RiskFilter = "risky" | "all" | GrantRisk;

export default function Grants() {
  const { apps, tenants, go, loading, loadExamples } = useApp();
  const [risk, setRisk] = useState<RiskFilter>("risky");
  const [thirdOnly, setThirdOnly] = useState(false);
  const [userOnly, setUserOnly] = useState(false);
  const [q, setQ] = useState("");
  const [tenant, setTenant] = useState("");

  const scoped = useMemo(() => apps.filter((a) => !tenant || a.tenantId === tenant), [apps, tenant]);
  const all = useMemo(() => grantRows(scoped), [scoped]);
  const sum = grantSummary(all);
  const scanned = scoped.filter((a) => a.discovery).length;

  const needle = q.trim().toLowerCase();
  const shown = all.filter(
    (r) =>
      (risk === "all" || (risk === "risky" ? r.risk === "critical" || r.risk === "high" : r.risk === risk)) &&
      (!thirdOnly || r.thirdParty) &&
      (!userOnly || r.consent === "user") &&
      (!needle || [r.app.name, r.publisher, r.resource, r.value, r.app.owner].some((v) => v.toLowerCase().includes(needle))),
  );

  const exportCsv = async () => {
    if (!shown.length) throw new Error("Nothing to export with these filters. Choose All to export every grant.");
    return downloadFile(`f360-oauth-grants-${new Date().toISOString().slice(0, 10)}.csv`, grantsCsv(shown), "text/csv");
  };

  const consentLabel = (r: GrantRow) =>
    r.type === "application" ? "Admin, app-only" : r.consent === "admin" ? "Admin, all users" : `${r.users} user${r.users === 1 ? "" : "s"} themselves`;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>OAuth grants</h1>
          <p>
            Every permission your apps hold in the tenant, rated by what it lets the app do on its own. Use it to find apps that could take over the tenant,
            apps that read everyone's mail or files, third-party apps users approved without IT (shadow IT), and leftover grants nobody uses.
          </p>
        </div>
        <div className="row">
          <button className="btn" onClick={() => go("discover")}>Scan the tenant again</button>
          <ActionButton className="btn primary" busy="Building the CSV…" onClick={exportCsv}>Export CSV ({shown.length})</ActionButton>
        </div>
      </div>

      {!loading && scanned === 0 && (
        <div className="empty">
          <h3>No permissions to review yet</h3>
          <p className="muted" style={{ maxWidth: "65ch" }}>
            Permissions come from Discover, which reads every app's requested and granted permissions from Entra, read-only. Apps you typed in by hand have
            none. Scan your lab tenant, or load the example data (it includes a third-party app users consented to and an automation app with too much access).
          </p>
          <div className="row">
            <button className="btn primary" onClick={() => go("discover")}>Read my apps with Discover</button>
            <ActionButton busy="Loading examples…" onClick={loadExamples}>Load example data</ActionButton>
          </div>
        </div>
      )}

      {scanned > 0 && (
        <>
          <div className="statline">
            <div><span className="n" style={{ color: sum.takeoverApps ? "var(--crit)" : undefined }}>{sum.takeoverApps}</span><span className="l">Apps that could take over the tenant</span></div>
            <div><span className="n" style={{ color: sum.bulkApps ? "var(--warn)" : undefined }}>{sum.bulkApps}</span><span className="l">Apps reading everyone's data, no user signed in</span></div>
            <div><span className="n" style={{ color: sum.shadowApps ? "var(--warn)" : undefined }}>{sum.shadowApps}</span><span className="l">Third-party apps users approved themselves</span></div>
            <div><span className="n">{sum.staleGrants}</span><span className="l">Grants the app no longer asks for</span></div>
          </div>

          <details className="panel">
            <summary><strong>How to read this page</strong></summary>
            <dl className="kv glance">
              <dt>Application permission</dt><dd>The app acts on its own with no user signed in, across the whole tenant. Only an admin can grant it.</dd>
              <dt>Delegated permission</dt><dd>The app acts as the signed-in user and can never do more than that user can. Users can grant some of these themselves if your consent settings allow it.</dd>
              <dt><Sev s="critical" label="Critical" /></dt><dd>The app could give itself more access or sign in as anyone. A leaked secret for this app is a leaked tenant.</dd>
              <dt><Sev s="warn" label="High" /></dt><dd>The app can read or change mail, files, chats or accounts (everyone's, for an application permission).</dd>
              <dt><Sev s="info" label="Medium" /></dt><dd>The app can read the whole directory or some of other people's data.</dd>
              <dt>Not rated</dt><dd>Your own API or a third party's. Federation 360 doesn't guess; ask the owner what it allows.</dd>
            </dl>
          </details>

          <Section className="panel stack">
            <div className="panel-head">
              <h2>Stop new risky consent</h2>
              <span className="sub">Tenant setting, free on every Entra tenant</span>
            </div>
            <p className="small" style={{ maxWidth: "80ch" }}>
              Set user consent to <strong>Allow user consent for apps from verified publishers, for selected permissions</strong> (or <strong>Do not allow user
              consent</strong>), and turn on the admin consent workflow so people can ask instead of working around it. Federation 360 can't read this setting yet,
              so check it in the portal.
            </p>
            <div className="row">
              <a className="btn sm" href={CONSENT_SETTINGS_URL} target="_blank" rel="noreferrer">Entra: user consent settings ↗</a>
              <button className="btn sm" onClick={() => go("playbooks", { id: "oauth-user-consent" })}>Shadow IT playbook</button>
              <button className="btn sm" onClick={() => go("playbooks", { id: "oauth-risky-grant" })}>Remove a risky grant playbook</button>
            </div>
          </Section>

          <Section className="panel stack">
            <h2>Every grant</h2>
            <div className="spread">
              <Seg<RiskFilter>
                label="Risk"
                value={risk}
                onChange={setRisk}
                options={[
                  { v: "risky", l: `Critical and high (${sum.byRisk.critical + sum.byRisk.high})` },
                  ...RISK_ORDER.map((k) => ({ v: k as RiskFilter, l: `${RISK_LABEL[k]} (${sum.byRisk[k]})` })),
                  { v: "all", l: `All (${sum.grants})` },
                ]}
              />
              <div className="row">
                {tenants.length > 1 && (
                  <select aria-label="Tenant" className="input" style={{ width: 220 }} value={tenant} onChange={(e) => setTenant(e.target.value)}>
                    <option value="">All tenants</option>
                    {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                  </select>
                )}
                <input aria-label="Search grants" className="input" style={{ width: 240 }} placeholder="Search app, permission, publisher…" value={q} onChange={(e) => setQ(e.target.value)} />
              </div>
            </div>
            <div className="row small">
              <label className="row"><input type="checkbox" checked={thirdOnly} onChange={(e) => setThirdOnly(e.target.checked)} /> Third-party apps only</label>
              <label className="row"><input type="checkbox" checked={userOnly} onChange={(e) => setUserOnly(e.target.checked)} /> Approved by users themselves only</label>
              <span className="muted">Showing {shown.length} of {sum.grants} grants across {sum.apps} app{sum.apps === 1 ? "" : "s"}. {scoped.length - scanned > 0 && `${scoped.length - scanned} app${scoped.length - scanned === 1 ? " was" : "s were"} typed in by hand and have no permission data.`}</span>
            </div>

            {shown.length === 0 ? (
              <p className="muted">{risk === "risky" ? "No critical or high grants. Choose All to see every grant." : "No grants match these filters."}</p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr><th>Risk</th><th>App</th><th>Permission</th><th>Type</th><th>Consent</th><th>Why it matters</th><th>Change it in</th></tr>
                  </thead>
                  <tbody>
                    {shown.map((r, i) => (
                      <tr key={r.app.id + r.type + r.resource + r.value + r.consent + i}>
                        <td className="nowrap"><Sev s={RISK_SEVERITY[r.risk]} label={RISK_LABEL[r.risk]} /></td>
                        <td>
                          <a href={"#inventory"} onClick={(e) => { e.preventDefault(); go("inventory", { app: r.app.id }); }}><strong>{r.app.name}</strong></a>
                          {r.app.example && <> <span className="example-flag">Example</span></>}
                          <div className="small muted">{r.publisher}{!r.app.owner.trim() && <> · <span style={{ color: "var(--warn)" }}>no owner</span></>}</div>
                        </td>
                        <td>
                          <span className="mono">{r.value}</span>
                          <div className="small muted">{r.resource}</div>
                          {r.stale && <div className="small" style={{ color: "var(--warn)" }}>No longer requested by the app</div>}
                        </td>
                        <td className="small">{r.type === "application" ? "Application" : "Delegated"}</td>
                        <td className="small nowrap">{consentLabel(r)}</td>
                        <td className="small" style={{ maxWidth: "46ch" }}>{r.why}</td>
                        <td className="small">
                          {grantPortalLinks(r.app).map((l) => <div key={l.url}><a href={l.url} target="_blank" rel="noreferrer">{l.label} ↗</a></div>)}
                          {grantPortalLinks(r.app).length === 0 && <span className="muted">No direct link (example app)</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>
        </>
      )}
    </div>
  );
}

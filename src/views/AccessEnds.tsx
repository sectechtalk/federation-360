import { useEffect, useMemo, useState } from "react";
import { FindingList, Sev, useApp } from "../components/ui";
import { ActionButton, BusyNote } from "../components/busy";
import { BlockedNote, PowerShellRun, TenantClientFields, signInBlockReason, useTenantClient } from "../components/tenantSignIn";
import { usePref } from "../lib/store";
import { ACCESS_PORTAL, accessReport, formatLifetime, formatMinutes, parseAccess, type AccessRow, type AccessSnapshot, type Lifetime } from "../lib/access";
import { ACCESS_SCOPES, APP_LIMIT, collectAccess, graphGetter } from "../lib/accessCollect";
import { browserSignInBlocker, currentRedirectUri, redeemCode, startSignIn, takeRedirectResult } from "../lib/discovery/entraLive";
import { sampleAccess } from "../data/sampleAccess";
import accessScript from "../../access/Export-F360Access.ps1?raw";
import { Section } from "../components/Section";

const SCRIPT_NAME = "Export-F360Access.ps1";
const GUID = /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
export const ACCESS_SNAPSHOT_PREF = "access:snapshot";

const SOURCE: Record<Lifetime["source"], string> = { default: "Entra default", "org-default": "organization policy", "app-policy": "this app's policy" };
const yn = (v?: string) => (v === "yes" ? "Yes" : v === "no" ? "No" : "Unknown");

/** Same snapshot the page shows, for other pages (Inventory, User lookup). */
export function useAccessSnapshot() {
  return usePref<AccessSnapshot | null>(ACCESS_SNAPSHOT_PREF, null);
}

/** One app's "how access ends" facts, as a card. Used here and in the Inventory app drawer. */
export function AccessCard({ row, example }: { row: AccessRow; example?: boolean }) {
  const tokenLine = row.ssoMode === "saml" ? row.samlToken : row.accessToken;
  return (
    <div className="stack">
      <dl className="kv">
        <dt>{row.ssoMode === "saml" ? "SAML token life" : "Access token life"}</dt>
        <dd>{formatLifetime(tokenLine)} <span className="muted small">({SOURCE[tokenLine.source]}{tokenLine.policy ? `: ${tokenLine.policy}` : ""})</span></dd>
        {row.ssoMode !== "saml" && <><dt>ID token life</dt><dd>{formatLifetime(row.idToken)}</dd></>}
        <dt>Sign-in frequency</dt><dd>{row.signInFrequency.text}</dd>
        <dt>Persistent browser</dt><dd>{row.persistentBrowser}</dd>
        <dt>Continuous access evaluation</dt><dd>{row.cae.text}</dd>
        <dt>SCIM provisioning</dt>
        <dd>
          <Sev s={row.scim.severity} label={row.scim.label} /> <span className="small">{row.scim.detail}</span>
          {row.syncJob?.lastRun && <div className="small muted">Last cycle {new Date(row.syncJob.lastRun.ended ?? row.syncJob.lastRun.began).toLocaleString()} · {row.syncJob.lastRun.state}{row.syncJob.inScope !== undefined && ` · ${row.syncJob.inScope} users in scope`}</div>}
        </dd>
      </dl>
      <fieldset className="panel stack" style={{ margin: 0 }}>
        <legend className="eyebrow">Declared app profile · from the vendor, not Entra</legend>
        {row.profile ? (
          <dl className="kv">
            <dt>App session lasts</dt><dd>{row.profile.sessionMinutes ? formatMinutes(row.profile.sessionMinutes) : "Unknown"}</dd>
            <dt>Idle timeout</dt><dd>{row.profile.idleMinutes ? formatMinutes(row.profile.idleMinutes) : "Unknown or none"}</dd>
            <dt>Ends sessions on SCIM disable</dt><dd>{yn(row.profile.endsSessionOnScimDisable)}</dd>
            <dt>Single logout</dt><dd>{yn(row.profile.singleLogout)}</dd>
            <dt>Honours CAE</dt><dd>{yn(row.profile.cae)}</dd>
            {row.profile.source && <><dt>Source</dt><dd className="small">{row.profile.source}</dd></>}
          </dl>
        ) : (
          <p className="small muted">Not recorded. Open the app in Inventory and fill in Declared app profile from the vendor's docs.</p>
        )}
      </fieldset>
      {row.caPolicies.length > 0 && (
        <details>
          <summary>Conditional Access policies that cover this app ({row.caPolicies.length})</summary>
          <ul className="small">
            {row.caPolicies.map((p) => (
              <li key={p.id}>
                {p.name} <span className="muted">· {p.users}{p.state !== "enabled" ? " · report-only" : ""}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
      {!example && row.spId && (
        <div className="row">
          <a className="btn sm" href={ACCESS_PORTAL.provisioning(row.spId, row.appId)} target="_blank" rel="noreferrer">Entra: provisioning ↗</a>
          <a className="btn sm" href={ACCESS_PORTAL.caPolicies} target="_blank" rel="noreferrer">Entra: Conditional Access ↗</a>
          <a className="btn sm" href={ACCESS_PORTAL.tokenLifetimeDocs} target="_blank" rel="noreferrer">Microsoft Learn: token lifetimes ↗</a>
        </div>
      )}
    </div>
  );
}

export default function AccessEnds() {
  const { tenants, apps, go, toast } = useApp();
  const entraTenants = tenants.filter((t) => t.platform === "entra" && GUID.test(t.tenantRef) && !t.example);
  const [tenantId, setTenantId, clientId, setClientId] = useTenantClient(entraTenants[0]?.tenantRef ?? "");
  const [snap, setSnap] = useAccessSnapshot();
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [reading, setReading] = useState(false);
  const [q, setQ] = useState("");
  const blocker = browserSignInBlocker();
  const redirectUri = currentRedirectUri();

  useEffect(() => {
    const r = takeRedirectResult("access");
    if (!r) return;
    if (r.error || !r.code || !r.pending) {
      setError(r.error ?? "Sign-in didn't complete.");
      return;
    }
    (async () => {
      try {
        setStatus("Signed in. Getting a read-only token…");
        const token = await redeemCode(r.code!, r.pending!);
        const s = await collectAccess(graphGetter(token), r.pending!.tenantId, setStatus);
        setSnap(s);
        toast(`Read ${s.apps.length} enterprise apps`);
      } catch (e: any) {
        setError(e?.message ?? String(e));
      }
      setStatus(null);
    })();
  }, []);

  const report = useMemo(() => (snap ? accessReport(snap, apps) : null), [snap, apps]);

  const onFile = async (f: File | undefined) => {
    if (!f) return;
    setError(null);
    try {
      setSnap(parseAccess(await f.text()));
      setReading(false);
      toast(`Loaded ${f.name}`);
    } catch (e: any) {
      setError(e.message);
    }
  };
  const signIn = async () => {
    setError(null);
    await startSignIn({ tenantId, clientId, redirectUri }, { scopes: ACCESS_SCOPES, returnTo: "access" });
    await new Promise((r) => setTimeout(r, 15000));
    throw new Error("Microsoft's sign-in page didn't open. Check the tenant ID and client ID, then try again.");
  };
  const blockReason = signInBlockReason(blocker, tenantId, clientId);
  const canSignIn = !blockReason;
  const tidForScript = GUID.test(tenantId.trim()) ? tenantId.trim() : "<your-tenant-id>";
  const scriptArgs = `-TenantId ${tidForScript} -OutFile $HOME\\Downloads\\f360-access.json`;
  const needle = q.trim().toLowerCase();
  const rows = (report?.rows ?? []).filter((r) => !needle || r.name.toLowerCase().includes(needle) || r.appId.toLowerCase().includes(needle));

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>How access ends</h1>
          <p>
            For every enterprise app: how long its tokens last, how often Entra makes people sign in again, whether continuous access evaluation can cut
            access early, whether SCIM provisioning is healthy enough to push a disable, and what the vendor says about the app's own session. These decide
            how long someone keeps getting in after you disable them. Read-only.
          </p>
        </div>
        {snap && (
          <div className="row">
            <button className="btn" onClick={() => setReading(!reading)}>{reading ? "Hide Read your tenant" : "Read again or another tenant"}</button>
            <button className="btn" onClick={() => { setSnap(null); toast("Scan cleared from this browser."); }}>Clear this scan</button>
          </div>
        )}
      </div>

      {status && <BusyNote>{status}</BusyNote>}
      {error && <div className="callout crit">{error}</div>}

      {(!snap || reading) && (
        <Section className="panel stack">
          <h2>Read your tenant</h2>
          <p className="small" style={{ maxWidth: "80ch" }}>
            Federation 360 reads token lifetime policies, Conditional Access session controls (sign-in frequency, persistent browser, CAE) and each enterprise
            app's provisioning job (schedule, last cycle, quarantine). Token policies and provisioning work on Entra ID Free; Conditional Access needs P1, and
            without it Entra's defaults are shown. Sign in as Global Reader, Security Reader or higher.
          </p>
          <div className="stack">
            <PowerShellRun title="1. PowerShell (works everywhere)" name={SCRIPT_NAME} script={accessScript} args={scriptArgs}>
              <label className="small" htmlFor="ac-file">Then load the file it saves (f360-access.json in your Downloads folder):</label>
              <input id="ac-file" className="input" type="file" accept=".json,application/json" onChange={(e) => onFile(e.target.files?.[0])} />
            </PowerShellRun>
            <hr style={{ border: 0, borderTop: "1px solid var(--line, #ddd)", width: "100%", margin: "4px 0" }} />
            <div className="stack">
              <h3>2. Sign in from this page</h3>
              <TenantClientFields prefix="ac" tenantId={tenantId} setTenantId={setTenantId} clientId={clientId} setClientId={setClientId} />
              <p className="small muted">
                Asks for {ACCESS_SCOPES.join(", ")} (delegated, read-only). The first time, an admin sees Microsoft's consent screen for Synchronization.Read.All.
                Reads provisioning for up to {APP_LIMIT} apps.
              </p>
              <div className="row">
                <ActionButton className="btn primary" busy="Opening Microsoft sign-in…" disabled={!canSignIn} onClick={signIn}>Sign in and read</ActionButton>
              </div>
              <BlockedNote reason={blockReason} />
            </div>
          </div>
          <div className="row">
            <span className="small muted">Just looking?</span>
            <ActionButton busy="Loading the sample…" onClick={async () => { setSnap(sampleAccess()); setReading(false); return "Sample tenant loaded"; }}>Try with sample data</ActionButton>
          </div>
        </Section>
      )}

      {snap && report && (
        <>
          <Section className="panel">
            <div className="spread">
              <div>
                <div className="eyebrow">Scan · {new Date(snap.collectedAt).toLocaleString()} · {snap.collector === "sample" ? "made-up sample" : snap.collector === "powershell" ? "from PowerShell" : "from this page"}</div>
                <h2>{snap.tenant.name || snap.tenant.domain || "Entra tenant"}{snap.example && <> <span className="example-flag">Example</span></>}</h2>
                <span className="small mono">{snap.tenant.id}{snap.tenant.domain && ` · ${snap.tenant.domain}`}</span>
              </div>
              <span className="small">
                Conditional Access: <strong>{snap.caPolicies === null ? "not read" : `${snap.caPolicies.filter((p) => p.state === "enabled").length} policies on`}</strong>
              </span>
            </div>
            {snap.warnings.map((w) => <div key={w} className="callout warn" style={{ marginTop: 8 }}>{w}</div>)}
          </Section>

          <div className="statline">
            <div><span className="n">{report.counts.apps}</span><span className="l">Enterprise apps read</span></div>
            <div><span className="n" style={{ color: report.counts.scimProblems ? "var(--warn)" : undefined }}>{report.counts.scim - report.counts.scimProblems} of {report.counts.scim}</span><span className="l">Provisioning jobs healthy</span></div>
            <div><span className="n">{report.counts.customLifetimes}</span><span className="l">Apps with a custom token lifetime</span></div>
            <div><span className="n">{report.counts.withProfile}</span><span className="l">Apps with a declared session length</span></div>
          </div>

          {report.findings.length > 0 && (
            <Section className="panel stack">
              <div className="panel-head"><h2>What needs you</h2><span className="sub">Most urgent first</span></div>
              <FindingList findings={report.findings} />
            </Section>
          )}

          <Section className="panel stack">
            <div className="spread">
              <h2>Apps</h2>
              <input aria-label="Search apps" className="input" style={{ width: 220 }} placeholder="Search app name or ID…" value={q} onChange={(e) => setQ(e.target.value)} />
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>App</th><th>Token life</th><th>Sign-in frequency</th><th>CAE</th><th>SCIM provisioning</th><th>App session (declared)</th><th></th></tr></thead>
                <tbody>
                  {rows.map((r) => {
                    const t = r.ssoMode === "saml" ? r.samlToken : r.accessToken;
                    return (
                      <tr key={r.key}>
                        <td>
                          {r.inventoryId ? <a href="#inventory" onClick={(e) => { e.preventDefault(); go("inventory", { app: r.inventoryId! }); }}><strong>{r.name}</strong></a> : <strong>{r.name}</strong>}
                          <div className="small muted">{r.ssoMode ? r.ssoMode.toUpperCase() : "No SSO mode set"}</div>
                        </td>
                        <td className="small">{formatLifetime(t)}<div className="muted">{SOURCE[t.source]}</div></td>
                        <td className="small">{r.signInFrequency.text}</td>
                        <td className="small">{r.cae.applies ? <Sev s="ok" label="Cuts access in minutes" /> : <span className="muted">Doesn't apply</span>}</td>
                        <td><Sev s={r.scim.severity} label={r.scim.label} /></td>
                        <td className="small">{r.profile?.sessionMinutes ? formatMinutes(r.profile.sessionMinutes) : <span className="muted">Not recorded</span>}</td>
                        <td><button className="btn sm" aria-expanded={open === r.key} onClick={() => setOpen(open === r.key ? null : r.key)}>{open === r.key ? "Hide details" : "Details"}</button></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {rows.length === 0 && <p className="muted">No app matches.</p>}
            {open && rows.find((r) => r.key === open) && (
              <Section className="panel stack">
                <div className="panel-head"><h2>{rows.find((r) => r.key === open)!.name}</h2><span className="sub">How access ends</span></div>
                {rows.find((r) => r.key === open)!.findings.length > 0 && <FindingList findings={rows.find((r) => r.key === open)!.findings} />}
                <AccessCard row={rows.find((r) => r.key === open)!} example={snap.example} />
              </Section>
            )}
            <p className="small muted">
              App names link to Inventory when Discover has matched them by app ID. The declared app profile is typed in on each Inventory entry.
            </p>
          </Section>
        </>
      )}
    </div>
  );
}

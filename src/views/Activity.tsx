import { useEffect, useMemo, useState } from "react";
import { Seg, Sev, useApp } from "../components/ui";
import { flowToCapture, useBrowserCaptures } from "../lib/browserCapture";
import { liveRefreshes } from "../lib/contain";
import { ActionButton, BusyNote } from "../components/busy";
import { BlockedNote, PowerShellRun, TenantClientFields, signInBlockReason, useTenantClient } from "../components/tenantSignIn";
import { usePref } from "../lib/store";
import { cadenceRows, emptySummary, foldActivity, readActivityFile, type ActivitySummary } from "../lib/activity";
import { formatMinutes } from "../lib/access";
import { ACTIVITY_SCOPES, collectActivity, ROW_LIMIT } from "../lib/activityCollect";
import { graphGetter } from "../lib/postureCollect";
import { browserSignInBlocker, currentRedirectUri, redeemCode, startSignIn, takeRedirectResult } from "../lib/discovery/entraLive";
import { sampleActivityFile } from "../data/sampleActivity";
import activityScript from "../../activity/Export-F360Activity.ps1?raw";
import { Section } from "../components/Section";

const SCRIPT_NAME = "Export-F360Activity.ps1";
const GUID = /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
export const ACTIVITY_PREF = "activity:summary";
const DAYS_KEY = "f360:activity:days";

export function useActivitySummary() {
  return usePref<ActivitySummary | null>(ACTIVITY_PREF, null);
}

const when = (t?: number) => (t ? new Date(t).toLocaleString() : "—");

export default function Activity() {
  const { tenants, toast, go } = useApp();
  const entraTenants = tenants.filter((t) => t.platform === "entra" && GUID.test(t.tenantRef) && !t.example);
  const [tenantId, setTenantId, clientId, setClientId] = useTenantClient(entraTenants[0]?.tenantRef ?? "");
  const [days, setDays] = usePref<"1" | "7" | "30">("activity:days", "7");
  const [sum, setSum] = useActivitySummary();
  const [status, setStatus] = useState<string | null>(null);
  const [errors, setErrors] = useState<string[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [peopleQ, setPeopleQ] = useState("");
  const blocker = browserSignInBlocker();
  const redirectUri = currentRedirectUri();

  useEffect(() => {
    const r = takeRedirectResult("activity");
    if (!r) return;
    if (r.error || !r.code || !r.pending) {
      setErrors([r.error ?? "Sign-in didn't complete."]);
      return;
    }
    (async () => {
      try {
        setStatus("Signed in. Getting a read-only token…");
        const token = await redeemCode(r.code!, r.pending!);
        let d = 7;
        try {
          d = Number(sessionStorage.getItem(DAYS_KEY)) || 7;
        } catch {
          /* ignore */
        }
        const scan = await collectActivity(graphGetter(token), d, setStatus);
        setWarnings(scan.warnings);
        if (scan.parsed.sources.length) {
          setSum(foldActivity(sum ?? emptySummary(), scan.parsed));
          toast(scan.parsed.sources[0]);
        }
      } catch (e: any) {
        setErrors([e?.message ?? String(e)]);
      }
      setStatus(null);
    })();
  }, []);

  const cadence = useMemo(() => (sum ? cadenceRows(sum) : []), [sum]);
  const people = useMemo(() => {
    if (!sum) return [];
    const n = peopleQ.trim().toLowerCase();
    return Object.values(sum.users)
      .filter((u) => !n || [u.upn, u.name, u.id].some((v) => v?.toLowerCase().includes(n)))
      .map((u) => {
        const apps = Object.values(u.apps);
        const last = Math.max(0, ...apps.map((a) => Math.max(a.lastInteractive ?? 0, a.lastSilent ?? 0)));
        return { u, apps: apps.length, last };
      })
      .sort((a, b) => b.last - a.last)
      .slice(0, 200);
  }, [sum, peopleQ]);

  const onFiles = async (list: FileList | null) => {
    if (!list?.length) return;
    const errs: string[] = [];
    let next = sum ?? emptySummary();
    let read = 0;
    for (const f of Array.from(list)) {
      setStatus(`Reading ${f.name}…`);
      try {
        next = foldActivity(next, readActivityFile(f.name, await f.text()));
        read++;
      } catch (e: any) {
        errs.push(e.message);
      }
    }
    setStatus(null);
    setErrors(errs);
    if (read) {
      setSum(next);
      toast(`Read ${read} file${read === 1 ? "" : "s"}`);
    }
  };
  const signIn = async () => {
    setErrors([]);
    try {
      sessionStorage.setItem(DAYS_KEY, days);
    } catch {
      /* ignore */
    }
    await startSignIn({ tenantId, clientId, redirectUri }, { scopes: ACTIVITY_SCOPES, returnTo: "activity" });
    await new Promise((r) => setTimeout(r, 15000));
    throw new Error("Microsoft's sign-in page didn't open. Check the tenant ID and client ID, then try again.");
  };
  const loadSample = async () => {
    const parsed = readActivityFile("Sample activity (made up)", JSON.stringify(sampleActivityFile()));
    setSum({ ...foldActivity(emptySummary(), parsed), example: true });
    return "Sample activity loaded";
  };
  const blockReason = signInBlockReason(blocker, tenantId, clientId);
  const canSignIn = !blockReason;
  const tidForScript = GUID.test(tenantId) ? tenantId : "<your-tenant-id>";
  const scriptArgs = `-TenantId ${tidForScript} -Days ${days} -OutFile $HOME\\Downloads\\f360-activity.json`;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Activity</h1>
          <p>
            Who signed in to which app and when, from all four Entra sign-in log tabs, plus what provisioning (SCIM) sent to each app and the audit events
            that matter when someone leaves. Non-interactive sign-ins are silent token refreshes, so this page also measures how often each app really goes
            back to Entra. Only a small per-person summary is kept, in this browser. User lookup reads it.
          </p>
        </div>
        {sum && (
          <div className="row">
            <button className="btn" onClick={() => { setSum(null); setWarnings([]); toast("Activity cleared from this browser."); }}>Clear activity</button>
          </div>
        )}
      </div>

      {status && <BusyNote>{status}</BusyNote>}
      {errors.map((e) => <div key={e} className="callout crit">{e}</div>)}
      {warnings.map((w) => <div key={w} className="callout warn">{w}</div>)}

      <Section className="panel stack">
        <h2>{sum ? "Add more activity" : "Load activity"}</h2>
        <p className="small" style={{ maxWidth: "85ch" }}>
          Load as many files as you like; each one adds to the summary. On Entra ID Free, open the Entra admin center &gt; Sign-in logs, pick each tab (User
          sign-ins interactive, User sign-ins non-interactive, Service principal sign-ins, Managed identity sign-ins), then <strong>Download</strong> &gt;{" "}
          <strong>Download JSON</strong> (last 7 days). Audit logs download the same way. Provisioning logs and reading through Graph need P1. Entity 360's
          timeline CSV works too.
        </p>
        <div className="stack">
          <div className="stack">
            <h3>1. Files (works everywhere)</h3>
            <label className="small" htmlFor="act-files">Sign-in, audit or provisioning log JSON, an Export-F360Activity.ps1 file, or an Entity 360 CSV:</label>
            <input id="act-files" className="input" type="file" multiple accept=".json,.csv,application/json,text/csv" onChange={(e) => onFiles(e.target.files)} />
          </div>
          <hr style={{ border: 0, borderTop: "1px solid var(--line, #ddd)", width: "100%", margin: "4px 0" }} />
          <PowerShellRun title="2. PowerShell (P1 for sign-ins)" name={SCRIPT_NAME} script={activityScript} args={scriptArgs}>
            <p className="small muted">Then load f360-activity.json from your Downloads folder under 1. Files.</p>
          </PowerShellRun>
          <hr style={{ border: 0, borderTop: "1px solid var(--line, #ddd)", width: "100%", margin: "4px 0" }} />
          <div className="stack">
            <h3>3. Sign in from this page (P1 for sign-ins)</h3>
            <TenantClientFields prefix="act" tenantId={tenantId} setTenantId={setTenantId} clientId={clientId} setClientId={setClientId} />
            <Seg label="How far back" value={days} onChange={setDays} options={[{ v: "1", l: "1 day" }, { v: "7", l: "7 days" }, { v: "30", l: "30 days" }]} />
            <p className="small muted">
              Asks for {ACTIVITY_SCOPES.join(", ")} (delegated, read-only). Reads up to {ROW_LIMIT.toLocaleString()} rows of each kind. Sign in as Reports Reader,
              Security Reader or Global Reader.
            </p>
            <div className="row">
              <ActionButton className="btn primary" busy="Opening Microsoft sign-in…" disabled={!canSignIn} onClick={signIn}>Sign in and read</ActionButton>
            </div>
            <BlockedNote reason={blockReason} />
          </div>
        </div>
        <div className="row">
          <span className="small muted">Just looking?</span>
          <ActionButton busy="Loading the sample…" onClick={loadSample}>Try with sample data</ActionButton>
        </div>
      </Section>

      <LiveRefreshPanel />

      {sum && (
        <>
          <Section className="panel stack">
            <div className="spread">
              <div>
                <div className="eyebrow">Activity summary{sum.example ? " · made-up sample" : ""} · {when(sum.from)} to {when(sum.to)}</div>
                <h2>{Object.keys(sum.users).length} people, {cadence.length} apps with silent refreshes{sum.example && <> <span className="example-flag">Example</span></>}</h2>
              </div>
            </div>
            <div className="statline">
              <div><span className="n">{sum.counts.interactive.toLocaleString()}</span><span className="l">Interactive sign-ins</span></div>
              <div><span className="n">{sum.counts.nonInteractive.toLocaleString()}</span><span className="l">Silent refreshes (non-interactive)</span></div>
              <div><span className="n">{(sum.counts.servicePrincipal + sum.counts.managedIdentity).toLocaleString()}</span><span className="l">App and managed identity sign-ins</span></div>
              <div><span className="n">{sum.counts.provisioning.toLocaleString()}</span><span className="l">Provisioning events</span></div>
            </div>
            <details>
              <summary>Files read ({sum.sources.length})</summary>
              <ul className="small">{sum.sources.map((s, i) => <li key={i}>{s}</li>)}</ul>
            </details>
          </Section>

          <Section className="panel stack">
            <div className="panel-head"><h2>Refresh cadence per app</h2><span className="sub">How often each app really goes back to Entra</span></div>
            {cadence.length ? (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>App</th><th className="num">Typical gap</th><th className="num">90% of gaps under</th><th className="num">People</th><th className="num">Gaps measured</th><th>What it means</th></tr></thead>
                  <tbody>
                    {cadence.map((c) => (
                      <tr key={c.key}>
                        <td><strong>{c.app}</strong></td>
                        <td className="num">{c.medianMinutes !== undefined ? formatMinutes(c.medianMinutes) : "—"}</td>
                        <td className="num">{c.p90Minutes !== undefined ? formatMinutes(c.p90Minutes) : "—"}</td>
                        <td className="num">{c.users}</td>
                        <td className="num">{c.samples}</td>
                        <td className="small">{c.reading}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="muted">No silent refreshes yet. Load the non-interactive sign-ins tab to measure this.</p>
            )}
            <p className="small muted">A gap is the time between one person's silent refreshes to one app; refreshes within two minutes of each other count once.</p>
          </Section>

          {Object.keys(sum.workloads).length > 0 && (
            <Section className="panel stack">
              <div className="panel-head"><h2>Apps and managed identities signing in as themselves</h2><span className="sub">Not affected by disabling a person</span></div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Name</th><th>Kind</th><th>Resources</th><th className="num">Sign-ins</th><th>Last</th></tr></thead>
                  <tbody>
                    {Object.entries(sum.workloads).sort((a, b) => b[1].last - a[1].last).map(([k, w]) => (
                      <tr key={k}>
                        <td><strong>{w.name}</strong></td>
                        <td className="small">{w.kind === "servicePrincipal" ? "Service principal" : "Managed identity"}</td>
                        <td className="small">{w.resources.join(", ") || "—"}</td>
                        <td className="num">{w.count}</td>
                        <td className="small">{when(w.last)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          )}

          <Section className="panel stack">
            <div className="spread">
              <h2>People</h2>
              <button className="btn" onClick={() => go("userlookup")}>Open User lookup</button>
              <input aria-label="Search people" className="input" style={{ width: 240 }} placeholder="Search UPN, name or object ID…" value={peopleQ} onChange={(e) => setPeopleQ(e.target.value)} />
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Person</th><th className="num">Apps</th><th>Last activity</th><th>Account events</th><th></th></tr></thead>
                <tbody>
                  {people.map(({ u, apps, last }) => (
                    <tr key={u.key}>
                      <td><strong>{u.name || u.upn || u.id}</strong><div className="small mono">{u.upn || u.id}</div></td>
                      <td className="num">{apps}</td>
                      <td className="small">{when(last || undefined)}</td>
                      <td className="small">
                        {u.disabledAt && <div><Sev s="info" label="Disabled" /> {when(u.disabledAt)}</div>}
                        {u.sessionsRevokedAt && <div><Sev s="info" label="Sessions revoked" /> {when(u.sessionsRevokedAt)}</div>}
                        {!u.disabledAt && !u.sessionsRevokedAt && <span className="muted">None in these logs</span>}
                      </td>
                      <td><button className="btn sm" onClick={() => go("userlookup", { q: u.upn || u.id || u.name })}>Look up</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {people.length === 0 && <p className="muted">Nobody matches.</p>}
          </Section>
        </>
      )}
    </div>
  );
}

/** Token refreshes the Federation 360 Capture extension saw in this browser: the real cadence, as it happens. */
function LiveRefreshPanel() {
  const live = useBrowserCaptures();
  const { events, apps } = useMemo(() => liveRefreshes(live.flows.map(flowToCapture)), [live.flows]);
  const fmt = (t: number) => new Date(t).toLocaleTimeString();
  return (
    <Section className="panel stack">
      <div className="panel-head"><h2>Live refresh capture</h2><span className="sub">Token refreshes in this browser, recorded by the Federation 360 Capture extension</span></div>
      {!live.connected ? (
        <p className="small muted">
          The Capture extension isn't running in this browser. Load it as shown on <a href="#flowtracer">Flow tracer</a>, then keep an app open in another tab: each time it
          silently refreshes its token, the refresh appears here with the token lifetime that came back.
        </p>
      ) : !events.length ? (
        <p className="small muted">Capture {live.version} is running. No token refresh seen yet: keep a signed-in app open in another tab; most refresh within 60 to 90 minutes.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>App (client ID)</th><th className="num">Refreshes</th><th>Typical gap</th><th>Access token lifetime</th><th>Last</th><th>Failures</th></tr></thead>
            <tbody>
              {apps.map((a) => (
                <tr key={a.clientId}>
                  <td className="mono small">{a.clientId}</td>
                  <td className="num">{a.count}</td>
                  <td className="small">{a.medianGapMin !== undefined ? `${a.medianGapMin} min` : "needs 2 refreshes"}</td>
                  <td className="small">{a.lifetimeMin !== undefined ? `${a.lifetimeMin} min` : "not readable (opaque token)"}</td>
                  <td className="small">{fmt(a.last)}</td>
                  <td>{a.failures ? <Sev s="warn" label={String(a.failures)} /> : <span className="muted">0</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="small muted">Only what this browser does is seen here. The sign-in logs above show every person and device.</p>
    </Section>
  );
}

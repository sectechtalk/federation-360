import { useEffect, useMemo, useState } from "react";
import { CodeBlock, Field, Sev, useApp } from "../components/ui";
import { ActionButton, BusyNote, downloadFile } from "../components/busy";
import { BlockedNote, PowerShellRun, TenantClientFields, signInBlockReason, useTenantClient } from "../components/tenantSignIn";
import { usePref } from "../lib/store";
import { exposureText, lookupUser, parseUserAccess, type LookupResult, type LookupRow, type UserAccessSnapshot } from "../lib/lookup";
import { collectUserAccess, LOOKUP_SCOPES } from "../lib/lookupCollect";
import { graphGetter } from "../lib/postureCollect";
import { browserSignInBlocker, currentRedirectUri, redeemCode, startSignIn, takeRedirectResult } from "../lib/discovery/entraLive";
import { sampleUserAccess, SAMPLE_PEOPLE } from "../data/sampleUserAccess";
import { sampleAccess } from "../data/sampleAccess";
import { sampleActivityFile } from "../data/sampleActivity";
import { emptySummary, foldActivity, readActivityFile, findUsers } from "../lib/activity";
import { useAccessSnapshot } from "./AccessEnds";
import { useActivitySummary } from "./Activity";
import lookupScript from "../../lookup/Export-F360UserAccess.ps1?raw";
import { compareReads, containRunbook, DRILL_MARKS, r360DeviceUrl, r360OffboardUrl, R360_DEFAULT_URL, type ContainApp, type DrillMarks } from "../lib/contain";
import { Section } from "../components/Section";

const SCRIPT_NAME = "Export-F360UserAccess.ps1";
const GUID = /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
const WHO_KEY = "f360:lookup:who";
const when = (t?: number) => (t ? new Date(t).toLocaleString() : "none");
const EXPOSURE_SEV = (r: LookupRow): "ok" | "info" | "warn" | "critical" =>
  r.exposure.kind === "none" ? "ok" : r.exposure.kind === "unknown" ? "warn" : r.exposure.minutes > 24 * 60 ? "critical" : r.exposure.minutes > 60 ? "warn" : "info";

/** Last per-person reads, newest first, keyed by lower-case UPN. */
export function useUserReads() {
  return usePref<Record<string, UserAccessSnapshot>>("lookup:reads", {});
}
const openTab = (url: string) => {
  const w = window.open(url, "_blank", "noopener");
  if (!w) throw new Error(`The browser blocked the new tab. Open this address yourself: ${url}`);
  return "Opened Remediation 360 in a new tab. Sign in, click Elevate to write, then Run request.";
};

export default function UserLookup() {
  const { tenants, apps, params, go, toast } = useApp();
  const entraTenants = tenants.filter((t) => t.platform === "entra" && GUID.test(t.tenantRef) && !t.example);
  const [tenantId, setTenantId, clientId, setClientId] = useTenantClient(entraTenants[0]?.tenantRef ?? "");
  const [access, setAccess] = useAccessSnapshot();
  const [activity, setActivity] = useActivitySummary();
  const [reads, setReads] = useUserReads();
  const [previous, setPrevious] = usePref<Record<string, UserAccessSnapshot>>("lookup:previous", {});
  const [r360Url, setR360Url] = usePref("remediation:url", R360_DEFAULT_URL);
  const [drill, setDrill] = usePref<DrillMarks>("lookup:drill", {});
  const [q, setQ] = useState(params.q ?? "");
  const [shown, setShown] = useState(params.q ?? "");
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const blocker = browserSignInBlocker();
  const redirectUri = currentRedirectUri();

  const saveRead = (s: UserAccessSnapshot) => {
    const key = s.user.upn.toLowerCase() || s.user.id.toLowerCase();
    // Keep the read it replaces, so Verify can show what changed.
    if (reads[key] && reads[key].collectedAt !== s.collectedAt) setPrevious({ ...previous, [key]: reads[key] });
    const next = { [key]: s, ...Object.fromEntries(Object.entries(reads).filter(([k]) => k !== key).slice(0, 19)) };
    setReads(next);
    setShown(s.user.upn || s.user.id);
    setQ(s.user.upn || s.user.id);
  };

  useEffect(() => {
    const r = takeRedirectResult("userlookup");
    if (!r) return;
    if (r.error || !r.code || !r.pending) {
      setError(r.error ?? "Sign-in didn't complete.");
      return;
    }
    (async () => {
      try {
        let who = "";
        try {
          who = sessionStorage.getItem(WHO_KEY) ?? "";
        } catch {
          /* ignore */
        }
        if (!who) throw new Error("Type the person's sign-in name again, then click Read from Entra.");
        setStatus("Signed in. Getting a read-only token…");
        const token = await redeemCode(r.code!, r.pending!);
        const s = await collectUserAccess(graphGetter(token), who, setStatus);
        saveRead(s);
        toast(`Read ${s.user.upn}: ${s.assignments.length} assignments, ${s.grants.length} consent grants`);
      } catch (e: any) {
        setError(e?.message ?? String(e));
      }
      setStatus(null);
    })();
  }, []);

  const snapshot = useMemo(() => {
    const n = shown.trim().toLowerCase();
    if (!n) return null;
    return reads[n] ?? Object.values(reads).find((s) => s.user.id.toLowerCase() === n || s.user.name.toLowerCase() === n) ?? null;
  }, [reads, shown]);
  const result: LookupResult | null = useMemo(
    () => (shown.trim() ? lookupUser({ query: shown, snapshot, access, activity, inventory: apps }) : null),
    [shown, snapshot, access, activity, apps],
  );
  const suggestions = useMemo(() => (activity && q.trim().length >= 2 && q !== shown ? findUsers(activity, q).slice(0, 8) : []), [activity, q, shown]);

  const readFromEntra = async () => {
    setError(null);
    const who = q.trim();
    if (!who) throw new Error("Type the person's sign-in name (UPN) or object ID first.");
    try {
      sessionStorage.setItem(WHO_KEY, who);
    } catch {
      /* ignore */
    }
    await startSignIn({ tenantId, clientId, redirectUri }, { scopes: LOOKUP_SCOPES, returnTo: "userlookup" });
    await new Promise((r) => setTimeout(r, 15000));
    throw new Error("Microsoft's sign-in page didn't open. Check the tenant ID and client ID, then try again.");
  };
  const onFile = async (f: File | undefined) => {
    if (!f) return;
    setError(null);
    try {
      saveRead(parseUserAccess(await f.text()));
      toast(`Loaded ${f.name}`);
    } catch (e: any) {
      setError(e.message);
    }
  };
  const loadSample = async () => {
    const now = new Date();
    for (const p of SAMPLE_PEOPLE) {
      const s = sampleUserAccess(p, now)!;
      reads[p] = s;
    }
    setReads({ ...reads });
    setAccess(sampleAccess(now));
    setActivity({ ...foldActivity(emptySummary(), readActivityFile("Sample activity (made up)", JSON.stringify(sampleActivityFile(now))), now), example: true });
    setShown(SAMPLE_PEOPLE[1]);
    setQ(SAMPLE_PEOPLE[1]);
    return "Sample tenant loaded: try sam.leaver@contoso.example and gray.finance@contoso.example";
  };
  const blockReason = signInBlockReason(blocker, tenantId, clientId, q.trim() ? null : "Type a person in the box at the top to turn on Read from Entra.");
  const canSignIn = !blockReason;
  const tidForScript = GUID.test(tenantId) ? tenantId : "<your-tenant-id>";
  const scriptArgs = `-TenantId ${tidForScript} -User ${q.trim() || "someone@contoso.com"}`;
  const isExample = !!(snapshot?.example || (activity?.example && !snapshot));

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>User lookup</h1>
          <p>
            One person, every app they can reach: assigned directly or through a group, consented, or simply signed in to. For each app, when they last used it,
            whether their tokens are likely still live, what SCIM last did, and how long they could still get in if you disabled them now, longest first.
            Read-only.
          </p>
        </div>
      </div>

      {status && <BusyNote>{status}</BusyNote>}
      {error && <div className="callout crit">{error}</div>}

      <Section className="panel stack">
        <h2>Find a person</h2>
        <div className="row" style={{ alignItems: "flex-end" }}>
          <div style={{ flex: "1 1 320px" }}>
            <Field id="ul-q" label="Person (sign-in name, name or object ID)" value={q} onChange={setQ} placeholder="someone@contoso.com" />
          </div>
          <ActionButton className="btn primary" busy="Looking up…" disabled={!q.trim()} onClick={async () => { setShown(q.trim()); return `Showing ${q.trim()}`; }}>Look up</ActionButton>
        </div>
        {suggestions.length > 0 && (
          <div className="row">
            <span className="small muted">In the activity:</span>
            {suggestions.map((u) => (
              <button key={u.key} className="btn sm" onClick={() => { const v = u.upn || u.id || u.name; setQ(v); setShown(v); toast(`Showing ${v}`); }}>{u.upn || u.name || u.id}</button>
            ))}
          </div>
        )}
        <p className="small muted">
          Uses what this browser already holds: {Object.keys(reads).length} Entra read{Object.keys(reads).length === 1 ? "" : "s"} of people,{" "}
          {activity ? <>activity from {when(activity.from)} to {when(activity.to)}</> : <>no activity (<a href="#activity" onClick={(e) => { e.preventDefault(); go("activity"); }}>load it on Activity</a>)</>}, and{" "}
          {access ? <>the How access ends scan of {new Date(access.collectedAt).toLocaleDateString()}</> : <>no access scan (<a href="#access" onClick={(e) => { e.preventDefault(); go("access"); }}>read it on How access ends</a>)</>}.
        </p>
        <details>
          <summary>Read this person's assignments, consents and devices from Entra</summary>
          <div className="stack" style={{ marginTop: 8 }}>
            <PowerShellRun title="1. PowerShell (works everywhere)" name={SCRIPT_NAME} script={lookupScript} args={scriptArgs}>
              <label className="small" htmlFor="ul-file">Then load the file it saves (in the folder PowerShell was in):</label>
              <input id="ul-file" className="input" type="file" accept=".json,application/json" onChange={(e) => onFile(e.target.files?.[0])} />
            </PowerShellRun>
            <hr style={{ border: 0, borderTop: "1px solid var(--line, #ddd)", width: "100%", margin: "4px 0" }} />
            <div className="stack">
              <h3>2. Sign in from this page</h3>
              <TenantClientFields prefix="ul" tenantId={tenantId} setTenantId={setTenantId} clientId={clientId} setClientId={setClientId} />
              <p className="small muted">Asks for {LOOKUP_SCOPES.join(", ")} (delegated, read-only). Last sign-in times need Entra ID P1.</p>
              <div className="row"><ActionButton className="btn primary" busy="Opening Microsoft sign-in…" disabled={!canSignIn} onClick={readFromEntra}>Read from Entra</ActionButton></div>
              <BlockedNote reason={blockReason} />
            </div>
          </div>
          <div className="row" style={{ marginTop: 8 }}>
            <span className="small muted">Just looking?</span>
            <ActionButton busy="Loading the sample…" onClick={loadSample}>Try with sample data</ActionButton>
          </div>
        </details>
      </Section>

      {shown && !result && <div className="callout warn">Nothing found for {shown}. Read them from Entra above, or load activity that includes them.</div>}

      {result && (
        <>
          <Section className="panel">
            <div className="spread">
              <div>
                <div className="eyebrow">{result.sources.join(" · ")}</div>
                <h2>{result.user.name || result.user.upn}{isExample && <> <span className="example-flag">Example</span></>}</h2>
                <span className="small mono">{result.user.upn}{result.user.id && ` · ${result.user.id}`}</span>
              </div>
              <div className="stack small" style={{ textAlign: "right" }}>
                <span>Account: {result.user.enabled === undefined ? <span className="muted">not read</span> : result.user.enabled ? <Sev s="info" label="Enabled" /> : <Sev s="ok" label="Disabled" />}</span>
                {result.user.sessionsValidFrom && <span>Sessions valid from {when(result.user.sessionsValidFrom)}</span>}
                {result.user.disabledAt && <span>Disabled {when(result.user.disabledAt)} (audit log)</span>}
                {result.user.sessionsRevokedAt && <span>Sessions revoked {when(result.user.sessionsRevokedAt)} (audit log)</span>}
              </div>
            </div>
            {result.warnings.map((w) => <div key={w} className="callout warn" style={{ marginTop: 8 }}>{w}</div>)}
          </Section>

          <div className="statline">
            <div><span className="n">{result.rows.length}</span><span className="l">Apps they can reach or used</span></div>
            <div><span className="n" style={{ color: result.longest && result.longest.exposure.kind === "minutes" && result.longest.exposure.minutes > 60 ? "var(--warn)" : undefined }}>{result.longest ? exposureText(result.longest.exposure) : "None"}</span><span className="l">Longest known exposure{result.longest ? ` (${result.longest.app})` : ""}</span></div>
            <div><span className="n" style={{ color: result.unknownCount ? "var(--warn)" : undefined }}>{result.unknownCount}</span><span className="l">Apps where the app's own session is unknown</span></div>
            <div><span className="n">{result.rows.filter((r) => r.prtDevices.length).length}</span><span className="l">Apps reached with device SSO (PRT)</span></div>
          </div>

          <Section className="panel stack">
            <div className="panel-head"><h2>Every app, longest exposure first</h2><span className="sub">{result.user.enabled === false ? `${result.user.name || "They"} is disabled: how long each app could still let them in` : `If you disabled ${result.user.name || "them"} and revoked sessions now`}</span></div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>App</th><th>How they get in</th><th>Last used</th><th>Tokens</th><th>SCIM</th><th>{result.user.enabled === false ? "Still open for" : "Exposure if disabled now"}</th><th></th></tr></thead>
                <tbody>
                  {result.rows.map((r) => (
                    <tr key={r.key}>
                      <td>
                        {r.inventoryId ? <a href="#inventory" onClick={(e) => { e.preventDefault(); go("inventory", { app: r.inventoryId! }); }}><strong>{r.app}</strong></a> : <strong>{r.app}</strong>}
                        <div className="small muted">{r.protocol ? r.protocol.toUpperCase() : "Protocol unknown"}</div>
                        {r.watch.map((w) => <div key={w} className="small" style={{ color: "var(--warn)" }}>{w}</div>)}
                      </td>
                      <td className="small">{r.access.map((a) => <div key={a}>{a}</div>)}</td>
                      <td className="small">
                        <div>Sign-in: {when(r.lastInteractive)}</div>
                        <div className="muted">Silent refresh: {when(r.lastSilent)}</div>
                        {r.lastFailure && r.lastFailure.time > (r.lastInteractive ?? 0) && <div style={{ color: "var(--crit)" }}>Failed {when(r.lastFailure.time)} ({r.lastFailure.code})</div>}
                      </td>
                      <td className="small">{r.tokens}</td>
                      <td><Sev s={r.scimSeverity} label={r.scim} />{r.scimDetail && <div className="small" style={{ color: "var(--crit)", maxWidth: 220 }}>{r.scimDetail}</div>}</td>
                      <td><Sev s={EXPOSURE_SEV(r)} label={exposureText(r.exposure)} /><div className="small muted">{r.exposure.why}</div></td>
                      <td><button className="btn sm" aria-expanded={open === r.key} onClick={() => setOpen(open === r.key ? null : r.key)}>{open === r.key ? "Hide" : "Details"}</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {open && result.rows.find((r) => r.key === open) && <RowDetails row={result.rows.find((r) => r.key === open)!} upn={result.user.upn} r360Url={r360Url} />}
            <p className="small muted">
              Exposure is the longer of the access token they already hold and what's left of the app's own session (declared in Inventory). Revoking sessions stops
              new tokens and refresh tokens at once, but a token already issued works until it expires; only Microsoft's own services cut it early (CAE). "Worst
              case" means the loaded activity has no sign-in for that app, so the full lifetime is assumed.
            </p>
          </Section>

          <ContainPanel
            result={result}
            snapshot={snapshot}
            before={snapshot ? previous[(snapshot.user.upn || snapshot.user.id).toLowerCase()] ?? null : null}
            r360Url={r360Url}
            setR360Url={setR360Url}
            tenantId={tenantId}
            canVerify={canSignIn}
            verify={readFromEntra}
            drill={drill}
            setDrill={setDrill}
          />

          {result.devices.length > 0 && (
            <Section className="panel stack">
              <div className="panel-head"><h2>Devices</h2><span className="sub">A device with a Primary Refresh Token signs them in to apps without a prompt</span></div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Device</th><th>OS</th><th>Join type</th><th>Enabled</th><th></th></tr></thead>
                  <tbody>
                    {result.devices.map((d) => (
                      <tr key={d.id}><td><strong>{d.name}</strong></td><td className="small">{d.os}</td><td className="small">{d.trustType === "AzureAd" ? "Entra joined" : d.trustType === "ServerAd" ? "Hybrid joined" : d.trustType === "Workplace" ? "Registered" : d.trustType || "—"}</td><td>{d.enabled ? <Sev s="info" label="Yes" /> : <Sev s="ok" label="No" />}</td><td><ActionButton className="btn sm" busy="Opening Remediation 360…" onClick={() => openTab(r360DeviceUrl(r360Url, d.name))}>Isolate in Remediation 360</ActionButton></td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          )}
        </>
      )}
    </div>
  );
}

function RowDetails({ row, upn, r360Url }: { row: LookupRow; upn: string; r360Url: string }) {
  const a = row.access_row;
  return (
    <Section className="panel stack">
      <div className="panel-head"><h2>{row.app}</h2><span className="sub">Why the window is what it is</span></div>
      {row.spId && upn && (
        <div className="row">
          <ActionButton className="btn primary" busy="Opening Remediation 360…" onClick={() => openTab(r360OffboardUrl(r360Url, "remove", upn, [{ spId: row.spId, name: row.app }]))}>Remove from this app in Remediation 360</ActionButton>
          <span className="small muted">Removes the direct assignment and runs Provision on demand for this app only. The account stays enabled.</span>
        </div>
      )}
      <dl className="kv">
        <dt>Exposure</dt><dd>{exposureText(row.exposure)}. {row.exposure.why}</dd>
        <dt>Tokens</dt><dd>{row.tokens}</dd>
        {row.prtDevices.length > 0 && <><dt>Device SSO from</dt><dd>{row.prtDevices.join(", ")}</dd></>}
        {a ? (
          <>
            <dt>Token life</dt><dd>{a.accessToken.min === a.accessToken.max ? `${a.accessToken.max} min` : `${a.accessToken.min} to ${a.accessToken.max} min`} ({a.accessToken.source === "default" ? "Entra default" : a.accessToken.policy})</dd>
            <dt>CAE</dt><dd>{a.cae.text}</dd>
            <dt>SCIM job</dt><dd>{a.scim.label}. {a.scim.detail}</dd>
            <dt>App session (declared)</dt><dd>{a.profile?.sessionMinutes ? `${a.profile.sessionMinutes} min; ends on SCIM disable: ${a.profile.endsSessionOnScimDisable}` : "Not recorded"}</dd>
          </>
        ) : (
          <><dt>Access settings</dt><dd className="muted">Not in the How access ends scan.</dd></>
        )}
      </dl>
    </Section>
  );
}

function ContainPanel(props: {
  result: LookupResult;
  snapshot: UserAccessSnapshot | null;
  before: UserAccessSnapshot | null;
  r360Url: string;
  setR360Url: (v: string) => void;
  tenantId: string;
  canVerify: boolean;
  verify: () => Promise<void>;
  drill: DrillMarks;
  setDrill: (d: DrillMarks) => void;
}) {
  const { result, snapshot, before, r360Url, setR360Url, tenantId, canVerify, verify, drill, setDrill } = props;
  const upn = result.user.upn;
  const apps: ContainApp[] = result.rows.filter((r) => r.spId).map((r) => ({ spId: r.spId, name: r.app }));
  const changes = before && snapshot ? compareReads(before, snapshot) : null;
  const t0 = drill.disabled;
  return (
    <Section className="panel stack">
      <div className="panel-head"><h2>Contain</h2><span className="sub">Federation 360 never writes. Remediation 360 does, as you, and audits every step.</span></div>
      <div className="grid-2">
        <div className="stack">
          <h3>Disable user everywhere</h3>
          <p className="small">Disables the account, revokes every session, then runs Provision on demand in each SCIM app ({apps.length} app{apps.length === 1 ? "" : "s"} from this lookup) so they hear about it now instead of in about 40 minutes.</p>
          <div className="row">
            <ActionButton className="btn primary" busy="Opening Remediation 360…" disabled={!upn} onClick={() => openTab(r360OffboardUrl(r360Url, "disable", upn, apps))}>Disable user everywhere in Remediation 360</ActionButton>
          </div>
          <p className="small muted">To remove them from just one app, open <strong>Details</strong> on that app. To isolate a device, use <strong>Isolate in Remediation 360</strong> under Devices.</p>
          <Field id="ul-remediation" label="Remediation 360 address" value={r360Url} onChange={setR360Url} placeholder={R360_DEFAULT_URL} />
        </div>
        <div className="stack">
          <h3>Or run it yourself</h3>
          <p className="small">The same steps as PowerShell. It only shows what it would do until you add <span className="mono">-Run</span>.</p>
          <div className="row">
            <ActionButton className="btn primary" busy="Writing the runbook…" disabled={!upn} onClick={async () => downloadFile("Contain-F360User.ps1", containRunbook({ upn, tenantId, apps, generatedAt: new Date() }))}>Download contain runbook</ActionButton>
          </div>
          <CodeBlock code={"cd $HOME\\Downloads\nUnblock-File .\\Contain-F360User.ps1\n.\\Contain-F360User.ps1        # what if\n.\\Contain-F360User.ps1 -Run   # do it"} />
        </div>
      </div>

      <h3>Verify</h3>
      <p className="small">After Remediation 360 or the runbook finishes, read the person again. This compares the new read with the one before it.</p>
      <div className="row">
        <ActionButton className="btn primary" busy="Opening Microsoft sign-in…" disabled={!canVerify} title={canVerify ? undefined : "Fill in the tenant ID and client ID under Read this person's assignments first."} onClick={verify}>Verify with a fresh read</ActionButton>
        {!canVerify && <span className="small muted">Needs the tenant ID and client ID above, or load a new PowerShell export.</span>}
      </div>
      {changes ? (
        <div className="table-wrap">
          <table>
            <thead><tr><th>What</th><th>Before ({new Date(before!.collectedAt).toLocaleString()})</th><th>After ({new Date(snapshot!.collectedAt).toLocaleString()})</th><th></th></tr></thead>
            <tbody>
              {changes.map((c) => (
                <tr key={c.what}><td>{c.what}</td><td className="small">{c.before}</td><td className="small">{c.after}</td><td><Sev s={c.good ? "ok" : "warn"} label={c.good ? "As expected" : "Check"} /></td></tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="small muted">No earlier read of this person in this browser yet, so there is nothing to compare.</p>
      )}

      <details>
        <summary>Lab offboarding drill (lab.user1 in your lab tenant)</summary>
        <ol className="small">
          <li>In a private window, open the lab test app and sign in as <span className="mono">lab.user1@&lt;your lab domain&gt;</span>. Leave it open.</li>
          <li>Here, look up <span className="mono">lab.user1@&lt;your lab domain&gt;</span> and click <strong>Read from Entra</strong> with the lab tenant ID and the F360-Discovery client ID.</li>
          <li>Click <strong>Download contain runbook</strong>, run it once without <span className="mono">-Run</span>, then with <span className="mono">-Run</span>, signed in as the lab admin account. (Remediation 360 acts on its own tenant only, so the lab uses the runbook.)</li>
          <li>Mark each moment below as it happens. Refresh the lab test app every few minutes until it refuses lab.user1.</li>
          <li>Click <strong>Verify with a fresh read</strong>. Afterwards, re-enable lab.user1 in the lab: Entra admin center, Users, lab.user1, Edit properties, Account enabled.</li>
        </ol>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Moment</th><th>Marked at</th><th>Minutes after the disable</th><th></th></tr></thead>
            <tbody>
              {DRILL_MARKS.map((m) => (
                <tr key={m.id}>
                  <td>{m.label}</td>
                  <td className="small">{drill[m.id] ? new Date(drill[m.id]!).toLocaleTimeString() : "not yet"}</td>
                  <td className="small">{drill[m.id] && t0 ? Math.round((drill[m.id]! - t0) / 60000) : "—"}</td>
                  <td><ActionButton className="btn sm" busy="Marking…" onClick={() => { setDrill({ ...drill, [m.id]: Date.now() }); return `Marked at ${new Date().toLocaleTimeString()}`; }}>Mark now</ActionButton></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="row"><ActionButton busy="Clearing…" onClick={() => { setDrill({}); return "Drill marks cleared"; }}>Clear the drill marks</ActionButton></div>
      </details>
    </Section>
  );
}

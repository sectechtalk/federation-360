import { useEffect, useMemo, useState } from "react";
import { CodeBlock, Field, FindingList, Seg, Sev, useApp } from "../components/ui";
import { ActionButton, BusyNote, downloadFile } from "../components/busy";
import { usePref } from "../lib/store";
import {
  LEVEL_LABEL, METHOD_LABEL, mfaReport, parsePosture, PORTAL, SIGNIN_LABEL, ssoReport, waveCsv,
  type MfaLevel, type PostureSnapshot,
} from "../lib/posture";
import { collectPosture, graphGetter, POSTURE_SCOPES, USER_LIMIT } from "../lib/postureCollect";
import { browserSignInBlocker, currentRedirectUri, redeemCode, startSignIn, takeRedirectResult } from "../lib/discovery/entraLive";
import { samplePosture } from "../data/samplePosture";
import postureScript from "../../posture/Export-F360Posture.ps1?raw";

const SCRIPT_NAME = "Export-F360Posture.ps1";
const GUID = /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
const LEVEL_SEV: Record<MfaLevel, "ok" | "warn" | "critical"> = { "phishing-resistant": "ok", phishable: "warn", none: "critical" };

export default function Posture() {
  const { tenants, apps, go, toast } = useApp();
  const entraTenants = tenants.filter((t) => t.platform === "entra" && GUID.test(t.tenantRef) && !t.example);
  const [tenantId, setTenantId] = usePref("discover:tenantId", entraTenants[0]?.tenantRef ?? "");
  const [clientId, setClientId] = usePref("discover:clientId", "");
  const [snap, setSnap] = usePref<PostureSnapshot | null>("posture:snapshot", null);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [level, setLevel] = useState<"all" | MfaLevel | "admins">("all");
  const [q, setQ] = useState("");
  const blocker = browserSignInBlocker();
  const redirectUri = currentRedirectUri();

  // Coming back from Microsoft's sign-in page.
  useEffect(() => {
    const r = takeRedirectResult("posture");
    if (!r) return;
    if (r.error || !r.code || !r.pending) {
      setError(r.error ?? "Sign-in didn't complete.");
      return;
    }
    (async () => {
      try {
        setStatus("Signed in. Getting a read-only token…");
        const token = await redeemCode(r.code!, r.pending!);
        const s = await collectPosture(graphGetter(token), r.pending!.tenantId, setStatus);
        setSnap(s);
        toast(`Read ${s.users.length} users and ${s.apps.length} enterprise apps`);
      } catch (e: any) {
        setError(e?.message ?? String(e));
      }
      setStatus(null);
    })();
  }, []);

  const mfa = useMemo(() => (snap ? mfaReport(snap) : null), [snap]);
  const sso = useMemo(() => (snap ? ssoReport(snap, apps) : null), [snap, apps]);

  const onFile = async (f: File | undefined) => {
    if (!f) return;
    setError(null);
    try {
      setSnap(parsePosture(await f.text()));
      toast(`Loaded ${f.name}`);
    } catch (e: any) {
      setError(e.message);
    }
  };
  const signIn = async () => {
    setError(null);
    await startSignIn({ tenantId, clientId, redirectUri }, { scopes: POSTURE_SCOPES, returnTo: "posture" });
    await new Promise((r) => setTimeout(r, 15000));
    throw new Error("Microsoft's sign-in page didn't open. Check the tenant ID and client ID, then try again.");
  };
  const loadSample = async () => {
    setSnap(samplePosture());
    return "Sample tenant loaded";
  };
  const downloadScript = async () => downloadFile(SCRIPT_NAME, postureScript);
  const canSignIn = !blocker && GUID.test(tenantId) && GUID.test(clientId);
  const tidForScript = GUID.test(tenantId) ? tenantId : "<your-tenant-id>";
  const commands = `cd $HOME\\Downloads\nUnblock-File .\\${SCRIPT_NAME}\n.\\${SCRIPT_NAME} -TenantId ${tidForScript} -OutFile $HOME\\Downloads\\f360-posture.json`;

  const needle = q.trim().toLowerCase();
  const shownUsers = (mfa?.members ?? []).filter(
    (u) =>
      (level === "all" || (level === "admins" ? u.admin : u.level === level)) &&
      (!needle || [u.upn, u.name, ...u.roles].some((v) => v.toLowerCase().includes(needle))),
  );

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>MFA and SSO coverage</h1>
          <p>
            How many people can sign in with a phishing-resistant method (passkey, Windows Hello, Platform SSO), which admins can't yet, a staged plan to
            get everyone there, and how many enterprise apps really sit behind single sign-on, assignment and SCIM. Read-only, and it works on Entra ID Free.
          </p>
        </div>
        {snap && (
          <div className="row">
            <button className="btn" onClick={() => { setSnap(null); toast("Scan cleared from this browser."); }}>Clear this scan</button>
          </div>
        )}
      </div>

      {status && <BusyNote>{status}</BusyNote>}
      {error && <div className="callout crit">{error}</div>}

      {!snap && (
        <section className="panel stack">
          <h2>Read your tenant</h2>
          <p className="small" style={{ maxWidth: "80ch" }}>
            Federation 360 reads the authentication methods policy, security defaults, admin roles, the <em>types</em> of sign-in method each user has
            registered (never phone numbers or keys) and each enterprise app's single sign-on mode and assignment setting. Microsoft's own registration report
            needs Entra ID P1, so this page counts methods user by user instead; that works on Free. Sign in as Global Reader, Authentication Administrator or
            Global Administrator.
          </p>
          <div className="grid-2">
            <div className="stack">
              <h3>1. PowerShell (works everywhere)</h3>
              <div className="row">
                <ActionButton className="btn primary" busy="Preparing the script…" onClick={downloadScript}>Download {SCRIPT_NAME}</ActionButton>
              </div>
              <CodeBlock code={commands} />
              <label className="small" htmlFor="p-file">Then load the file it saves (f360-posture.json):</label>
              <input id="p-file" className="input" type="file" accept=".json,application/json" onChange={(e) => onFile(e.target.files?.[0])} />
            </div>
            <div className="stack">
              <h3>2. Sign in from this page</h3>
              <Field id="p-tid" label="Directory (tenant) ID" value={tenantId} onChange={setTenantId} placeholder="00000000-0000-0000-0000-000000000000" error={tenantId && !GUID.test(tenantId) ? "A tenant ID is a GUID." : null} />
              <Field id="p-cid" label="Client ID of F360-Discovery" value={clientId} onChange={setClientId} placeholder="the same app Discover uses" error={clientId && !GUID.test(clientId) ? "A client ID is a GUID." : null} />
              <p className="small muted">
                Asks for {POSTURE_SCOPES.join(", ")} (delegated, read-only). The first time, an admin sees Microsoft's consent screen for the two new ones.
                Reads up to {USER_LIMIT} users; use the script for more. {blocker && <strong>{blocker}</strong>}
              </p>
              <div className="row">
                <ActionButton className="btn primary" busy="Opening Microsoft sign-in…" disabled={!canSignIn} onClick={signIn}>Sign in and read</ActionButton>
              </div>
            </div>
          </div>
          <div className="row">
            <span className="small muted">Just looking?</span>
            <ActionButton busy="Loading the sample…" onClick={loadSample}>Load the sample tenant</ActionButton>
          </div>
        </section>
      )}

      {snap && mfa && sso && (
        <>
          <section className="panel">
            <div className="spread">
              <div>
                <div className="eyebrow">Scan · {new Date(snap.collectedAt).toLocaleString()} · {snap.collector === "sample" ? "made-up sample" : snap.collector === "powershell" ? "from PowerShell" : "from this page"}</div>
                <h2>{snap.tenant.name || snap.tenant.id}{snap.example && <> <span className="example-flag">Example</span></>}</h2>
                <span className="small mono">{snap.tenant.id}{snap.tenant.domain && ` · ${snap.tenant.domain}`}</span>
              </div>
              <span className="small">
                Security defaults: <strong>{snap.securityDefaults === null ? "not read" : snap.securityDefaults ? "on" : "off"}</strong>{" "}
                <a href={PORTAL.securityDefaults} target="_blank" rel="noreferrer">change ↗</a>
              </span>
            </div>
            {snap.warnings.map((w) => <div key={w} className="callout warn" style={{ marginTop: 8 }}>{w}</div>)}
          </section>

          <div className="statline">
            <div><span className="n" style={{ color: mfa.percent["phishing-resistant"] >= 90 ? "var(--ok)" : "var(--warn)" }}>{mfa.percent["phishing-resistant"]}%</span><span className="l">People with a phishing-resistant method ({mfa.counts["phishing-resistant"]} of {mfa.members.length})</span></div>
            <div><span className="n" style={{ color: mfa.adminsResistant < mfa.admins.length ? "var(--crit)" : undefined }}>{mfa.adminsResistant} of {mfa.admins.length}</span><span className="l">Admins with a phishing-resistant method</span></div>
            <div><span className="n" style={{ color: mfa.counts.phishable ? "var(--warn)" : undefined }}>{mfa.counts.phishable}</span><span className="l">People with phishable MFA only (push, code, SMS)</span></div>
            <div><span className="n" style={{ color: mfa.counts.none ? "var(--crit)" : undefined }}>{mfa.counts.none}</span><span className="l">People with no MFA method</span></div>
          </div>

          <div className="meter" role="img" aria-label={`Phishing-resistant ${mfa.percent["phishing-resistant"]}%, phishable ${mfa.percent.phishable}%, none ${mfa.percent.none}%`}>
            <span className="meter-ok" style={{ width: `${mfa.percent["phishing-resistant"]}%` }} />
            <span className="meter-warn" style={{ width: `${mfa.percent.phishable}%` }} />
            <span className="meter-crit" style={{ width: `${mfa.percent.none}%` }} />
          </div>
          <p className="small muted">
            Counts enabled member accounts only. {mfa.guests} guest{mfa.guests === 1 ? "" : "s"} (they do MFA in their own tenant) and {mfa.disabled} disabled
            account{mfa.disabled === 1 ? "" : "s"} are left out.
          </p>

          {mfa.findings.length > 0 && (
            <section className="panel stack">
              <div className="panel-head"><h2>What needs you</h2><span className="sub">Most urgent first</span></div>
              <FindingList findings={mfa.findings} />
            </section>
          )}

          <section className="panel stack">
            <div className="panel-head">
              <h2>Rollout plan: phishing-resistant MFA in three waves</h2>
              <span className="sub">Staged, with a way back at every step</span>
            </div>
            <ol className="small stack" style={{ maxWidth: "90ch", paddingLeft: 18 }}>
              <li>
                <strong>Turn passkeys on for one group.</strong> Authentication methods &gt; Policies &gt; Passkey (FIDO2): Enable, target a security group for the
                current wave, allow self-service set up. Leave Microsoft Authenticator on so nobody is locked out. <a href={PORTAL.methodsPolicy} target="_blank" rel="noreferrer">Authentication methods policies ↗</a>
              </li>
              <li>
                <strong>People register.</strong> Each person adds a passkey (in Microsoft Authenticator, a security key or Windows Hello) at <a href={PORTAL.registerMethods} target="_blank" rel="noreferrer">My Sign-ins &gt; Security info ↗</a>.
                Someone with nothing usable gets a Temporary Access Pass from the helpdesk first (free).
              </li>
              <li>
                <strong>Enforce, then widen.</strong> With Entra ID P1, a Conditional Access policy requiring the <em>Phishing-resistant MFA</em> authentication
                strength for the wave's group, in report-only for a week, then on. On Free there's no enforcement; security defaults keep requiring MFA of any kind.
              </li>
              <li>
                <strong>Rollback.</strong> Put the Conditional Access policy back to report-only, or take the group off the passkey policy. Nobody loses their other
                methods, so sign-in keeps working.
              </li>
            </ol>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Wave</th><th>Why this order</th><th className="num">Done</th><th className="num">Still to go</th><th>People</th></tr></thead>
                <tbody>
                  {mfa.waves.map((w) => (
                    <tr key={w.id}>
                      <td><strong>{w.title}</strong></td>
                      <td className="small">{w.why}</td>
                      <td className="num">{w.done}</td>
                      <td className="num">{w.todo.length ? <Sev s={w.id === "admins" ? "critical" : "warn"} label={String(w.todo.length)} /> : <Sev s="ok" label="0" />}</td>
                      <td>
                        <ActionButton className="btn sm" busy="Building the list…" disabled={!w.todo.length} onClick={async () => downloadFile(`f360-${w.id}-wave.csv`, waveCsv(w), "text/csv")}>
                          {w.todo.length ? `Download list (${w.todo.length})` : "Nobody left"}
                        </ActionButton>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="panel stack">
            <div className="spread">
              <h2>People</h2>
              <div className="row">
                <Seg
                  label="Show"
                  value={level}
                  onChange={setLevel}
                  options={[
                    { v: "all", l: `All (${mfa.members.length})` },
                    { v: "admins", l: `Admins (${mfa.admins.length})` },
                    { v: "phishing-resistant", l: `Phishing-resistant (${mfa.counts["phishing-resistant"]})` },
                    { v: "phishable", l: `Phishable (${mfa.counts.phishable})` },
                    { v: "none", l: `None (${mfa.counts.none})` },
                  ]}
                />
                <input aria-label="Search people" className="input" style={{ width: 220 }} placeholder="Search name, UPN, role…" value={q} onChange={(e) => setQ(e.target.value)} />
              </div>
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>User</th><th>Admin roles</th><th>MFA today</th><th>Methods registered</th><th>Change it in</th></tr></thead>
                <tbody>
                  {shownUsers.map((u) => (
                    <tr key={u.id}>
                      <td><strong>{u.name}</strong><div className="small mono">{u.upn}</div></td>
                      <td className="small">{u.roles.join(", ") || <span className="muted">none</span>}</td>
                      <td className="nowrap"><Sev s={LEVEL_SEV[u.level]} label={LEVEL_LABEL[u.level]} /></td>
                      <td className="small">{u.methods.filter((m) => m !== "password").map((m) => METHOD_LABEL[m] ?? m).join(", ") || <span className="muted">password only</span>}</td>
                      <td className="small">
                        {snap.example ? (
                          <span className="muted">No direct link (sample)</span>
                        ) : (
                          <>
                            <div><a href={PORTAL.userMethods(u.id)} target="_blank" rel="noreferrer">Entra: authentication methods ↗</a></div>
                            <div><a href={PORTAL.userAdmin(u.id)} target="_blank" rel="noreferrer">Microsoft 365 admin: user ↗</a></div>
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {shownUsers.length === 0 && <p className="muted">Nobody matches.</p>}
          </section>

          <section className="panel stack">
            <div className="panel-head"><h2>Authentication methods policy</h2><span className="sub">Which methods are on, and for whom</span></div>
            {snap.methodsPolicy ? (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Method</th><th>State</th><th>Turned on for</th></tr></thead>
                  <tbody>
                    {snap.methodsPolicy.map((m) => (
                      <tr key={m.id}>
                        <td>{m.id}</td>
                        <td><Sev s={m.state === "enabled" ? "ok" : "info"} label={m.state === "enabled" ? "On" : "Off"} /></td>
                        <td className="small">{m.targets.map((t) => (t === "all_users" ? "All users" : t)).join(", ") || <span className="muted">nobody</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="muted">Not read in this scan (needs Policy.Read.All).</p>
            )}
            <div><a className="btn sm" href={PORTAL.methodsPolicy} target="_blank" rel="noreferrer">Entra: authentication methods policies ↗</a></div>
          </section>

          <section className="panel stack">
            <div className="panel-head"><h2>SSO coverage</h2><span className="sub">{sso.total} enterprise app{sso.total === 1 ? "" : "s"} you added (Microsoft's own apps left out)</span></div>
            <div className="statline">
              <div><span className="n">{sso.percent.sso}%</span><span className="l">Use SAML or OIDC single sign-on ({sso.sso} of {sso.total})</span></div>
              <div><span className="n" style={{ color: sso.percent.assigned < 100 ? "var(--warn)" : undefined }}>{sso.percent.assigned}%</span><span className="l">Of those, require assignment</span></div>
              <div><span className="n">{sso.percent.scim}%</span><span className="l">Of those, remove leavers with SCIM</span></div>
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>App</th><th>Sign-in</th><th>Assignment required</th><th>SCIM</th><th>What to fix</th><th>Change it in</th></tr></thead>
                <tbody>
                  {sso.rows.map((r) => (
                    <tr key={r.spId}>
                      <td>
                        {r.inventoryId ? <a href="#inventory" onClick={(e) => { e.preventDefault(); go("inventory", { app: r.inventoryId! }); }}><strong>{r.name}</strong></a> : <strong>{r.name}</strong>}
                        <div className="small muted">{r.thirdParty ? "Third party" : "Your organisation"}{r.owner && ` · ${r.owner}`}</div>
                      </td>
                      <td className="small">{SIGNIN_LABEL[r.signIn]}</td>
                      <td>{r.assignmentRequired ? <Sev s="ok" label="Yes" /> : <Sev s={r.findings.some((f) => f.severity === "warn") ? "warn" : "info"} label="No" />}</td>
                      <td className="small">{r.scim ? "Yes" : "No"}</td>
                      <td className="small">{r.findings.map((f) => <div key={f.title} title={f.detail}>{f.title}</div>)}{!r.findings.length && <span className="muted">Nothing</span>}</td>
                      <td className="small">
                        {snap.example ? (
                          <span className="muted">No direct link (sample)</span>
                        ) : (
                          <>
                            <div><a href={PORTAL.appProperties(r.spId, r.appId)} target="_blank" rel="noreferrer">Entra: properties (assignment) ↗</a></div>
                            <div><a href={PORTAL.appSso(r.spId, r.appId)} target="_blank" rel="noreferrer">Entra: single sign-on ↗</a></div>
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="small muted">SCIM comes from Inventory. Run Discover so apps here match their Inventory entries by app ID.</p>
          </section>
        </>
      )}
    </div>
  );
}

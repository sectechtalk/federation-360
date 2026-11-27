import { useMemo, useState } from "react";
import { CodeBlock, useApp } from "../components/ui";
import { ActionButton, BusyNote, copyNow, downloadFile } from "../components/busy";
import scriptTemplate from "../../connectivity/Test-F360Connectivity.ps1?raw";
import {
  REMEDIATE_SCRIPT,
  adviceFor,
  buildPlan,
  embedPlan,
  isTestableHost,
  parseResults,
  remediation360Fields,
  summarizeByTest,
  type DeviceReport,
  type ResultStatus,
} from "../lib/connectivity";
import { WORKDIR } from "../data/workdir";
import { Section } from "../components/Section";

const STATUS_SEV: Record<ResultStatus, string> = { pass: "ok", warn: "warn", fail: "critical" };
const STATUS_LABEL: Record<ResultStatus, string> = { pass: "Pass", warn: "Warning", fail: "Fail" };

function Status({ s }: { s: ResultStatus }) {
  return (
    <span className={`sev sev-${STATUS_SEV[s]}`}>
      <span className="dot" />
      {STATUS_LABEL[s]}
    </span>
  );
}

const save = (name: string, text: string, type = "text/plain") => downloadFile(name, text, type);

const hostOf = (u: string) => {
  try {
    return new URL(u).hostname;
  } catch {
    return "";
  }
};

export default function Connectivity() {
  const { apps, tenants, toast, loading } = useApp();
  const [showExamples, setShowExamples] = useState(false);
  const visible = apps.filter((a) => showExamples || !a.example);
  const [picked, setPicked] = useState<Set<string> | null>(null);
  const chosen = visible.filter((a) => (picked ? picked.has(a.id) : true));
  const [name, setName] = useState("");
  const plan = useMemo(() => buildPlan(tenants, chosen, { name }), [tenants, chosen.map((a) => a.id).join(","), name]);
  const detect = useMemo(() => embedPlan(scriptTemplate, plan), [plan]);
  const fields = remediation360Fields(plan);
  const planFile = `f360-plan-${plan.id}.json`;

  const [pasted, setPasted] = useState("");
  const [files, setFiles] = useState<string[]>([]);
  const parsed = useMemo(() => parseResults([...files, pasted], plan), [files, pasted, plan]);
  const byTest = useMemo(() => summarizeByTest(parsed.reports), [parsed.reports]);
  const [openDevice, setOpenDevice] = useState<string | null>(null);

  const toggle = (id: string) => {
    const s = new Set(picked ?? visible.map((a) => a.id));
    s.has(id) ? s.delete(id) : s.add(id);
    setPicked(s);
  };

  const skipped = chosen.filter((a) => {
    const urls = a.protocol === "saml" ? [a.saml.acsUrl, a.saml.signOnUrl] : a.oidc.redirectUris.split(/\s+/);
    return !urls.some((u) => isTestableHost(hostOf(u)));
  });

  const [reading, setReading] = useState<string | null>(null);
  const readFiles = async (list: FileList | null) => {
    if (!list || !list.length) return;
    setReading(`Reading ${list.length} file${list.length === 1 ? "" : "s"}…`);
    try {
      const texts = await Promise.all([...list].map((f) => f.text()));
      setFiles((cur) => [...cur, ...texts]);
      toast(`Read ${texts.length} file${texts.length === 1 ? "" : "s"}`);
    } catch (e: any) {
      toast("Couldn't read the files: " + (e?.message ?? e));
    }
    setReading(null);
  };

  const localRun = `cd ${WORKDIR}
git pull
# Windows PowerShell 5.1, the same engine Intune uses. Bypass applies to this one process only.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\connectivity\\Test-F360Connectivity.ps1 \`
  -PlanPath "$HOME\\Downloads\\${planFile}" -OutputDir "${WORKDIR}\\connectivity\\results"
# Show where the result file is and select it in File Explorer (it is not opened).
$f = Get-ChildItem .\\connectivity\\results -Filter *.json | Sort-Object LastWriteTime | Select-Object -Last 1
"Result file: $($f.FullName)"
explorer.exe "/select,$($f.FullName)"`;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Connectivity test</h1>
          <p>
            Check from real Windows devices that they can reach every identity provider and app endpoint your sign-ins depend on. No agent: one signed PowerShell script runs as an Intune remediation through Remediation 360, reports, and changes nothing.
          </p>
        </div>
      </div>

      <Section className="panel stack">
        <div className="panel-head"><h2>1. Choose the apps to test</h2><span className="sub">{chosen.length} of {visible.length} chosen</span></div>
        {loading ? (
          <p className="small muted">Loading the inventory…</p>
        ) : visible.length === 0 ? (
          <div className="callout">
            No apps to test yet. Add your apps on the Inventory page or bring them in from Discover. Until then, the plan below tests the Microsoft Entra sign-in baseline, which you can run right away.
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th style={{ width: 40 }} /><th>App</th><th>Tenant</th><th>Protocol</th></tr></thead>
              <tbody>
                {visible.map((a) => (
                  <tr key={a.id}>
                    <td><input type="checkbox" aria-label={`Test ${a.name}`} checked={picked ? picked.has(a.id) : true} onChange={() => toggle(a.id)} /></td>
                    <td>{a.name}{a.example && <span className="small muted"> (example)</span>}</td>
                    <td className="small">{tenants.find((t) => t.id === a.tenantId)?.name ?? "?"}</td>
                    <td className="small">{a.protocol.toUpperCase()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="row">
          <label className="small"><input type="checkbox" checked={showExamples} onChange={(e) => { setShowExamples(e.target.checked); setPicked(null); }} /> Include example apps (their hosts are fictional and are left out of the plan)</label>
        </div>
        <label className="field" style={{ maxWidth: 420 }}>
          <span className="small muted">Plan name (optional)</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder={plan.name} />
        </label>
        {skipped.length > 0 && (
          <p className="small muted" style={{ margin: 0 }}>
            No device-reachable URL recorded for: {skipped.map((a) => a.name).join(", ")}. Localhost, plain HTTP and reserved example names are skipped; the identity provider checks still cover them.
          </p>
        )}
      </Section>

      <Section className="panel stack">
        <div className="panel-head"><h2>2. The test plan</h2><span className="sub">Plan {plan.id} · {plan.tests.length} checks</span></div>
        {plan.fallback && (
          <div className="callout">
            {chosen.length === 0 ? "No apps are chosen in step 1" : "None of the apps chosen in step 1 has an endpoint a device can reach (localhost, plain HTTP and example names are skipped)"}, so this plan tests the Microsoft Entra sign-in baseline: name lookup, port 443, TLS and TLS inspection, clock and the discovery document. You can download and run it now. For app-specific checks, add your real apps on the Inventory page or bring them in from Discover, then tick them in step 1.
          </div>
        )}
        {plan.tests.length === 0 ? (
          <p className="small muted" style={{ margin: 0 }}>Choose at least one app with a real HTTPS endpoint or an Entra tenant.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>#</th><th>Check</th><th>Target</th><th>Apps that rely on it</th></tr></thead>
              <tbody>
                {plan.tests.map((t) => (
                  <tr key={t.id}>
                    <td className="small mono">{t.id}</td>
                    <td><div>{t.label}</div><div className="small muted">{t.type.toUpperCase()}</div></td>
                    <td className="small mono" style={{ wordBreak: "break-all" }}>{t.url ?? `${t.host}${t.port ? ":" + t.port : ""}`}</td>
                    <td className="small">{t.apps.length ? t.apps.join(", ") : "All"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="small muted" style={{ margin: 0 }}>
          Every check is anonymous: a DNS lookup, a TCP connect, a TLS handshake, a plain GET, or a clock comparison. No credentials or tokens are sent. Behind a proxy the script uses the proxy Windows would use and reports which path worked. A TLS certificate from an unexpected issuer on login.microsoftonline.com is flagged as TLS inspection.
        </p>
      </Section>

      <Section className="panel stack">
        <div className="panel-head"><h2>3. Try it on this PC</h2><span className="sub">Optional, before you send it to devices</span></div>
        <div className="row">
          <ActionButton className="btn primary" busy="Building plan…" disabled={!plan.tests.length} onClick={() => save(planFile, JSON.stringify(plan, null, 2), "application/json")}>Download {planFile}</ActionButton>
          <ActionButton busy="Copying…" disabled={!plan.tests.length} onClick={() => copyNow(JSON.stringify(plan, null, 2))}>Copy plan JSON</ActionButton>
        </div>
        <p className="small" style={{ margin: 0 }}>The file lands in your Downloads folder. Then paste this into PowerShell 7. It runs the script from the folder you cloned Federation 360 into, prints a summary line and the full path of the result file, and opens File Explorer with that file selected. Drag the file onto the box in step 5, or use Choose files there.</p>
        <CodeBlock code={localRun} />
      </Section>

      <Section className="panel stack">
        <div className="panel-head"><h2>4. Send it to devices through Remediation 360</h2><span className="sub">Signed, four-eyes, canary first</span></div>
        <div className="row">
          <ActionButton className="btn primary" busy="Building script…" disabled={!plan.tests.length} onClick={() => save("detect.ps1", detect)}>Download detect.ps1</ActionButton>
          <ActionButton busy="Preparing download…" onClick={() => save("remediate.ps1", REMEDIATE_SCRIPT)}>Download remediate.ps1</ActionButton>
          <ActionButton busy="Copying…" disabled={!plan.tests.length} onClick={() => copyNow(detect)}>Copy detect.ps1</ActionButton>
        </div>
        <p className="small" style={{ margin: 0 }}>
          detect.ps1 is the script with this plan built in, so the signed script and its plan can't drift apart. Changing the plan later means a new change in Remediation 360, approved and signed like any other.
        </p>
        <ol className="small" style={{ margin: 0, paddingLeft: 18 }}>
          <li>Open Remediation 360, choose <strong>Elevate to write</strong>, then <strong>Changes &gt; New remediation</strong>.</li>
          <li>Fill the form with the values below and upload the two files (do not sign them; CI signs after merge).</li>
          <li><strong>Preview</strong>, then <strong>Create change</strong>. Approve and merge it, wait for signing, then publish. It goes to the canary group first.</li>
          <li>After it runs (daily, or use Intune's <strong>Run remediation</strong> on the canary device), open Intune &gt; Devices &gt; Scripts and remediations &gt; F360 Connectivity test &gt; Device status, add the <strong>Pre-remediation detection output</strong> column, export, and drop the CSV in step 5.</li>
        </ol>
        <div className="table-wrap">
          <table>
            <tbody>
              {[
                ["Folder name", fields.folder],
                ["Display name", fields.displayName],
                ["Description", fields.description],
                ["Publisher", fields.publisher],
                ["Run as", "System"],
                ["Run in 32-bit PowerShell", "No"],
                ["Enforce signature check", "Yes"],
                ["Schedule type", "Daily"],
                ["Interval", String(fields.schedule.interval)],
                ["Time (daily)", fields.schedule.time],
                ["Use UTC", "No"],
                ["Run remediation script", "No"],
              ].map(([k, v]) => (
                <tr key={k}>
                  <th className="small" style={{ width: 220 }}>{k}</th>
                  <td className="small mono">{v}</td>
                  <td style={{ width: 60 }}><ActionButton className="btn sm ghost" busy="Copying…" report="toast" onClick={() => copyNow(v)}>Copy</ActionButton></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="small muted" style={{ margin: 0 }}>
          Run as System uses the machine's WinHTTP proxy, not the signed-in user's browser proxy. If users sign in through a proxy that only the user profile knows about, the System run can fail where browsers work; the result shows which proxy each run saw.
        </p>
      </Section>

      <Section className="panel stack">
        <div className="panel-head"><h2>5. Read the results</h2><span className="sub">{parsed.reports.length} device{parsed.reports.length === 1 ? "" : "s"}</span></div>
        <p className="small" style={{ margin: 0 }}>
          Where the result files are: from the step 3 run on this PC, <span className="mono">{WORKDIR}\connectivity\results</span> (the step 3 block prints the exact path); on devices that ran it through Intune, <span className="mono">C:\ProgramData\F360\results</span>. Each run writes one <span className="mono">&lt;device&gt;-&lt;time&gt;.json</span>. Drag files onto the box below or use Choose files. You can also drop an Intune device status export or paste <span className="mono">F360|v1|…</span> lines. Nothing leaves this page.
        </p>
        <div className="row">
          <label className="btn">
            Choose files
            <input type="file" multiple accept=".json,.csv,.txt" style={{ display: "none" }} onChange={(e) => readFiles(e.target.files)} />
          </label>
          {(files.length > 0 || pasted) && <button className="btn ghost" onClick={() => { setFiles([]); setPasted(""); setOpenDevice(null); toast("Results cleared from this page"); }}>Clear</button>}
        </div>
        <textarea
          className="input mono"
          rows={4}
          value={pasted}
          onChange={(e) => setPasted(e.target.value)}
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => { e.preventDefault(); readFiles(e.dataTransfer.files); }}
          placeholder="Paste or drop here"
          aria-label="Results"
        />
        {reading && <BusyNote>{reading}</BusyNote>}
        {parsed.errors.map((e, i) => <div className="callout warn" key={i}>{e}</div>)}

        {parsed.reports.length > 0 && (
          <>
            <h3 style={{ margin: "8px 0 0" }}>By device</h3>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Device</th><th>Pass</th><th>Warn</th><th>Fail</th><th>Plan</th><th /></tr></thead>
                <tbody>
                  {parsed.reports.map((r) => (
                    <DeviceRow key={r.device} r={r} planId={plan.id} open={openDevice === r.device} onToggle={() => setOpenDevice(openDevice === r.device ? null : r.device)} />
                  ))}
                </tbody>
              </table>
            </div>
            <h3 style={{ margin: "8px 0 0" }}>By check</h3>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Check</th><th>Target</th><th>Failing on</th><th>Warning on</th><th>Passing</th></tr></thead>
                <tbody>
                  {byTest.map((t) => (
                    <tr key={t.key}>
                      <td>{t.label}{t.apps.length > 0 && <div className="small muted">{t.apps.join(", ")}</div>}</td>
                      <td className="small mono" style={{ wordBreak: "break-all" }}>{t.target}</td>
                      <td className="small">{t.fail.join(", ") || "-"}</td>
                      <td className="small">{t.warn.join(", ") || "-"}</td>
                      <td className="small">{t.pass.length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Section>

      <details className="panel">
        <summary>Show the script template ({scriptTemplate.split("\n").length} lines)</summary>
        <CodeBlock code={scriptTemplate} />
      </details>
    </div>
  );
}

function DeviceRow({ r, planId, open, onToggle }: { r: DeviceReport; planId: string; open: boolean; onToggle: () => void }) {
  const overall: ResultStatus = r.counts.fail ? "fail" : r.counts.warn ? "warn" : "pass";
  const shown = r.results;
  return (
    <>
      <tr>
        <td>
          <div><Status s={overall} /> <strong>{r.device}</strong></div>
          <div className="small muted">
            {r.source === "summary" ? "Summary line only" : [r.runAs, r.startedAt && new Date(r.startedAt).toLocaleString()].filter(Boolean).join(" · ")}
          </div>
        </td>
        <td>{r.counts.pass}</td>
        <td>{r.counts.warn}</td>
        <td>{r.counts.fail}</td>
        <td className="small mono">{r.planId}{r.planId !== planId && <div className="small muted">not the plan above</div>}</td>
        <td><button className="btn sm" onClick={onToggle}>{open ? "Hide" : "Details"}</button></td>
      </tr>
      {open && (
        <tr>
          <td colSpan={6}>
            <div className="stack">
              {r.proxy && (r.proxy.user || r.proxy.winhttp || r.proxy.pac) && (
                <div className="small">Proxy seen: {[r.proxy.winhttp && `WinHTTP ${r.proxy.winhttp}`, r.proxy.user && `user ${r.proxy.user}`, r.proxy.pac && `PAC ${r.proxy.pac}`].filter(Boolean).join(" · ")}</div>
              )}
              {r.os && <div className="small muted">{r.os}</div>}
              {shown.length === 0 && <div className="small muted">Every check passed.</div>}
              {shown.map((t) => {
                const tip = t.status !== "pass" ? adviceFor(t) : null;
                return (
                  <div key={t.id + t.target} className={`finding ${STATUS_SEV[t.status]}`}>
                    <div className="stripe" />
                    <div className="body">
                      <div className="title"><Status s={t.status} /><span>{t.label}</span><span className="small mono muted">{t.target}</span></div>
                      <div className="detail">{t.detail}{t.ms ? ` (${t.ms} ms)` : ""}</div>
                      {tip && <div className="detail"><strong>What to do:</strong> {tip}</div>}
                    </div>
                  </div>
                );
              })}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

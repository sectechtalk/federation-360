import { useEffect, useMemo, useState } from "react";
import { CodeBlock, Field, Sev, useApp } from "../components/ui";
import { ActionButton, downloadFile } from "../components/busy";
import { TenantLogReader } from "../components/TenantLogReader";
import { usePref } from "../lib/store";
import { graphToken, tenantConfigs, type TenantLogsConfig } from "../lib/entraLogs";
import { runDetections } from "../detections/rules";
import { takeHandoff } from "../lib/caseHandoff";
import { containRunbook, r360DeviceUrl, r360OffboardUrl, R360_DEFAULT_URL, type ContainApp } from "../lib/contain";
import { cleanupRunbook, verifyContainment, type ContainCheck } from "../lib/incidentContain";
import {
  addFile, addLogs, buildTimeline, casePeople, EMPTY_CASE, evidencePack, incidentReport, newCaseId, NIST_STEPS, scopeOf, sha256, suggestSeverity, TACTIC_ORDER, TECHNIQUES, VERDICTS,
  type CaseData, type CaseRecord, type CaseSeverity, type Verdict,
} from "../lib/investigate";
import { sampleIncidentFiles } from "../data/sampleIncident";
import { useUserReads } from "./UserLookup";
import { Section } from "../components/Section";

const SEVERITIES: CaseSeverity[] = ["Critical", "High", "Medium", "Low"];
const fmt = (t?: number) => (t ? new Date(t).toLocaleString() : "none");
const openTab = (url: string) => {
  const w = window.open(url, "_blank", "noopener");
  if (!w) throw new Error(`The browser blocked the new tab. Open this address yourself: ${url}`);
  return "Opened Remediation 360 in a new tab. Sign in there; a second person approves device actions.";
};
const blankRecord = (user = ""): CaseRecord => ({ caseId: newCaseId(), user, analyst: "", severity: "Low", verdict: "Undetermined", notes: "", done: {} });

export default function Investigate() {
  const { params, go, toast } = useApp();
  const [data, setData] = useState<CaseData>(EMPTY_CASE);
  const [notes, setNotes] = useState<string[]>([]);
  const [rec, setRec] = useState<CaseRecord>(() => blankRecord(params.user ?? ""));
  const [analyst, setAnalyst] = usePref("investigate:analyst", "");
  const [r360Url, setR360Url] = usePref("remediation:url", R360_DEFAULT_URL);
  const [reads] = useUserReads();
  const [onlySuspicious, setOnlySuspicious] = useState(true);
  const [sevTouched, setSevTouched] = useState(false);
  const [tenant, setTenant] = useState<TenantLogsConfig | null>(null);
  const [checks, setChecks] = useState<ContainCheck[] | null>(null);
  const [packHash, setPackHash] = useState("");

  // What Detections handed over with "Investigate this person".
  useEffect(() => {
    const h = takeHandoff();
    if (!h) return;
    addLogs(EMPTY_CASE, h.label, h.logs, h.hits).then((d) => {
      setData(d);
      setNotes([`From Detections: ${h.logs.signIns.length} sign-ins, ${h.logs.audits.length} audit events, ${h.hits.length} hits.`]);
    });
  }, []);

  const computed = useMemo(() => runDetections(data.logs).flatMap((r) => r.hits), [data.logs]);
  const full: CaseData = useMemo(() => ({ ...data, hits: [...data.hits, ...computed] }), [data, computed]);
  const people = useMemo(() => casePeople(full), [full]);
  const user = rec.user || people[0]?.user || "";
  const timeline = useMemo(() => (user ? buildTimeline(full, user, data.files.length ? Date.parse(data.files[data.files.length - 1].loadedAt) : Date.now()) : []), [full, user, data.files]);
  const scope = useMemo(() => scopeOf(timeline), [timeline]);
  const suggestion = useMemo(() => suggestSeverity(timeline, scope), [timeline, scope]);
  const severity = sevTouched ? rec.severity : suggestion.severity;
  const record: CaseRecord = { ...rec, user, analyst, severity };
  const shown = onlySuspicious ? timeline.filter((e) => e.suspicious) : timeline;
  const access = reads[user];
  const apps: ContainApp[] = (access?.assignments ?? []).filter((a) => a.spId).map((a) => ({ spId: a.spId, name: a.app }));
  const consented = [...new Set(timeline.filter((e) => e.kind === "audit" && /consent to application/i.test(e.title)).map((e) => e.detail.split(" · ")[0]).filter(Boolean))];
  const badRules = full.rules.filter((r) => (r.mailbox === user || r.mailbox === user.split("@")[0]) && (r.forwardTo.length || r.deletes || /rss|archive|conversation history|junk/i.test(r.moveTo))).map((r) => r.name);
  const riskyDevices = [...new Set(timeline.filter((e) => e.kind === "signin" && e.suspicious && e.device).map((e) => e.device!))];

  const onFiles = async (files: FileList | null) => {
    if (!files?.length) return;
    let d = data;
    const out: string[] = [];
    for (const f of Array.from(files)) {
      const r = await addFile(d, f.name, await f.text());
      d = r.data;
      out.push(r.note);
    }
    setData(d);
    setNotes((n) => [...n, ...out]);
    toast(`Added ${files.length} file${files.length === 1 ? "" : "s"} to the case`);
  };
  const loadSample = async () => {
    let d = EMPTY_CASE;
    const out: string[] = [];
    for (const f of sampleIncidentFiles()) {
      const r = await addFile(d, f.name, f.text);
      d = r.data;
      out.push(r.note);
    }
    setData(d);
    setNotes(out);
    setRec(blankRecord("blair.ops@f360sample.onmicrosoft.com"));
    setSevTouched(false);
    setChecks(null);
    return "Sample incident loaded: Blair's account";
  };
  const onTenantRead = async (r: { logs: CaseData["logs"] }, cfg: TenantLogsConfig) => {
    setTenant(cfg);
    const d = await addLogs(data, `${cfg.name || cfg.tenantId}: Graph read ${new Date().toISOString()}`, r.logs);
    setData(d);
    setNotes((n) => [...n, ...r.logs.sources]);
  };
  const newCase = () => {
    toast("New case started. The evidence, notes and checklist were cleared.");
    setData(EMPTY_CASE);
    setNotes([]);
    setRec(blankRecord());
    setSevTouched(false);
    setChecks(null);
    setPackHash("");
    toast("Started a new case. The old one is gone unless you downloaded its evidence pack.");
  };
  const downloadPack = async () => {
    if (!user) throw new Error("Load evidence and pick a person first.");
    const pack = JSON.stringify(evidencePack(record, full, timeline, scope), null, 2);
    const h = await sha256(pack);
    setPackHash(h);
    downloadFile(`${record.caseId}-evidence.json`, pack, "application/json");
    downloadFile(`${record.caseId}-report.html`, incidentReport(record, full, timeline, scope, h), "text/html");
    return `Downloaded ${record.caseId}-evidence.json and ${record.caseId}-report.html. Evidence SHA-256 ${h.slice(0, 16)}…`;
  };
  const markContained = () => {
    const now = Date.now();
    setRec({ ...rec, containedAt: now, done: { ...rec.done, revoke: rec.done.revoke ?? now } });
    toast(`Containment time set to ${new Date(now).toLocaleTimeString()}`);
  };
  const verify = async () => {
    if (!rec.containedAt) throw new Error("Click Mark contained now when the runbook or Remediation 360 has finished, then verify.");
    const cfg = tenant ?? Object.values(tenantConfigs())[0];
    if (!cfg || cfg.clientId === "free") throw new Error("Verify reads the tenant through Graph (Entra ID P1 or higher). Set it up under 1. Gather evidence > Read from your tenant.");
    const token = await graphToken(cfg);
    if (!token) throw new Error("Sign in under 1. Gather evidence > Read from your tenant, then verify again.");
    const c = await verifyContainment(token, user, rec.containedAt);
    setChecks(c);
    return c.every((x) => x.good) ? "Contained: every check passed." : `${c.filter((x) => !x.good).length} check${c.filter((x) => !x.good).length === 1 ? "" : "s"} not passed yet.`;
  };
  const toggle = (id: string) => setRec({ ...rec, done: rec.done[id] ? Object.fromEntries(Object.entries(rec.done).filter(([k]) => k !== id)) : { ...rec.done, [id]: Date.now() } });

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Investigate</h1>
          <p>
            One incident, every source, one timeline. Load sign-ins, audit events, Detections hits, Entity 360 and Exchange evidence for one person; each step gets its
            MITRE ATT&amp;CK technique. Set severity and a verdict, contain through Remediation 360 or a runbook, verify, and download an evidence pack with a SHA-256 for
            every file. Read-only, and nothing leaves this tab until you download it.
          </p>
        </div>
        <div className="row">
          <span className="tag mono">{record.caseId}</span>
          <button className="btn" onClick={newCase}>Start a new case</button>
          <ActionButton className="btn primary" busy="Building the evidence pack…" disabled={!user} onClick={downloadPack}>Download evidence pack</ActionButton>
        </div>
      </div>

      <Section className="panel stack">
        <div className="panel-head"><h2>1. Gather evidence</h2><span className="sub">Every file is hashed and listed in the chain of custody</span></div>
        <div className="grid-2">
          <div className="stack small">
            <label htmlFor="inv-files"><strong>Add files</strong> (any number, any order)</label>
            <input id="inv-files" className="input" type="file" multiple onChange={(e) => onFiles(e.target.files)} />
            <ul className="plain">
              <li><strong>Entra</strong>: sign-in and audit log JSON (admin center Download JSON, Export-F360SignIns.ps1, Log Analytics)</li>
              <li><strong>Detections</strong>: the file from Export detections (JSON)</li>
              <li><strong>Entity 360</strong>: the person's timeline CSV, or one sign-in's Raw source evidence saved as .json</li>
              <li><strong>Exchange 360 / Exchange Online</strong>: <span className="mono">Get-InboxRule -Mailbox &lt;upn&gt; | ConvertTo-Json</span> and <span className="mono">Get-MessageTraceV2 -RecipientAddress &lt;upn&gt; | ConvertTo-Json</span></li>
              <li><strong>Anything else</strong> (a HeatMap 360 scan, an export from another tool): kept and hashed as evidence, not read</li>
            </ul>
            <div className="row">
              <span className="muted">Just looking?</span>
              <ActionButton busy="Loading the sample…" onClick={loadSample}>Load the sample incident</ActionButton>
            </div>
          </div>
          <div className="stack small">
            <strong>Read from your tenant</strong>
            <TenantLogReader onRead={onTenantRead} user={rec.user || undefined} />
          </div>
        </div>
        {notes.length > 0 && <ul className="plain small">{notes.map((n, i) => <li key={i}>{n}</li>)}</ul>}
        {data.files.length > 0 && (
          <details>
            <summary className="small"><strong>Chain of custody</strong> ({data.files.length} item{data.files.length === 1 ? "" : "s"})</summary>
            <div className="table-wrap">
              <table className="table small">
                <thead><tr><th>Evidence</th><th>What it is</th><th>Records</th><th>Added</th><th>SHA-256</th></tr></thead>
                <tbody>{data.files.map((f) => <tr key={f.sha256}><td>{f.name}</td><td>{f.kind}</td><td>{f.records}</td><td>{new Date(f.loadedAt).toLocaleString()}</td><td className="mono" title={f.sha256}>{f.sha256.slice(0, 16)}…</td></tr>)}</tbody>
              </table>
            </div>
          </details>
        )}
      </Section>

      {people.length > 0 && (
        <Section className="panel stack">
          <div className="panel-head"><h2>2. Who</h2><span className="sub">People in the evidence, most suspicious steps first</span></div>
          <div className="row">
            <label htmlFor="inv-user">Person</label>
            <select id="inv-user" className="input" value={user} onChange={(e) => { setRec({ ...rec, user: e.target.value }); setSevTouched(false); setChecks(null); }}>
              {!people.some((p) => p.user === user) && user && <option value={user}>{user} (no evidence yet)</option>}
              {people.map((p) => <option key={p.user} value={p.user}>{p.user}: {p.suspicious} suspicious of {p.events}</option>)}
            </select>
            {access && <span className="small">Can reach <strong>{access.assignments.length}</strong> apps (User lookup, read {new Date(access.collectedAt).toLocaleDateString()}) <button className="btn sm" onClick={() => go("userlookup", { q: user })}>Open in User lookup</button></span>}
            {!access && user && <button className="btn sm" onClick={() => go("userlookup", { q: user })}>See which apps this person can reach (User lookup)</button>}
          </div>
        </Section>
      )}

      {user && timeline.length > 0 && (
        <>
          <div className="statline">
            <div><span className="n" style={{ color: timeline.some((e) => e.suspicious && e.severity === "critical") ? "var(--crit)" : undefined }}>{timeline.filter((e) => e.suspicious).length}</span><span className="l">Suspicious steps</span></div>
            <div><span className="n">{scope.suspiciousIps.filter((x) => x.succeeded).length}</span><span className="l">Suspicious addresses that got in</span></div>
            <div><span className="n">{scope.techniques.length}</span><span className="l">ATT&amp;CK techniques</span></div>
            <div><span className="n" style={{ fontSize: "1rem" }}>{fmt(scope.first)}</span><span className="l">First suspicious step</span></div>
          </div>

          <Section className="panel stack">
            <div className="panel-head"><h2>3. Timeline</h2><span className="sub">{user}</span></div>
            {scope.techniques.length > 0 && (
              <div className="stack small">
                <strong>ATT&amp;CK, by tactic</strong>
                {TACTIC_ORDER.filter((t) => scope.techniques.some((x) => x.tactic === t)).map((t) => (
                  <div key={t} className="row"><span className="muted" style={{ minWidth: 150 }}>{t}</span>{scope.techniques.filter((x) => x.tactic === t).map((x) => <a key={x.id} className="chip" href={`https://attack.mitre.org/techniques/${x.id.replace(".", "/")}/`} target="_blank" rel="noreferrer">{x.id} {x.name}</a>)}</div>
                ))}
              </div>
            )}
            {scope.suspiciousIps.length > 0 && (
              <p className="small" style={{ margin: 0 }}>
                <strong>Addresses:</strong> {scope.suspiciousIps.map((x) => `${x.ip}${x.country ? ` (${x.country})` : ""} ${x.count}×${x.succeeded ? ", got in" : ""}`).join("; ")}.{" "}
                {scope.apps.length > 0 && <><strong>Apps signed in to:</strong> {scope.apps.join(", ")}.</>}
              </p>
            )}
            <label className="small"><input type="checkbox" checked={onlySuspicious} onChange={(e) => setOnlySuspicious(e.target.checked)} /> Suspicious steps only ({timeline.filter((e) => e.suspicious).length} of {timeline.length})</label>
            <div className="table-wrap">
              <table className="table small">
                <thead><tr><th>Time</th><th>Step</th><th>Details</th><th>ATT&amp;CK</th><th>Source</th></tr></thead>
                <tbody>
                  {shown.map((e, i) => (
                    <tr key={i}>
                      <td className="mono" style={{ whiteSpace: "nowrap" }}>{e.kind === "inbox-rule" ? "now (no time)" : new Date(e.time).toLocaleString()}</td>
                      <td><Sev s={e.suspicious ? e.severity : "ok"} label={e.kind === "signin" ? "Sign-in" : e.kind === "audit" ? "Change" : e.kind === "detection" ? "Detection" : e.kind === "inbox-rule" ? "Inbox rule" : "Mail"} /> {e.title}</td>
                      <td>{e.detail}</td>
                      <td>{e.attack ? <span title={TECHNIQUES[e.attack]?.name}>{e.attack}</span> : ""}</td>
                      <td>{e.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>

          <Section className="panel stack">
            <div className="panel-head"><h2>4. Triage</h2><span className="sub">Your judgement; Federation 360 only suggests</span></div>
            <div className="grid-2">
              <div className="stack small">
                <Field id="inv-analyst" label="Analyst (goes into the chain of custody)" value={analyst} onChange={setAnalyst} placeholder="Your name" />
                <label htmlFor="inv-sev">Severity</label>
                <select id="inv-sev" className="input" value={severity} onChange={(e) => { setSevTouched(true); setRec({ ...rec, severity: e.target.value as CaseSeverity }); }}>
                  {SEVERITIES.map((s) => <option key={s} value={s}>{s}{s === suggestion.severity ? " (suggested)" : ""}</option>)}
                </select>
                <span className="muted">Suggested {suggestion.severity}: {suggestion.why}</span>
                <label htmlFor="inv-verdict">Verdict</label>
                <select id="inv-verdict" className="input" value={rec.verdict} onChange={(e) => setRec({ ...rec, verdict: e.target.value as Verdict })}>
                  {VERDICTS.map((v) => <option key={v}>{v}</option>)}
                </select>
              </div>
              <div className="stack small">
                <label htmlFor="inv-notes">Findings (plain words; they go into the report)</label>
                <textarea id="inv-notes" className="input" rows={8} value={rec.notes} onChange={(e) => setRec({ ...rec, notes: e.target.value })} placeholder="What happened, how you know, what the person said, what was escalated and to whom." />
              </div>
            </div>
          </Section>

          <Section className="panel stack">
            <div className="panel-head"><h2>5. Contain and clean up</h2><span className="sub">Federation 360 never writes. Remediation 360 or your runbook does, as you.</span></div>
            <div className="grid-2">
              <div className="stack small">
                <strong>Through Remediation 360</strong>
                <div className="row">
                  <ActionButton className="btn primary" busy="Opening Remediation 360…" onClick={() => openTab(r360OffboardUrl(r360Url, "disable", user, apps))}>Disable user everywhere in Remediation 360</ActionButton>
                </div>
                {riskyDevices.map((d) => (
                  <div key={d} className="row"><ActionButton busy="Opening Remediation 360…" onClick={() => openTab(r360DeviceUrl(r360Url, d))}>Isolate {d} in Remediation 360</ActionButton></div>
                ))}
                {!riskyDevices.length && <span className="muted">No managed device appears in the suspicious sign-ins, so there's nothing to isolate. Attackers usually sign in from their own machine.</span>}
                <Field id="inv-remediation" label="Remediation 360 address" value={r360Url} onChange={setR360Url} placeholder={R360_DEFAULT_URL} />
              </div>
              <div className="stack small">
                <strong>With PowerShell, as you</strong>
                <div className="row">
                  <ActionButton busy="Writing the runbook…" onClick={async () => downloadFile("Contain-F360User.ps1", containRunbook({ upn: user, tenantId: tenant?.tenantId, apps, generatedAt: new Date() }))}>Download contain runbook</ActionButton>
                  <ActionButton busy="Writing the runbook…" onClick={async () => downloadFile("Cleanup-F360Incident.ps1", cleanupRunbook({ upn: user, tenantId: tenant?.tenantId, since: scope.first ?? Date.now() - 86_400_000, apps: consented, inboxRules: badRules, caseId: record.caseId, generatedAt: new Date() }))}>Download clean-up runbook</ActionButton>
                </div>
                <span className="muted">Contain: disable, revoke sessions, push the disable to SCIM apps. Clean-up: remove MFA methods added since {fmt(scope.first)}{consented.length ? `, grants to ${consented.join(", ")}` : ""}{badRules.length ? `, inbox rules ${badRules.map((r) => `"${r}"`).join(", ")}` : ""}, then revoke sessions again. Both are What-if unless you add -Run.</span>
                <CodeBlock code={"cd $HOME\\Downloads\nUnblock-File .\\Contain-F360User.ps1, .\\Cleanup-F360Incident.ps1\n.\\Contain-F360User.ps1          # what if\n.\\Contain-F360User.ps1 -Run     # do it"} />
              </div>
            </div>
            <div className="row">
              <button className="btn" onClick={markContained}>Mark contained now</button>
              <span className="small muted">{rec.containedAt ? `Contained at ${fmt(rec.containedAt)}.` : "Click when the runbook or Remediation 360 has finished."}</span>
              <ActionButton className="btn primary" busy="Reading the account and sign-ins…" disabled={!rec.containedAt} onClick={verify}>Verify containment</ActionButton>
            </div>
            {checks && (
              <table className="table small">
                <thead><tr><th>Check</th><th>Result</th><th></th></tr></thead>
                <tbody>{checks.map((c) => <tr key={c.what}><td>{c.what}</td><td>{c.result}</td><td><Sev s={c.good ? "ok" : "critical"} label={c.good ? "Good" : "Not yet"} /></td></tr>)}</tbody>
              </table>
            )}
          </Section>

          <Section className="panel stack">
            <div className="panel-head"><h2>6. Response checklist</h2><span className="sub">NIST SP 800-61 phases; ticks are timed and go into the report</span></div>
            <div className="grid-2">
              {NIST_STEPS.map((p) => (
                <div key={p.phase} className="stack small">
                  <strong>{p.phase}</strong>
                  {p.steps.map((s) => (
                    <label key={s.id}><input type="checkbox" checked={!!rec.done[s.id]} onChange={() => toggle(s.id)} /> {s.text}{rec.done[s.id] ? <span className="muted"> ({new Date(rec.done[s.id]).toLocaleTimeString()})</span> : null}</label>
                  ))}
                </div>
              ))}
            </div>
            {packHash && <p className="small muted" style={{ margin: 0 }}>Last evidence pack SHA-256: <span className="mono">{packHash}</span></p>}
          </Section>
        </>
      )}
      {user && timeline.length === 0 && data.files.length > 0 && <div className="callout">Nothing in the evidence for {user} yet. Add their logs, or pick someone else.</div>}
    </div>
  );
}

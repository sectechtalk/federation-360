import { useMemo, useState } from "react";
import { CodeBlock, Sev, useApp } from "../components/ui";
import { ActionButton, downloadFile } from "../components/busy";
import { EMPTY_LOGS, mergeLogs, readLogFile, type LoadedLogs } from "../detections/events";
import { RULES, runDetections, type Hit } from "../detections/rules";
import { sampleSignInLog } from "../detections/sample";
import exportScript from "../../detections/Export-F360SignIns.ps1?raw";

const SCRIPT_NAME = "Export-F360SignIns.ps1";
const ruleTitle = (id: string) => RULES.find((r) => r.id === id)?.title ?? id;

export default function Detections() {
  const { go, toast } = useApp();
  const [logs, setLogs] = useState<LoadedLogs>(EMPTY_LOGS);
  const [error, setError] = useState<string | null>(null);
  const [sample, setSample] = useState(false);
  const results = useMemo(() => (logs.signIns.length || logs.audits.length ? runDetections(logs) : null), [logs]);
  const hits: Hit[] = (results ?? []).flatMap((r) => r.hits).sort((a, b) => (a.severity === b.severity ? b.time - a.time : a.severity === "critical" ? -1 : 1));

  const onFiles = async (files: FileList | null) => {
    if (!files?.length) return;
    setError(null);
    let next = sample ? EMPTY_LOGS : logs;
    const errors: string[] = [];
    for (const f of Array.from(files)) {
      try {
        next = mergeLogs(next, readLogFile(f.name, await f.text()));
      } catch (e: any) {
        errors.push(e.message);
      }
    }
    setSample(false);
    setLogs(next);
    if (errors.length) setError(errors.join(" "));
    else toast(`Loaded ${files.length} file${files.length === 1 ? "" : "s"}`);
  };
  const loadSample = async () => {
    const x = sampleSignInLog();
    setLogs(readLogFile("Sample tenant", JSON.stringify(x)));
    setSample(true);
    setError(null);
    return "Sample logs loaded";
  };
  const exportHits = async () => {
    if (!hits.length) throw new Error("No detections to export.");
    return downloadFile(`f360-detections-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify({ generatedAt: new Date().toISOString(), sources: logs.sources, hits }, null, 2), "application/json");
  };
  const downloadScript = async () => downloadFile(SCRIPT_NAME, exportScript);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Detections</h1>
          <p>
            Rules that catch account takeover, MFA fatigue and stolen session tokens in Entra sign-in and audit logs. Each rule is code with tests, a MITRE
            ATT&amp;CK technique, known false positives, a response playbook, and the same logic as a KQL query for Microsoft Sentinel. Logs are read in this
            tab only.
          </p>
        </div>
        {(logs.signIns.length > 0 || logs.audits.length > 0) && (
          <div className="row">
            <button className="btn" onClick={() => { setLogs(EMPTY_LOGS); setSample(false); toast("Logs cleared from this page."); }}>Clear logs</button>
            <ActionButton className="btn primary" busy="Building the file…" onClick={exportHits}>Export detections (JSON)</ActionButton>
          </div>
        )}
      </div>

      {error && <div className="callout crit">{error}</div>}

      <section className="panel stack">
        <div className="panel-head"><h2>Load logs</h2><span className="sub">Sign-in logs, plus audit logs for two of the rules</span></div>
        <div className="grid-2">
          <div className="stack small">
            <h3>Entra ID Free (your lab)</h3>
            <p>
              Entra admin center &gt; Entra ID &gt; Monitoring &amp; health &gt; <strong>Sign-in logs</strong> &gt; <strong>Download</strong> &gt; <strong>Download JSON</strong>{" "}
              (the last 7 days). Do the same on <strong>Audit logs</strong> for the two rules that need them. Graph v1.0 and this download have no session IDs, so the
              stolen-token rule says it can't run rather than "all clear".
            </p>
            <h3>Entra ID P1 or higher</h3>
            <p>
              Run the script: it reads sign-ins (interactive and non-interactive, from Graph beta so session IDs are included) and audit events, read-only, and
              saves one file. Needs AuditLog.Read.All and a Reports Reader or Security Reader role. Or export SigninLogs and AuditLogs from Log Analytics as JSON.
            </p>
            <div className="row">
              <ActionButton busy="Preparing the script…" onClick={downloadScript}>Download {SCRIPT_NAME}</ActionButton>
            </div>
            <CodeBlock code={`cd $HOME\\Downloads\nUnblock-File .\\${SCRIPT_NAME}\n.\\${SCRIPT_NAME} -TenantId <your-tenant-id> -Days 7`} />
          </div>
          <div className="stack">
            <label className="small" htmlFor="det-files"><strong>Load one or more JSON files</strong> (sign-ins and audits can be separate files)</label>
            <input id="det-files" className="input" type="file" multiple accept=".json,application/json" onChange={(e) => onFiles(e.target.files)} />
            <div className="row">
              <span className="small muted">Just looking?</span>
              <ActionButton busy="Loading the sample…" onClick={loadSample}>Load sample logs with every attack</ActionButton>
            </div>
            {logs.sources.length > 0 && (
              <ul className="plain small">
                {logs.sources.map((s) => <li key={s}>{s}</li>)}
                <li className="muted">{logs.signIns.length} sign-ins and {logs.audits.length} audit events in total.</li>
              </ul>
            )}
          </div>
        </div>
      </section>

      {results && (
        <>
          <div className="statline">
            <div><span className="n" style={{ color: hits.some((h) => h.severity === "critical") ? "var(--crit)" : undefined }}>{hits.filter((h) => h.severity === "critical").length}</span><span className="l">Critical: act now</span></div>
            <div><span className="n" style={{ color: hits.some((h) => h.severity === "warn") ? "var(--warn)" : undefined }}>{hits.filter((h) => h.severity === "warn").length}</span><span className="l">Warnings: check today</span></div>
            <div><span className="n">{results.filter((r) => !r.missing).length} of {RULES.length}</span><span className="l">Rules that could run on these logs</span></div>
            <div><span className="n">{logs.signIns.length}</span><span className="l">Sign-ins checked</span></div>
          </div>

          <section className="panel stack">
            <div className="panel-head"><h2>What fired</h2><span className="sub">Critical first, newest first</span></div>
            {hits.length === 0 ? (
              <p>Nothing fired. Check the rules list below for any that couldn't run on these logs.</p>
            ) : (
              <div className="stack">
                {hits.map((h, i) => {
                  const rule = RULES.find((r) => r.id === h.rule)!;
                  return (
                    <div key={i} className={`finding ${h.severity}`}>
                      <div className="stripe" />
                      <div className="body">
                        <div className="title"><Sev s={h.severity} /><span>{h.title}</span></div>
                        <div className="detail small"><strong>{h.user}</strong> · {new Date(h.time).toLocaleString()} · {ruleTitle(h.rule)} · ATT&amp;CK {rule.attack.id}</div>
                        <ul className="plain small mono">{h.evidence.map((e) => <li key={e}>{e}</li>)}</ul>
                        <div><button className="btn sm" onClick={() => go("playbooks", { id: rule.playbook })}>Respond: open the playbook</button></div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </>
      )}

      <section className="panel stack">
        <div className="panel-head"><h2>The rules</h2><span className="sub">{RULES.length} rules, each with tests in tests/detections.test.ts</span></div>
        {RULES.map((r) => {
          const res = results?.find((x) => x.rule.id === r.id);
          return (
            <details key={r.id} className="panel">
              <summary>
                <strong>{r.title}</strong>{" "}
                <span className="small muted">ATT&amp;CK {r.attack.id} {r.attack.name}</span>{" "}
                {res && (res.missing ? <Sev s="info" label="Couldn't run" /> : res.hits.length ? <Sev s={res.hits.some((h) => h.severity === "critical") ? "critical" : "warn"} label={`${res.hits.length} hit${res.hits.length === 1 ? "" : "s"}`} /> : <Sev s="ok" label="No hits" />)}
              </summary>
              <div className="stack small" style={{ marginTop: 8 }}>
                <p>{r.summary}</p>
                {res?.missing && <div className="callout warn">{res.missing}</div>}
                <p><strong>Needs:</strong> {r.needs.map((n) => (n === "signIns" ? "sign-in logs" : n === "audits" ? "audit logs" : "session IDs (Graph beta or Log Analytics)")).join(", ")}.</p>
                <p><strong>False positives:</strong> {r.falsePositives}</p>
                <p><strong>Sentinel / Log Analytics (KQL):</strong></p>
                <CodeBlock code={r.kql} />
                <div><button className="btn sm" onClick={() => go("playbooks", { id: r.playbook })}>Response playbook</button></div>
              </div>
            </details>
          );
        })}
      </section>
    </div>
  );
}

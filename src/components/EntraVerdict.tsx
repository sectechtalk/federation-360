import { useCallback, useEffect, useState } from "react";
import { CodeBlock, Sev, useApp } from "./ui";
import { ActionButton, copyNow, downloadFile } from "./busy";
import type { FlowCapture } from "../lib/flow";
import type { Severity } from "../lib/types";
import { playbookById } from "../data/playbooks";
import { WORKDIR } from "../data/workdir";
import {
  LogsError, explain, fetchCandidates, graphToken, matchSignIns, signInForLogs, signOut, signedInUser, tenantConfigs, tenantIdOf,
  type Match, type Problem, type TenantLogsConfig,
} from "../lib/entraLogs";
import setupScript from "../../signin-logs/Connect-F360SignInLogs.ps1?raw";

/** Entra writes a sign-in to its log a few minutes after it happens. Keep looking this long. */
const WAIT_MS = 20 * 60_000;
const RETRY_MS = 30_000;

type State =
  | { s: "idle" }
  | { s: "checking" }
  | { s: "waiting"; next: number }
  | { s: "found"; m: Match }
  | { s: "gone" }
  | { s: "problem"; p: Problem; msg: string };

const TONE: Record<"ok" | "fail" | "warn", Severity> = { ok: "ok", fail: "critical", warn: "warn" };

const ADMIN_CENTER = "https://entra.microsoft.com/";

/** What Entra decided about this sign-in, from its sign-in log, shown beside the captured flow. */
export function EntraVerdict({ capture }: { capture: FlowCapture }) {
  const { toast, go } = useApp();
  const h = capture.entra;
  const [tenantId, setTenantId] = useState<string | null | undefined>(undefined);
  const [cfg, setCfg] = useState<TenantLogsConfig | null>(null);
  const [user, setUser] = useState<string | null>(null);
  const [state, setState] = useState<State>({ s: "idle" });
  const [run, setRun] = useState(0);
  const [now, setNow] = useState(Date.now());

  // Which tenant this flow belongs to, and whether sign-in logs are set up for it.
  useEffect(() => {
    let live = true;
    setTenantId(undefined);
    (async () => {
      const all = tenantConfigs();
      let id = h?.tenant ? await tenantIdOf(h.tenant) : null;
      if (!id && Object.keys(all).length === 1) id = Object.keys(all)[0];
      if (!live) return;
      setTenantId(id);
      const c = id ? all[id] ?? null : null;
      setCfg(c);
      setUser(c ? signedInUser(c.tenantId) : null);
    })();
    return () => {
      live = false;
    };
  }, [h?.tenant, run]);

  const lookUp = useCallback(async () => {
    if (!h || !cfg || cfg.clientId === "free") return;
    const token = await graphToken(cfg);
    if (!token) {
      setUser(null);
      setState({ s: "idle" });
      return;
    }
    setState((s) => (s.s === "found" ? s : { s: "checking" }));
    try {
      const m = matchSignIns(h, await fetchCandidates(token, h));
      if (m) return setState({ s: "found", m });
      const age = Date.now() - (Date.parse(h.to ?? h.from ?? "") || Date.now());
      setState(age < WAIT_MS ? { s: "waiting", next: Date.now() + RETRY_MS } : { s: "gone" });
    } catch (e: any) {
      if (e instanceof LogsError && e.problem === "signed-out") {
        signOut(cfg.tenantId);
        setUser(null);
        return setState({ s: "idle" });
      }
      setState({ s: "problem", p: e instanceof LogsError ? e.problem : "other", msg: String(e?.message ?? e) });
    }
  }, [h, cfg]);

  // Look it up by itself as soon as there's a signed-in account, and again while Entra hasn't written it yet.
  useEffect(() => {
    if (user) lookUp();
  }, [user, lookUp, capture.id, capture.steps.length]);
  useEffect(() => {
    if (state.s !== "waiting") return;
    const tick = setInterval(() => setNow(Date.now()), 1000);
    const t = setTimeout(lookUp, Math.max(0, state.next - Date.now()));
    return () => {
      clearInterval(tick);
      clearTimeout(t);
    };
  }, [state, lookUp]);

  if (!h || tenantId === undefined) return null;

  const signIn = async () => {
    if (!cfg) return;
    try {
      const u = await signInForLogs(cfg);
      setUser(u);
      toast(`Signed in as ${u}`);
    } catch (e: any) {
      setState({ s: "problem", p: "other", msg: String(e?.message ?? e) });
    }
  };

  const requestHint = h.requestIds[0] ? <> Filter <strong>Request ID</strong> by <span className="mono">{h.requestIds[0]}</span>.</> : null;
  const head = (
    <div className="spread">
      <span className="eyebrow">Entra's verdict · from the sign-in log</span>
      {cfg && cfg.clientId !== "free" && user && (
        <span className="row small muted">
          Reading as {user}
          <button className="btn sm" onClick={() => { signOut(cfg.tenantId); setUser(null); setState({ s: "idle" }); }}>Sign out</button>
        </span>
      )}
    </div>
  );

  // ------------------------------------------------ not set up for this tenant
  if (!cfg) {
    const t = tenantId ?? "<your-tenant-id>";
    const cmd = `cd ${WORKDIR}\n./signin-logs/Connect-F360SignInLogs.ps1 -TenantId ${t}`;
    return (
      <section className="panel stack" aria-label="Entra's verdict">
        {head}
        <p style={{ margin: 0 }}>
          <strong>See what Entra decided about each sign-in, and why</strong>: the error, which Conditional Access policy blocked it and what to do. Set it up once for this tenant{tenantId ? <> (<span className="mono">{tenantId}</span>)</> : null}, then it appears here by itself.
        </p>
        <ol className="small" style={{ margin: 0, paddingLeft: 20, display: "grid", gap: 4 }}>
          <li>Open PowerShell 7 and run the two lines below. Sign in as a Global Administrator or Privileged Role Administrator of this tenant when asked. If that role is eligible in Privileged Identity Management, activate it first.</li>
          <li>The script adds a read-only app registration named <strong>Federation 360 sign-in logs</strong>, grants it permission to read sign-in logs, and opens this page again, connected.</li>
          <li>Click <strong>Sign in to read sign-in logs</strong> when it appears here.</li>
        </ol>
        <CodeBlock code={cmd} />
        <div className="row">
          <ActionButton className="btn primary" busy="Copying…" onClick={() => copyNow(cmd)}>Copy the commands</ActionButton>
          <ActionButton busy="Preparing the script…" onClick={async () => downloadFile("Connect-F360SignInLogs.ps1", setupScript)}>Download the script</ActionButton>
        </div>
        <p className="small muted" style={{ margin: 0 }}>
          Microsoft serves sign-in logs to apps only on tenants with Entra ID P1 or higher (Microsoft 365 E3, E5 and E7 include it). On a free tenant, such as a practice lab, the script says so and changes nothing, and this box then shows where to find the sign-in in the Entra admin center instead.
        </p>
      </section>
    );
  }

  // ------------------------------------------------ free tenant
  if (cfg.clientId === "free" || (state.s === "problem" && state.p === "unlicensed")) {
    return (
      <section className="panel stack" aria-label="Entra's verdict">
        {head}
        <div className="callout">
          <strong>This tenant's license doesn't let apps read sign-in logs.</strong> Microsoft serves them through its API only on Entra ID P1 or higher (Microsoft 365 E3, E5 and E7 include it), and this tenant is on Entra ID Free.
          {" "}To see Entra's verdict for this sign-in, open <a href={ADMIN_CENTER} target="_blank" rel="noreferrer">the Entra admin center</a> and go to <strong>Entra ID</strong> &gt; <strong>Monitoring &amp; health</strong> &gt; <strong>Sign-in logs</strong>.{requestHint}
        </div>
      </section>
    );
  }

  // ------------------------------------------------ signed out
  if (!user) {
    return (
      <section className="panel stack" aria-label="Entra's verdict">
        {head}
        <div className="row">
          <ActionButton className="btn primary" busy="Signing in…" onClick={signIn}>Sign in to read sign-in logs</ActionButton>
          <span className="small muted">{cfg.name ? `${cfg.name}. ` : ""}A Microsoft sign-in window opens. Once you're signed in, every sign-in here gets Entra's verdict by itself for the next 24 hours.</span>
        </div>
        {state.s === "problem" && <div className="callout warn">{state.msg}</div>}
      </section>
    );
  }

  // ------------------------------------------------ problems with a fix
  if (state.s === "problem") {
    const consentUrl = `https://login.microsoftonline.com/${cfg.tenantId}/adminconsent?client_id=${cfg.clientId}`;
    return (
      <section className="panel stack" aria-label="Entra's verdict">
        {head}
        {state.p === "no-consent" ? (
          <div className="callout warn">
            <strong>Federation 360 isn't allowed to read sign-in logs in this tenant yet.</strong> Fix: run <span className="mono">./signin-logs/Connect-F360SignInLogs.ps1 -TenantId {cfg.tenantId}</span> again as a Global Administrator, or open <a href={consentUrl} target="_blank" rel="noreferrer">the admin consent page</a> as one and click <strong>Accept</strong>. Then click <strong>Sign in again</strong>.
          </div>
        ) : state.p === "no-role" ? (
          <div className="callout warn">
            <strong>Your account ({user}) isn't allowed to read sign-in logs.</strong> Fix: in <a href={ADMIN_CENTER} target="_blank" rel="noreferrer">the Entra admin center</a>, go to <strong>Entra ID</strong> &gt; <strong>Roles &amp; admins</strong> &gt; <strong>Security Reader</strong> &gt; <strong>Add assignments</strong> and add yourself (an admin may need to do this). If the role is eligible in Privileged Identity Management, activate it. Then click <strong>Sign in again</strong>.
          </div>
        ) : (
          <div className="callout warn">Couldn't read the sign-in log: {state.msg}</div>
        )}
        <div className="row">
          <ActionButton className="btn primary" busy="Signing in…" onClick={async () => { signOut(cfg.tenantId); await signIn(); }}>Sign in again</ActionButton>
          <button className="btn" onClick={() => setRun((n) => n + 1)}>Try again</button>
        </div>
      </section>
    );
  }

  // ------------------------------------------------ looking
  if (state.s === "idle" || state.s === "checking" || state.s === "waiting" || state.s === "gone") {
    return (
      <section className="panel stack" aria-label="Entra's verdict">
        {head}
        {state.s === "waiting" ? (
          <p className="small" style={{ margin: 0 }}>
            Entra hasn't written this sign-in to its log yet. That usually takes 2 to 5 minutes. Checking again in {Math.max(0, Math.ceil((state.next - now) / 1000))} seconds.
          </p>
        ) : state.s === "gone" ? (
          <p className="small" style={{ margin: 0 }}>
            No matching entry in this tenant's sign-in log. The sign-in may belong to another tenant, or to a personal Microsoft account, which Entra doesn't log here.
            {" "}<button className="btn sm" onClick={lookUp}>Check again</button>
          </p>
        ) : (
          <p className="small muted" style={{ margin: 0 }}>Looking for this sign-in in Entra's log…</p>
        )}
      </section>
    );
  }

  // ------------------------------------------------ found
  const v = explain(state.m.records, (c) => !!playbookById(c));
  const last = state.m.records[state.m.records.length - 1];
  const rows: [string, string | undefined][] = [
    ["When", new Date(last.createdDateTime).toLocaleString()],
    ["User", last.userPrincipalName],
    ["App", [last.appDisplayName, last.appId].filter(Boolean).join(" · ")],
    ["Resource", last.resourceDisplayName],
    ["Result", last.status?.errorCode ? `AADSTS${last.status.errorCode}: ${last.status.failureReason ?? ""}` : "Success"],
    ["Conditional Access", last.conditionalAccessStatus],
    ["Client", [last.clientAppUsed, last.deviceDetail?.browser, last.deviceDetail?.operatingSystem].filter(Boolean).join(" · ")],
    ["IP address", [last.ipAddress, last.location?.city, last.location?.countryOrRegion].filter(Boolean).join(" · ")],
    ["Request ID", last.id],
    ["Correlation ID", last.correlationId],
  ];
  return (
    <section className="panel stack" aria-label="Entra's verdict">
      {head}
      <div className="findings">
        <div className={`finding ${TONE[v.tone]}`}>
          <div className="stripe" />
          <div className="body">
            <div className="title"><Sev s={TONE[v.tone]} /><span>{v.headline}</span></div>
            {v.lines.length > 0 && (
              <ul className="detail" style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                {v.lines.map((l, i) => <li key={i}>{l}</li>)}
              </ul>
            )}
            {v.fix && <div className="detail"><strong>What to do:</strong> {v.fix}</div>}
            {v.playbook && (
              <div><button className="btn sm" onClick={() => go("playbooks", { id: v.playbook! })}>Open the playbook →</button></div>
            )}
          </div>
        </div>
      </div>
      {state.m.how === "likely" && (
        <p className="small muted" style={{ margin: 0 }}>Closest match by app and time. Entra didn't record an ID from this recording, so check the user and time below.</p>
      )}
      <details>
        <summary>Sign-in log details{state.m.records.length > 1 ? ` (${state.m.records.length} entries)` : ""}</summary>
        <table className="small" style={{ marginTop: 8 }}>
          <tbody>
            {rows.filter(([, val]) => val).map(([k, val]) => <tr key={k}><th style={{ textAlign: "left", paddingRight: 12 }}>{k}</th><td className="mono">{val}</td></tr>)}
          </tbody>
        </table>
        <CodeBlock code={JSON.stringify(state.m.records, null, 2)} />
      </details>
    </section>
  );
}

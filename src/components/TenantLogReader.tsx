// Reads sign-ins and audit events from a tenant through Graph (detections/live.ts), for Detections and Investigate.
// Uses the per-tenant "Federation 360 sign-in logs" app registration that Entra's verdict on the Flow tracer uses.
import { useState } from "react";
import { CodeBlock } from "./ui";
import { ActionButton, copyNow, downloadFile } from "./busy";
import { WORKDIR } from "../data/workdir";
import { LogsError, graphToken, signInForLogs, signOut, signedInUser, tenantConfigs, type TenantLogsConfig } from "../lib/entraLogs";
import { readTenantLogs, type TenantRead } from "../detections/live";
import setupScript from "../../signin-logs/Connect-F360SignInLogs.ps1?raw";

const FIX: Record<string, string> = {
  unlicensed: "This tenant is on Entra ID Free, and Microsoft serves sign-in logs to apps only on P1 or higher. Download the logs from the Entra admin center instead (left column).",
  "no-consent": "Federation 360 isn't allowed to read sign-in logs here yet. Run Connect-F360SignInLogs.ps1 for this tenant again as a Global Administrator, then sign in again.",
  "no-role": "Your account can't read sign-in logs. Ask for the Security Reader role (or activate it in Privileged Identity Management), then sign in again.",
};

export function TenantLogReader({ onRead, user: fixedUser }: { onRead: (r: TenantRead, cfg: TenantLogsConfig) => void; user?: string }) {
  const configs = Object.values(tenantConfigs());
  const [tenantId, setTenantId] = useState(configs[0]?.tenantId ?? "");
  const cfg: TenantLogsConfig | undefined = configs.find((c) => c.tenantId === tenantId);
  const [who, setWho] = useState<string | null>(cfg ? signedInUser(cfg.tenantId) : null);
  const [days, setDays] = useState(7);
  const [upn, setUpn] = useState(fixedUser ?? "");
  const [problem, setProblem] = useState<string | null>(null);

  if (!configs.length) {
    const cmd = `cd ${WORKDIR}\n./signin-logs/Connect-F360SignInLogs.ps1 -TenantId <your-tenant-id>`;
    return (
      <div className="stack small">
        <p style={{ margin: 0 }}>
          Set it up once per tenant: run the two lines below in PowerShell 7 as a Global Administrator or Privileged Role Administrator. The script adds a read-only app
          registration named <strong>Federation 360 sign-in logs</strong> and opens this app again, connected. It's the same setup Entra's verdict on the Flow tracer uses.
        </p>
        <CodeBlock code={cmd} />
        <div className="row">
          <ActionButton busy="Copying…" onClick={() => copyNow(cmd)}>Copy the commands</ActionButton>
          <ActionButton busy="Preparing the script…" onClick={async () => downloadFile("Connect-F360SignInLogs.ps1", setupScript)}>Download the script</ActionButton>
        </div>
      </div>
    );
  }

  const choose = (id: string) => {
    setTenantId(id);
    const c = configs.find((x) => x.tenantId === id);
    setWho(c ? signedInUser(c.tenantId) : null);
    setProblem(null);
  };
  const signIn = async () => {
    if (!cfg) throw new Error("Pick a tenant first.");
    const u = await signInForLogs(cfg);
    setWho(u);
    setProblem(null);
    return `Signed in as ${u}`;
  };
  const read = async () => {
    if (!cfg) throw new Error("Pick a tenant first.");
    const token = await graphToken(cfg);
    if (!token) {
      setWho(null);
      throw new Error("Your sign-in has ended. Click Sign in to read sign-in logs, then Read again.");
    }
    try {
      const r = await readTenantLogs(token, { days, user: upn.trim() || undefined, label: cfg.name || cfg.tenantId });
      onRead(r, cfg);
      setProblem(null);
      return `Read ${r.logs.signIns.length} sign-ins and ${r.logs.audits.length} audit events${r.capped.length ? " (stopped early; see the note)" : ""}`;
    } catch (e) {
      if (e instanceof LogsError) {
        if (e.problem === "signed-out") {
          signOut(cfg.tenantId);
          setWho(null);
        }
        setProblem(FIX[e.problem] ?? e.message);
      }
      throw e;
    }
  };

  return (
    <div className="stack small">
      <div className="row">
        <label htmlFor="tlr-tenant">Tenant</label>
        <select id="tlr-tenant" className="input" value={tenantId} onChange={(e) => choose(e.target.value)}>
          {configs.map((c) => <option key={c.tenantId} value={c.tenantId}>{c.name ? `${c.name} (${c.tenantId})` : c.tenantId}</option>)}
        </select>
        {who && cfg && <span className="muted">Reading as {who} <ActionButton className="btn sm" busy="Signing out…" report="toast" onClick={() => { signOut(cfg.tenantId); setWho(null); return "Signed out of the log reader"; }}>Sign out</ActionButton></span>}
      </div>
      {cfg?.clientId === "free" ? (
        <div className="callout">{FIX.unlicensed}</div>
      ) : !who ? (
        <div className="row">
          <ActionButton className="btn primary" busy="Signing in…" onClick={signIn}>Sign in to read sign-in logs</ActionButton>
          <span className="muted">A Microsoft sign-in window opens. Federation 360 asks only for read permissions.</span>
        </div>
      ) : (
        <div className="row">
          <label htmlFor="tlr-days">Last</label>
          <select id="tlr-days" className="input" value={days} onChange={(e) => setDays(Number(e.target.value))}>
            {[1, 3, 7, 14, 30].map((d) => <option key={d} value={d}>{d} day{d === 1 ? "" : "s"}</option>)}
          </select>
          {!fixedUser && <input aria-label="One user only (optional)" className="input" style={{ width: 260 }} placeholder="One user only (optional UPN)" value={upn} onChange={(e) => setUpn(e.target.value)} />}
          <ActionButton className="btn primary" busy="Reading sign-ins and audit events…" onClick={read}>Read from this tenant</ActionButton>
        </div>
      )}
      {problem && <div className="callout warn">{problem}</div>}
    </div>
  );
}

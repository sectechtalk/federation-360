// Shared pieces for the "read your tenant" panels on How access ends, Activity and User lookup (and the tenant and
// client ID boxes on Discover and Posture).
//
// The client ID of F360-Discovery is different in every tenant, so it is remembered per tenant ID: switching the
// tenant box between the lab and a production tenant brings back that tenant's client ID instead of keeping the
// other tenant's (or an empty box).
import type { ReactNode } from "react";
import { CodeBlock, Field } from "./ui";
import { ActionButton, copyNow, downloadFile } from "./busy";
import { usePref } from "../lib/store";

export const GUID = /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i;

/** Client ID for a tenant: the one saved for that tenant, else the single older shared value if no tenant has one yet. */
export function clientIdFor(tenantId: string, byTenant: Record<string, string>, legacy: string): string {
  const key = tenantId.trim().toLowerCase();
  if (byTenant[key] !== undefined) return byTenant[key];
  return Object.keys(byTenant).length === 0 ? legacy : "";
}

export function useTenantClient(defaultTenant: string): [string, (v: string) => void, string, (v: string) => void] {
  const [tenantId, setTenantId] = usePref("discover:tenantId", defaultTenant);
  const [legacy, setLegacy] = usePref("discover:clientId", "");
  const [byTenant, setByTenant] = usePref<Record<string, string>>("discover:clientIds", {});
  const clientId = clientIdFor(tenantId, byTenant, legacy);
  const setClientId = (v: string) => {
    const key = tenantId.trim().toLowerCase();
    if (GUID.test(key)) setByTenant({ ...byTenant, [key]: v.trim() });
    setLegacy(v.trim());
  };
  return [tenantId, (v: string) => setTenantId(v.trim()), clientId, setClientId];
}

/** Why the sign-in button is greyed out, in plain words, or null when it can be clicked. */
export function signInBlockReason(blocker: string | null, tenantId: string, clientId: string, extra?: string | null): string | null {
  if (blocker) return blocker;
  if (!tenantId.trim()) return "Fill in Directory (tenant) ID to turn on the sign-in button.";
  if (!GUID.test(tenantId.trim())) return "Directory (tenant) ID must be a GUID, like 00000000-0000-0000-0000-000000000000.";
  if (!clientId.trim())
    return "Fill in Client ID of F360-Discovery to turn on the sign-in button. Copy it from the Entra admin center: App registrations > All applications > F360-Discovery > Application (client) ID, in this same tenant.";
  if (!GUID.test(clientId.trim())) return "Client ID of F360-Discovery must be a GUID.";
  return extra ?? null;
}

export function TenantClientFields(props: {
  prefix: string;
  tenantId: string;
  setTenantId: (v: string) => void;
  clientId: string;
  setClientId: (v: string) => void;
}) {
  const { prefix, tenantId, setTenantId, clientId, setClientId } = props;
  return (
    <>
      <Field id={`${prefix}-tid`} label="Directory (tenant) ID" value={tenantId} onChange={setTenantId} placeholder="00000000-0000-0000-0000-000000000000" error={tenantId && !GUID.test(tenantId.trim()) ? "A tenant ID is a GUID." : null} />
      <Field id={`${prefix}-cid`} label="Client ID of F360-Discovery" value={clientId} onChange={setClientId} placeholder="Application (client) ID of F360-Discovery in this tenant" error={clientId && !GUID.test(clientId.trim()) ? "A client ID is a GUID." : null} />
      <p className="small muted">The client ID is remembered for each tenant ID, so switching tenants brings back the right one.</p>
    </>
  );
}

/** A grey note under a disabled sign-in button saying what to fill in. */
export function BlockedNote({ reason }: { reason: string | null }) {
  if (!reason) return null;
  return <p className="small callout warn" role="note">{reason}</p>;
}

/** #Requires only works in a script file, so it is dropped here; the run command checks for PowerShell 7 instead. */
export function runnableScript(script: string): string {
  return script.replace(/^#Requires[^\n]*\r?\n/im, "");
}

function base64Utf8(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

/**
 * One line that carries the whole script (base64) and runs it in memory with the given arguments. Pasting one line
 * avoids the console mangling a multi-line paste, and nothing is written to disk except the script's own result file.
 */
export function inlineRunCommand(script: string, args: string): string {
  const b64 = base64Utf8(runnableScript(script));
  return `if ($PSVersionTable.PSVersion.Major -lt 7) { Write-Host 'Open PowerShell 7 (pwsh), then paste this again.' -ForegroundColor Yellow } else { & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64}')))) ${args} }`;
}

/** "PowerShell" block: run without downloading (copy one line, paste it) or download the .ps1 and run the file. */
export function PowerShellRun(props: { title: ReactNode; name: string; script: string; args: string; children?: ReactNode }) {
  const { title, name, script, args, children } = props;
  const downloadCommands = `cd $HOME\\Downloads\nUnblock-File .\\${name}\n.\\${name} ${args}`;
  return (
    <div className="stack">
      <h3>{title}</h3>
      <p className="small">
        <strong>Run without downloading.</strong> Click <strong>Copy run command</strong>, open PowerShell 7 (pwsh), right-click to paste, then press Enter.
        It is one line that holds the whole {name} script and runs it in memory with these arguments:
      </p>
      <CodeBlock code={`${name} ${args}`} wrap />
      <div className="row">
        <ActionButton className="btn primary" busy="Copying the run command…" report="toast" onClick={() => copyNow(inlineRunCommand(script, args)).then(() => `Run command for ${name} copied. Paste it into PowerShell 7 and press Enter.`)}>Copy run command</ActionButton>
      </div>
      <details>
        <summary className="small">Or download {name} and run the file</summary>
        <div className="stack" style={{ marginTop: 8 }}>
          <div className="row">
            <ActionButton className="btn primary" busy="Preparing the script…" onClick={async () => downloadFile(name, script)}>Download {name}</ActionButton>
          </div>
          <CodeBlock code={downloadCommands} />
        </div>
      </details>
      {children}
    </div>
  );
}

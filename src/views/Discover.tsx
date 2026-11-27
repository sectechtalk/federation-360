import { useEffect, useMemo, useState } from "react";
import { useTenantClient } from "../components/tenantSignIn";
import { CodeBlock, Field, ProtoChip, Seg, useApp } from "../components/ui";
import { ActionButton, BusyNote, downloadFile } from "../components/busy";
import { daysUntil } from "../lib/health";
import {
  collectEntraExport, entraAdapter, GRAPH_SCOPES, makeSampleEntraExport,
  type DiscoverySnapshot, type EntraExport, type ProviderAdapter,
} from "@sectechtalk/f360-collector";
import { browserSignInBlocker, currentRedirectUri, redeemCode, startSignIn, takeRedirectResult } from "../lib/discovery/entraLive";
import { applyMerge, planMerge } from "../lib/discovery/merge";
import type { AppIntegration, DiscoveryInfo } from "../lib/types";
import exportScript from "@sectechtalk/f360-collector/powershell/Export-F360EntraInventory.ps1?raw";
import { Section } from "../components/Section";

const SCRIPT_NAME = "Export-F360EntraInventory.ps1";

const ADAPTERS: ProviderAdapter[] = [entraAdapter];
const GUID = /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i;

function credSummary(d: DiscoveryInfo) {
  if (!d.credentials.length) return <span className="muted">none</span>;
  const next = [...d.credentials].filter((c) => c.end).sort((a, b) => a.end.localeCompare(b.end));
  const live = next.filter((c) => daysUntil(c.end.slice(0, 10)) >= 0);
  const expired = next.length - live.length;
  const soon = live[0];
  return (
    <span className="small">
      {d.credentials.length} {d.credentials.length === 1 ? "credential" : "credentials"}
      {soon && <>, next expires {soon.end.slice(0, 10)}</>}
      {expired > 0 && <>, <span style={{ color: "var(--crit)" }}>{expired} expired</span></>}
    </span>
  );
}

function Preview({ snap, example, onDone, onDiscard }: { snap: DiscoverySnapshot; example: boolean; onDone: (tenantId: string) => void; onDiscard: () => void }) {
  const { tenants, apps, store, toast } = useApp();
  const plan = useMemo(() => planMerge(snap, tenants, apps, new Date(), { example }), [snap, tenants, apps, example]);
  const [flagMissing, setFlagMissing] = useState(true);

  type Row = { action: "New" | "Update" | "Adopt" | "Same" | "Missing"; app: AppIntegration; changes?: string[] };
  const rows: Row[] = [
    ...plan.creates.map((app) => ({ action: "New" as const, app })),
    ...plan.updates.map((u) => ({ action: u.adopted ? ("Adopt" as const) : ("Update" as const), app: u.after, changes: u.changes })),
    ...plan.missing.map((app) => ({ action: "Missing" as const, app })),
    ...plan.unchanged.map((app) => ({ action: "Same" as const, app })),
  ];
  const writes = plan.creates.length + plan.updates.length + (flagMissing ? plan.missing.length : 0);

  const apply = async () => {
    if (!store) throw new Error("Storage isn't connected yet. Wait a moment and try again.");
    try {
      await applyMerge(store, plan, { flagMissing });
    } catch (e: any) {
      throw new Error("Couldn't save: " + (e?.message ?? e));
    }
    const msg = `Inventory updated: ${plan.creates.length} added, ${plan.updates.length} updated`;
    onDone(plan.tenant.id);
    toast(msg); // after the page change, so it isn't replaced by "Opened Inventory"
    return msg;
  };

  return (
    <Section className="panel stack">
      <div className="spread">
        <div>
          <div className="eyebrow">Scan result · {new Date(snap.collectedAt).toLocaleString()}</div>
          <h2>{snap.tenant.name}</h2>
          <span className="small mono">{snap.tenant.ref}{snap.tenant.domain && ` · ${snap.tenant.domain}`}</span>
        </div>
        <div className="row">
          <button className="btn" onClick={() => { onDiscard(); toast("Scan discarded. Nothing was added to the inventory."); }}>Discard</button>
          <ActionButton className="btn primary" busy="Saving to inventory…" disabled={!writes} onClick={apply}>
            {writes ? `Add to inventory (${writes} ${writes === 1 ? "change" : "changes"})` : "Inventory is already up to date"}
          </ActionButton>
        </div>
      </div>

      <div className="row">
        <span className="tag">{plan.tenantIsNew ? "New tenant entry" : `Matches tenant “${plan.tenant.name}”`}</span>
        <span className="tag">{plan.creates.length} new</span>
        <span className="tag">{plan.updates.length} updated</span>
        <span className="tag">{plan.unchanged.length} unchanged</span>
        {plan.missing.length > 0 && <span className="tag">{plan.missing.length} no longer found</span>}
      </div>

      {example && <div className="callout">This is the fictional sample tenant. Anything you add is marked as an example, so Inventory's “Remove examples” clears it.</div>}
      {snap.skipped.length > 0 && (
        <p className="small muted">Left out on purpose: {snap.skipped.map((s) => `${s.count} ${s.reason}`).join("; ")}.</p>
      )}
      {snap.warnings.map((w) => <div key={w} className="callout warn">{w}</div>)}
      {plan.missing.length > 0 && (
        <label className="row small">
          <input type="checkbox" checked={flagMissing} onChange={(e) => setFlagMissing(e.target.checked)} />
          Flag the {plan.missing.length} apps an earlier scan found but this one didn't. Nothing is deleted.
        </label>
      )}

      <div className="table-wrap">
        <table>
          <thead><tr><th>Change</th><th>Name</th><th>Protocol</th><th>What it is</th><th>Owner</th><th>Credentials</th><th>Changed</th></tr></thead>
          <tbody>
            {rows.map(({ action, app, changes }) => (
              <tr key={app.id}>
                <td><span className="tag">{action}</span></td>
                <td><strong>{app.name}</strong>{app.discovery?.thirdParty && <div className="small muted">by {app.discovery.publisher ?? "another organization"}</div>}</td>
                <td><ProtoChip p={app.protocol} /></td>
                <td className="small">{snap.apps.find((d) => d.discovery.externalId === app.discovery?.externalId)?.kind ?? "—"}</td>
                <td className="small">{app.owner || <span style={{ color: "var(--warn)" }}>no owner</span>}</td>
                <td>{app.discovery ? credSummary(app.discovery) : "—"}</td>
                <td className="small">{action === "Adopt" ? "Linked your existing entry; " : ""}{changes?.join(", ") ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="small muted">
        The tenant's values replace names, identifiers, URLs, credentials and owners. Your status, environment, provisioning, SCIM settings and notes are kept.
      </p>
    </Section>
  );
}

export default function Discover() {
  const { tenants, go, toast } = useApp();
  const [provider, setProvider] = useState<"entra" | "okta">("entra");
  const entraTenants = tenants.filter((t) => t.platform === "entra" && GUID.test(t.tenantRef) && !t.example);
  const [tenantId, setTenantId, clientId, setClientId] = useTenantClient(entraTenants[0]?.tenantRef ?? "");
  const [snap, setSnap] = useState<DiscoverySnapshot | null>(null);
  const [raw, setRaw] = useState<EntraExport | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const blocker = browserSignInBlocker();
  const redirectUri = currentRedirectUri();

  const load = (data: unknown) => {
    setError(null);
    const adapter = ADAPTERS.find((a) => a.detect(data));
    if (!adapter) throw new Error("This file isn't a Federation 360 discovery export. Run the export script and load the file it saves.");
    setRaw(data as EntraExport);
    setSnap(adapter.toSnapshot(data));
  };

  // Coming back from Microsoft's sign-in page.
  useEffect(() => {
    const r = takeRedirectResult();
    if (!r) return;
    if (r.error || !r.code || !r.pending) {
      setError(r.error ?? "Sign-in didn't complete.");
      return;
    }
    (async () => {
      try {
        setStatus("Signed in. Getting a read-only token…");
        const token = await redeemCode(r.code!, r.pending!);
        const x = await collectEntraExport(token, r.pending!.tenantId, setStatus);
        load(x);
        setStatus(null);
      } catch (e: any) {
        setStatus(null);
        setError(e?.message ?? String(e));
      }
    })();
  }, []);

  const onFile = async (f: File | undefined) => {
    if (!f) return;
    setError(null);
    setStatus(`Reading ${f.name}…`);
    try {
      load(JSON.parse((await f.text()).replace(/^﻿/, "")));
      toast(`Loaded ${f.name}`);
    } catch (e: any) {
      setError(e instanceof SyntaxError ? "That file isn't valid JSON." : e.message);
    }
    setStatus(null);
  };

  const download = () => {
    if (!raw) throw new Error("There's no scan to save.");
    return downloadFile(`f360-entra-export-${raw.collectedAt.slice(0, 10)}.json`, JSON.stringify(raw), "application/json");
  };

  const tidForScript = GUID.test(tenantId) ? tenantId : "<your-tenant-id>";
  const commands = `cd $HOME\\Downloads\nUnblock-File .\\${SCRIPT_NAME}\n.\\${SCRIPT_NAME} -TenantId ${tidForScript} -OutFile $HOME\\Downloads\\f360-entra-export.json`;
  const downloadScript = () => downloadFile(SCRIPT_NAME, exportScript);
  const signIn = async () => {
    setError(null);
    await startSignIn({ tenantId, clientId, redirectUri });
    // The browser normally leaves for Microsoft's sign-in page before this wait ends.
    await new Promise((r) => setTimeout(r, 15000));
    throw new Error("Microsoft's sign-in page didn't open. Check the tenant ID and client ID, then try again.");
  };
  const trySample = () => {
    load(makeSampleEntraExport());
    toast("Sample tenant loaded");
  };
  const canSignIn = !blocker && GUID.test(tenantId) && GUID.test(clientId);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Discover</h1>
          <p>
            Read every SAML, OpenID Connect and OAuth app straight from your tenant, with its certificates, secrets, redirect URIs, owners and permissions,
            and fill the inventory with the real thing. Discovery only reads. It never changes anything in the tenant.
          </p>
        </div>
        <Seg label="Identity provider" value={provider} onChange={setProvider} options={[{ v: "entra", l: "Microsoft Entra ID" }, { v: "okta", l: "Okta (later)" }]} />
      </div>

      {provider === "okta" ? (
        <div className="empty"><p>Okta discovery isn't built yet. It will use the same preview and merge as Entra, reading apps and their sign-on settings through the Okta Apps API.</p></div>
      ) : snap ? (
        <>
          <Preview snap={snap} example={raw?.collector === "sample"} onDiscard={() => { setSnap(null); setRaw(null); }} onDone={(t) => go("inventory", { tenant: t })} />
          {raw?.collector === "browser" && <div><ActionButton className="btn sm" busy="Building file…" onClick={download}>Save this scan as a file</ActionButton></div>}
        </>
      ) : (
        <>
          {status && <BusyNote>{status}</BusyNote>}
          {error && <div className="callout warn" role="alert">{error}</div>}

          <Field
            id="d-tid"
            label="Directory (tenant) ID"
            value={tenantId}
            onChange={setTenantId}
            placeholder="00000000-0000-0000-0000-000000000000"
            error={tenantId && !GUID.test(tenantId) ? "A tenant ID is a GUID, like 8f2b6c1e-0d4a-4a7e-9a51-3c0d2e7b9f10." : null}
            hint={entraTenants.length ? <>From your inventory: {entraTenants.map((t, i) => <span key={t.id}>{i ? ", " : ""}<button className="btn ghost sm" onClick={() => { setTenantId(t.tenantRef); toast(`Tenant ID filled in from ${t.name}`); }}>{t.name}</button></span>)}</> : "Entra admin center > Entra ID > Overview > Tenant ID."}
          />

          <Section className="panel stack">
            <div>
              <div className="eyebrow">Option 1 · works everywhere, including the Claude artifact</div>
              <h2>Run the export script, then load its file</h2>
            </div>
            <p>
              The script signs you in with the Microsoft Graph PowerShell module, asks for read-only {GRAPH_SCOPES.join(" and ")}, and saves one JSON file.
              The file holds names, IDs, URLs and dates. Graph never returns secret values, and the script drops certificate bodies too.
            </p>
            <div className="row">
              <ActionButton busy="Preparing download…" onClick={downloadScript}>Download {SCRIPT_NAME}</ActionButton>
            </div>
            <p>Save it to your Downloads folder, then run these three lines in PowerShell 7. <span className="mono">Unblock-File</span> clears the "downloaded from the internet" mark so Windows lets it run.</p>
            <CodeBlock code={commands} />
            <p className="small muted">
              The first run installs the Microsoft.Graph.Authentication module for your user. On Microsoft's consent screen, as a Global Administrator,
              tick “Consent on behalf of your organization” and select Accept. If no sign-in window appears or it says “User canceled authentication”, run the same command with <span className="mono">-UseDeviceCode</span> added and sign in with the code at microsoft.com/devicelogin.
            </p>
            <details>
              <summary>Show the script ({exportScript.split("\n").length} lines)</summary>
              <CodeBlock code={exportScript} />
            </details>
            <label className="field" htmlFor="d-file">
              <span>Load export file</span>
              <input id="d-file" className="input" type="file" accept=".json,application/json" onChange={(e) => onFile(e.target.files?.[0])} />
            </label>
          </Section>

          <Section className="panel stack">
            <div>
              <div className="eyebrow">Option 2 · when Federation 360 runs on localhost or your own site</div>
              <h2>Sign in and scan from this page</h2>
            </div>
            <p>
              Uses the authorization code flow with PKCE. The access token stays in this page's memory and is gone when you close it.
              It needs the lab's <span className="mono">F360-Discovery</span> app registration (or your own single-page app with the same delegated permissions).
            </p>
            {blocker && <div className="callout warn">{blocker} Use option 1 here, or run <span className="mono">npm run dev</span> and open http://localhost:5173/#discover.</div>}
            <div className="grid-2">
              <Field id="d-cid" label="Client ID of F360-Discovery" value={clientId} onChange={setClientId} placeholder="from the Terraform output discovery_client_id" error={clientId && !GUID.test(clientId) ? "A client ID is a GUID." : null} />
              <label className="field">
                <span>Redirect URI this page uses</span>
                <input className="input mono" readOnly value={redirectUri} />
                <span className="hint">Must be listed as a single-page application redirect URI on the app.</span>
              </label>
            </div>
            <div className="row">
              <ActionButton className="btn primary" busy="Opening Microsoft sign-in…" disabled={!canSignIn} onClick={signIn}>
                Sign in and scan
              </ActionButton>
            </div>
          </Section>

          <Section className="panel stack">
            <h2>No tenant handy?</h2>
            <div className="spread">
            <span>No tenant handy? Try the preview with a fictional tenant shaped like the lab.</span>
            <ActionButton busy="Loading sample…" onClick={trySample}>
              Try with sample data
            </ActionButton>
          </div>
          </Section>
        </>
      )}
    </div>
  );
}

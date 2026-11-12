import { Fragment, useState } from "react";
import { useApp, ProtoChip, Sev, Field, FindingList, copyText } from "../components/ui";
import { appHealth, worst } from "../lib/health";
import { PROTOCOLS } from "../lib/protocols";
import {
  emptyOidc, emptySaml, ENV_LABEL, newId, PLATFORM_LABEL,
  type AppIntegration, type Environment, type Platform, type Tenant,
} from "../lib/types";
import { wellKnownUrls } from "../lib/metadata";

const envOpts = Object.keys(ENV_LABEL) as Environment[];
const platOpts = Object.keys(PLATFORM_LABEL) as Platform[];

export function blankApp(tenantId: string): AppIntegration {
  return {
    id: newId(), tenantId, name: "", protocol: "saml", environment: "prod", owner: "", status: "planned",
    provisioning: "none", saml: emptySaml(), oidc: emptyOidc(), notes: "", updatedAt: new Date().toISOString(),
  };
}

function TenantEditor({ initial, onClose }: { initial: Tenant; onClose: () => void }) {
  const { store, toast, apps } = useApp();
  const [t, setT] = useState(initial);
  const [confirmDel, setConfirmDel] = useState(false);
  const set = (k: keyof Tenant, v: string) => setT({ ...t, [k]: v });
  const save = async () => {
    if (!t.name.trim()) return toast("Give the tenant a name");
    await store?.put("tenants", { ...t, updatedAt: new Date().toISOString() });
    toast("Tenant saved");
    onClose();
  };
  const del = async () => {
    await store?.remove("tenants", t.id);
    toast("Tenant deleted");
    onClose();
  };
  const used = apps.filter((a) => a.tenantId === t.id).length;
  return (
    <div className="drawer-bg" onClick={onClose}>
      <div className="drawer" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="Edit tenant">
        <div className="spread"><h2>{initial.name ? "Edit tenant" : "Add tenant"}</h2><button className="btn ghost" onClick={onClose}>Close</button></div>
        <Field id="t-name" label="Name" value={t.name} onChange={(v) => set("name", v)} placeholder="Contoso (corporate)" />
        <div className="grid-2">
          <Field id="t-plat" label="Platform" value={t.platform} onChange={(v) => set("platform", v)} options={platOpts} hint={PLATFORM_LABEL[t.platform]} />
          <Field id="t-env" label="Environment" value={t.environment} onChange={(v) => set("environment", v)} options={envOpts} />
        </div>
        <Field id="t-ref" label={t.platform === "entra" ? "Directory (tenant) ID" : t.platform === "aws-idc" ? "Instance ARN or identity store ID" : "Org / issuer URL"} value={t.tenantRef} onChange={(v) => set("tenantRef", v)} placeholder={t.platform === "entra" ? "8f2b6c1e-0d4a-4a7e-9a51-3c0d2e7b9f10" : ""} hint="Used to build discovery and metadata URLs." />
        <Field id="t-dom" label="Primary domain / portal" value={t.domain} onChange={(v) => set("domain", v)} placeholder="contoso.com" />
        <Field id="t-notes" label="Notes" value={t.notes} onChange={(v) => set("notes", v)} multiline />
        <div className="spread">
          <div className="row">
            <button className="btn primary" onClick={save}>Save tenant</button>
            <button className="btn" onClick={onClose}>Cancel</button>
          </div>
          {initial.name && (confirmDel ? (
            <div className="row"><span className="small">{used ? `${used} apps still point here.` : "Delete for good?"}</span><button className="btn danger" onClick={del}>Yes, delete</button><button className="btn" onClick={() => setConfirmDel(false)}>Keep</button></div>
          ) : <button className="btn danger" onClick={() => setConfirmDel(true)}>Delete</button>)}
        </div>
      </div>
    </div>
  );
}

function AppEditor({ initial, onClose }: { initial: AppIntegration; onClose: () => void }) {
  const { store, toast, tenants, go } = useApp();
  const [a, setA] = useState<AppIntegration>(initial);
  const [confirmDel, setConfirmDel] = useState(false);
  const set = (k: keyof AppIntegration, v: any) => setA({ ...a, [k]: v });
  const ss = (k: keyof AppIntegration["saml"], v: string) => setA({ ...a, saml: { ...a.saml, [k]: v } });
  const so = (k: keyof AppIntegration["oidc"], v: string) => setA({ ...a, oidc: { ...a.oidc, [k]: v } });
  const isNew = !initial.name;
  const save = async () => {
    if (!a.name.trim()) return toast("Give the integration a name");
    await store?.put("apps", { ...a, updatedAt: new Date().toISOString() });
    toast("Integration saved");
    onClose();
  };
  const del = async () => {
    await store?.remove("apps", a.id);
    toast("Integration deleted");
    onClose();
  };
  const tenant = tenants.find((t) => t.id === a.tenantId);
  const findings = appHealth(a);
  const urls = tenant ? wellKnownUrls(tenant.platform, tenant.tenantRef) : [];

  return (
    <div className="drawer-bg" onClick={onClose}>
      <div className="drawer" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="Edit integration">
        <div className="spread">
          <h2>{isNew ? "Add integration" : a.name}</h2>
          <button className="btn ghost" onClick={onClose}>Close</button>
        </div>
        {!isNew && (
          <div className="row">
            {a.protocol === "saml" && <button className="btn sm" onClick={() => go("saml", { app: a.id })}>Decode a SAML message for this app</button>}
            {(a.protocol === "oidc" || a.protocol === "oauth") && <button className="btn sm" onClick={() => go("jwt", { app: a.id })}>Decode a token for this app</button>}
            <button className="btn sm" onClick={() => go("metadata", { tenant: a.tenantId })}>Check the IdP's metadata</button>
          </div>
        )}
        {!isNew && findings.length > 0 && <FindingList findings={findings} />}

        <Field id="a-name" label="Name" value={a.name} onChange={(v) => set("name", v)} placeholder="Expense Portal" />
        <div className="grid-2">
          <label className="field" htmlFor="a-tenant">
            <span>Tenant</span>
            <select id="a-tenant" className="input" value={a.tenantId} onChange={(e) => set("tenantId", e.target.value)}>
              {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          </label>
          <label className="field" htmlFor="a-proto">
            <span>Protocol</span>
            <select id="a-proto" className="input" value={a.protocol} onChange={(e) => set("protocol", e.target.value)}>
              {PROTOCOLS.map((p) => <option key={p.id} value={p.id} disabled={p.status === "planned"}>{p.name}{p.status === "planned" ? " (coming soon)" : ""}</option>)}
            </select>
          </label>
          <Field id="a-env" label="Environment" value={a.environment} onChange={(v) => set("environment", v)} options={envOpts} />
          <Field id="a-status" label="Status" value={a.status} onChange={(v) => set("status", v)} options={["live", "testing", "planned", "broken"]} />
          <Field id="a-owner" label="Owner" value={a.owner} onChange={(v) => set("owner", v)} placeholder="Team or person accountable" />
          <Field id="a-prov" label="Provisioning" value={a.provisioning} onChange={(v) => set("provisioning", v)} options={["none", "scim", "jit", "manual"]} hint="How accounts get created in the app." />
        </div>

        {a.protocol === "saml" && (
          <fieldset className="panel stack" style={{ margin: 0 }}>
            <legend className="eyebrow">SAML settings</legend>
            <Field id="s-eid" label="SP Entity ID (Identifier)" value={a.saml.entityId} onChange={(v) => ss("entityId", v)} hint="Must equal the Audience in assertions." />
            <Field id="s-acs" label="ACS URL (Reply URL)" value={a.saml.acsUrl} onChange={(v) => ss("acsUrl", v)} />
            <Field id="s-son" label="Sign-on URL" value={a.saml.signOnUrl} onChange={(v) => ss("signOnUrl", v)} />
            <Field id="s-idp" label="IdP Entity ID (Issuer)" value={a.saml.idpEntityId} onChange={(v) => ss("idpEntityId", v)} hint={tenant?.platform === "entra" && tenant.tenantRef ? `For this tenant: https://sts.windows.net/${tenant.tenantRef}/` : undefined} />
            <div className="grid-2">
              <Field id="s-nis" label="NameID source" value={a.saml.nameIdSource} onChange={(v) => ss("nameIdSource", v)} />
              <Field id="s-nif" label="NameID format" value={a.saml.nameIdFormat} onChange={(v) => ss("nameIdFormat", v)} />
              <Field id="s-th" label="Signing cert thumbprint (SHA-1)" value={a.saml.certThumbprint} onChange={(v) => ss("certThumbprint", v)} />
              <Field id="s-exp" label="Signing cert expires" type="date" value={a.saml.certExpires} onChange={(v) => ss("certExpires", v)} />
            </div>
          </fieldset>
        )}

        {(a.protocol === "oidc" || a.protocol === "oauth") && (
          <fieldset className="panel stack" style={{ margin: 0 }}>
            <legend className="eyebrow">{a.protocol === "oidc" ? "OpenID Connect" : "OAuth 2.0"} settings</legend>
            <Field id="o-cid" label="Client (application) ID" value={a.oidc.clientId} onChange={(v) => so("clientId", v)} />
            <div className="grid-2">
              <Field id="o-gt" label="Grant type" value={a.oidc.grantType} onChange={(v) => so("grantType", v)} options={["authorization_code", "client_credentials", "device_code", "implicit"]} />
              <Field id="o-ct" label="Client type" value={a.oidc.clientType} onChange={(v) => so("clientType", v)} options={["confidential", "public"]} />
            </div>
            <Field id="o-ru" label="Redirect URIs (one per line)" value={a.oidc.redirectUris} onChange={(v) => so("redirectUris", v)} multiline />
            <Field id="o-sc" label="Scopes" value={a.oidc.scopes} onChange={(v) => so("scopes", v)} />
            <Field id="o-aud" label="Expected audience (aud)" value={a.oidc.audience} onChange={(v) => so("audience", v)} hint="ID tokens: the client ID. Access tokens: the API's App ID URI or client ID." />
            <Field id="o-iss" label="Expected issuer (iss)" value={a.oidc.issuer} onChange={(v) => so("issuer", v)} hint={tenant?.platform === "entra" && tenant.tenantRef ? `v2.0: https://login.microsoftonline.com/${tenant.tenantRef}/v2.0` : undefined} />
            {a.oidc.clientType === "confidential" && <Field id="o-se" label="Secret / certificate expires" type="date" value={a.oidc.secretExpires} onChange={(v) => so("secretExpires", v)} />}
          </fieldset>
        )}

        <Field id="a-notes" label="Notes" value={a.notes} onChange={(v) => set("notes", v)} multiline />

        {urls.length > 0 && (
          <details>
            <summary>Identity provider URLs for {tenant?.name}</summary>
            <dl className="kv" style={{ marginTop: 8 }}>
              {urls.map((u) => <Fragment key={u.url}><dt>{u.label}</dt><dd><a href={u.url} target="_blank" rel="noreferrer">{u.url}</a></dd></Fragment>)}
            </dl>
          </details>
        )}

        <div className="spread">
          <div className="row">
            <button className="btn primary" onClick={save}>Save integration</button>
            <button className="btn" onClick={onClose}>Cancel</button>
          </div>
          {!isNew && (confirmDel ? (
            <div className="row"><span className="small">Delete for good?</span><button className="btn danger" onClick={del}>Yes, delete</button><button className="btn" onClick={() => setConfirmDel(false)}>Keep</button></div>
          ) : <button className="btn danger" onClick={() => setConfirmDel(true)}>Delete</button>)}
        </div>
      </div>
    </div>
  );
}

function ImportExport({ onClose }: { onClose: () => void }) {
  const { tenants, apps, store, toast } = useApp();
  const json = JSON.stringify({ format: "federation-360", version: 1, tenants, apps }, null, 2);
  const [text, setText] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const doImport = async () => {
    try {
      const d = JSON.parse(text);
      if (!Array.isArray(d.tenants) || !Array.isArray(d.apps)) throw new Error("Expected { tenants: [...], apps: [...] }.");
      await Promise.all([...d.tenants.map((t: Tenant) => store?.put("tenants", t)), ...d.apps.map((a: AppIntegration) => store?.put("apps", a))]);
      toast(`Imported ${d.tenants.length} tenants and ${d.apps.length} apps`);
      onClose();
    } catch (e: any) {
      setErr("Couldn't import: " + e.message);
    }
  };
  return (
    <div className="drawer-bg" onClick={onClose}>
      <div className="drawer" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="Import or export">
        <div className="spread"><h2>Back up or move your inventory</h2><button className="btn ghost" onClick={onClose}>Close</button></div>
        <p className="muted">Copy the JSON to save it in a file or a Git repository. Paste JSON below to import; items with the same ID are replaced.</p>
        <div className="row"><button className="btn primary" onClick={() => copyText(json, toast)}>Copy inventory JSON</button><span className="small muted">{tenants.length} tenants, {apps.length} apps</span></div>
        <Field id="imp" label="Import JSON" value={text} onChange={(v) => { setText(v); setErr(null); }} multiline rows={10} error={err} placeholder='{"tenants": [...], "apps": [...]}' />
        <div><button className="btn" onClick={doImport} disabled={!text.trim()}>Import</button></div>
      </div>
    </div>
  );
}

export default function Inventory() {
  const { tenants, apps, params, loading, loadExamples, store, toast } = useApp();
  const [tenantFilter, setTenantFilter] = useState(params.tenant ?? "");
  const [q, setQ] = useState("");
  const [editingApp, setEditingApp] = useState<AppIntegration | null>(() => (params.app ? apps.find((a) => a.id === params.app) ?? null : null));
  const [editingTenant, setEditingTenant] = useState<Tenant | null>(() =>
    params.add === "tenant" ? { id: newId(), name: "", platform: "entra", tenantRef: "", domain: "", environment: "prod", notes: "", updatedAt: "" } : null,
  );
  const [io, setIo] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);

  const shown = apps.filter((a) => (!tenantFilter || a.tenantId === tenantFilter) && (!q || (a.name + a.owner + a.saml.entityId + a.oidc.clientId).toLowerCase().includes(q.toLowerCase())));
  const tenantName = (id: string) => tenants.find((t) => t.id === id)?.name ?? "—";
  const examples = [...tenants.filter((t) => t.example), ...apps.filter((a) => a.example)];
  const clearExamples = async () => {
    await Promise.all([...tenants.filter((t) => t.example).map((t) => store?.remove("tenants", t.id)), ...apps.filter((a) => a.example).map((a) => store?.remove("apps", a.id))]);
    setConfirmClear(false);
    toast("Example data removed");
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Inventory</h1>
          <p>Every tenant and every app integration, with the values you need when something breaks: identifiers, URLs, certificate and secret expiry, and an owner.</p>
        </div>
        <div className="row">
          <button className="btn" onClick={() => setIo(true)}>Back up / import</button>
          <button className="btn" onClick={() => setEditingTenant({ id: newId(), name: "", platform: "entra", tenantRef: "", domain: "", environment: "prod", notes: "", updatedAt: "" })}>Add tenant</button>
          <button className="btn primary" disabled={!tenants.length} onClick={() => setEditingApp(blankApp(tenantFilter || tenants[0]?.id || ""))}>Add integration</button>
        </div>
      </div>

      {examples.length > 0 && (
        <div className="callout spread">
          <span>{examples.length} fictional example items are loaded so you can explore. Remove them when you add your own.</span>
          {confirmClear ? (
            <span className="row"><button className="btn sm danger" onClick={clearExamples}>Remove all examples</button><button className="btn sm" onClick={() => setConfirmClear(false)}>Keep</button></span>
          ) : <button className="btn sm" onClick={() => setConfirmClear(true)}>Remove examples</button>}
        </div>
      )}

      <section className="panel">
        <div className="panel-head"><h2>Tenants</h2><span className="sub">Click to edit</span></div>
        {loading ? <p className="muted">Loading…</p> : tenants.length === 0 ? (
          <div className="empty">
            <p>No tenants yet. A tenant is one identity provider instance: an Entra tenant, an AWS IAM Identity Center instance, an Okta org.</p>
            <button className="btn" onClick={loadExamples}>Load example data</button>
          </div>
        ) : (
          <div className="grid-3">
            {tenants.map((t) => (
              <button key={t.id} className="panel card-btn" style={{ padding: 12, borderColor: tenantFilter === t.id ? "var(--accent)" : undefined }} onClick={() => setEditingTenant(t)}>
                <div className="spread"><strong>{t.name}</strong>{t.example && <span className="example-flag">Example</span>}</div>
                <span className="small muted">{PLATFORM_LABEL[t.platform]} · {ENV_LABEL[t.environment]}</span>
                <span className="small mono" style={{ overflowWrap: "anywhere" }}>{t.tenantRef || "no ID recorded"}</span>
                <span className="small">{apps.filter((a) => a.tenantId === t.id).length} integrations</span>
              </button>
            ))}
          </div>
        )}
      </section>

      <section className="stack">
        <div className="spread">
          <h2>Integrations</h2>
          <div className="row">
            <input aria-label="Search integrations" className="input" style={{ width: 220 }} placeholder="Search name, owner, ID…" value={q} onChange={(e) => setQ(e.target.value)} />
            <select aria-label="Filter by tenant" className="input" style={{ width: 220 }} value={tenantFilter} onChange={(e) => setTenantFilter(e.target.value)}>
              <option value="">All tenants</option>
              {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Protocol</th><th>Tenant</th><th>Env</th><th>Identifier</th><th>Owner</th><th>Status</th><th>Health</th></tr></thead>
            <tbody>
              {shown.map((a) => {
                const h = appHealth(a);
                return (
                  <tr key={a.id} className="clickable" onClick={() => setEditingApp(a)}>
                    <td><strong>{a.name}</strong>{a.example && <> <span className="example-flag">Example</span></>}</td>
                    <td><ProtoChip p={a.protocol} />{a.provisioning === "scim" && <> <span className="chip proto-scim">SCIM</span></>}</td>
                    <td>{tenantName(a.tenantId)}</td>
                    <td>{a.environment}</td>
                    <td className="small" style={{ maxWidth: 260, overflowWrap: "anywhere", fontFamily: "var(--font-mono)" }}>{a.protocol === "saml" ? a.saml.entityId : a.oidc.clientId}</td>
                    <td>{a.owner || <span className="muted">—</span>}</td>
                    <td><span className="tag">{a.status}</span></td>
                    <td><Sev s={worst(h)} label={worst(h) === "ok" ? "Healthy" : undefined} /></td>
                  </tr>
                );
              })}
              {!shown.length && <tr><td colSpan={8} className="muted">No integrations match.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      {editingApp && <AppEditor initial={editingApp} onClose={() => setEditingApp(null)} />}
      {editingTenant && <TenantEditor initial={editingTenant} onClose={() => setEditingTenant(null)} />}
      {io && <ImportExport onClose={() => setIo(false)} />}
    </div>
  );
}

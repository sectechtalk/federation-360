import { Fragment, useState } from "react";
import { useApp, ProtoChip, Sev, Field, FindingList } from "../components/ui";
import { ActionButton, copyNow, downloadFile } from "../components/busy";
import { appHealth, daysUntil, worst } from "../lib/health";
import { PROTOCOLS } from "../lib/protocols";
import {
  emptyOidc, emptyProfile, emptySaml, emptyScim, ENV_LABEL, newId, PLATFORM_LABEL,
  type AppIntegration, type AppProfile, type DiscoveryInfo, type Environment, type Platform, type Tenant,
} from "../lib/types";
import { wellKnownUrls } from "../lib/metadata";
import { assertNoSecretMaterial, buildCredentialsExport } from "../lib/credentialExport";
import { usePref } from "../lib/store";
import { accessRow } from "../lib/access";
import { AccessCard, useAccessSnapshot } from "./AccessEnds";
import { Section } from "../components/Section";

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
    if (!t.name.trim()) throw new Error("Give the tenant a name");
    if (!store) throw new Error("Storage isn't connected yet. Wait a moment and try again.");
    await store.put("tenants", { ...t, updatedAt: new Date().toISOString() });
    toast("Tenant saved");
    onClose();
  };
  const del = async () => {
    if (!store) throw new Error("Storage isn't connected yet. Wait a moment and try again.");
    await store.remove("tenants", t.id);
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
            <ActionButton className="btn primary" busy="Saving…" onClick={save}>Save tenant</ActionButton>
            <button className="btn" onClick={onClose}>Cancel</button>
          </div>
          {initial.name && (confirmDel ? (
            <div className="row"><span className="small">{used ? `${used} apps still point here.` : "Delete for good?"}</span><ActionButton className="btn danger" busy="Deleting…" onClick={del}>Yes, delete</ActionButton><button className="btn" onClick={() => setConfirmDel(false)}>Keep</button></div>
          ) : <button className="btn danger" onClick={() => setConfirmDel(true)}>Delete</button>)}
        </div>
      </div>
    </div>
  );
}

function entraLinks(d: DiscoveryInfo) {
  const links: { label: string; url: string }[] = [];
  if (d.objectId && d.appId) links.push({ label: "App registration", url: `https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/${d.appId}` });
  if (d.servicePrincipalId && d.appId) links.push({ label: "Enterprise application", url: `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/${d.servicePrincipalId}/appId/${d.appId}` });
  return links;
}

/** Read-only facts from the last tenant scan. */
function DiscoveryPanel({ d }: { d: DiscoveryInfo }) {
  const links = d.provider === "entra" ? entraLinks(d) : [];
  return (
    <fieldset className="panel stack" style={{ margin: 0 }}>
      <legend className="eyebrow">From the tenant · last scanned {d.lastSeen.slice(0, 10)}</legend>
      {d.missing && <div className="callout warn">The last scan of this tenant didn't find this app. If it was deleted on purpose, delete this entry.</div>}
      <dl className="kv">
        {d.appId && <><dt>Application (client) ID</dt><dd>{d.appId}</dd></>}
        {d.objectId && <><dt>App object ID</dt><dd>{d.objectId}</dd></>}
        {d.servicePrincipalId && <><dt>Service principal ID</dt><dd>{d.servicePrincipalId}</dd></>}
        <dt>Sign-in</dt><dd>{d.servicePrincipalId ? (d.enabled ? "Enabled" : "Disabled") : "No enterprise app yet (nobody can sign in)"}</dd>
        {d.thirdParty && <><dt>Registered by</dt><dd>{d.publisher ?? "Another organization"} (third-party app)</dd></>}
        {d.signInAudience && <><dt>Who can sign in</dt><dd>{d.signInAudience}</dd></>}
        {d.ssoMode && <><dt>SSO mode</dt><dd>{d.ssoMode}</dd></>}
        <dt>Owners</dt><dd>{d.owners.length ? d.owners.join(", ") : "None"}</dd>
        {d.identifierUris.length > 0 && <><dt>Identifier URIs</dt><dd>{d.identifierUris.join(" · ")}</dd></>}
        {d.redirectUris.length > 0 && <><dt>Redirect URIs</dt><dd>{d.redirectUris.map((r) => <div key={r.type + r.uri}>{r.uri} <span className="tag">{r.type}</span></div>)}</dd></>}
        {(d.implicit.idToken || d.implicit.accessToken) && <><dt>Implicit grant</dt><dd>{[d.implicit.idToken && "ID tokens", d.implicit.accessToken && "access tokens"].filter(Boolean).join(" and ")} enabled</dd></>}
      </dl>
      {d.credentials.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Credential</th><th>Type</th><th>On</th><th>Expires</th></tr></thead>
            <tbody>
              {d.credentials.map((c) => {
                const left = daysUntil(c.end.slice(0, 10));
                return (
                  <tr key={c.on + c.keyId}>
                    <td>{c.name}{c.thumbprint && <div className="small mono">{c.thumbprint}</div>}</td>
                    <td>{c.kind}{c.usage ? ` (${c.usage})` : ""}</td>
                    <td className="small">{c.on === "application" ? "App registration" : "Enterprise app"}</td>
                    <td style={{ color: left < 0 ? "var(--crit)" : left <= 30 ? "var(--warn)" : undefined }}>{c.end.slice(0, 10)}{Number.isFinite(left) && <div className="small">{left < 0 ? `${-left} days ago` : `in ${left} days`}</div>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {d.permissions.length > 0 && (
        <details>
          <summary>Permissions ({d.permissions.filter((p) => p.status === "granted").length} granted, {d.permissions.filter((p) => p.status === "requested").length} requested)</summary>
          <div className="table-wrap" style={{ marginTop: 8 }}>
            <table>
              <thead><tr><th>API</th><th>Permission</th><th>Type</th><th>Status</th></tr></thead>
              <tbody>
                {d.permissions.map((p, i) => (
                  <tr key={i}><td>{p.resource}</td><td className="mono">{p.value}</td><td>{p.type}</td><td>{p.status}{p.consent === "AllPrincipals" ? " (admin, all users)" : p.consent === "Principal" ? " (one user)" : ""}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
      {links.length > 0 && <div className="row">{links.map((l) => <a key={l.url} className="btn sm" href={l.url} target="_blank" rel="noreferrer">Open {l.label} in Entra ↗</a>)}</div>}
    </fieldset>
  );
}

function AppEditor({ initial, onClose }: { initial: AppIntegration; onClose: () => void }) {
  const { store, toast, tenants, go } = useApp();
  const [a, setA] = useState<AppIntegration>(initial);
  const [confirmDel, setConfirmDel] = useState(false);
  const set = (k: keyof AppIntegration, v: any) => setA({ ...a, [k]: v });
  const ss = (k: keyof AppIntegration["saml"], v: string) => setA({ ...a, saml: { ...a.saml, [k]: v } });
  const so = (k: keyof AppIntegration["oidc"], v: string) => setA({ ...a, oidc: { ...a.oidc, [k]: v } });
  const scim = a.scim ?? emptyScim();
  const sc = (k: keyof NonNullable<AppIntegration["scim"]>, v: string) => setA({ ...a, scim: { ...scim, [k]: v } });
  const profile = a.profile ?? emptyProfile();
  const sp = <K extends keyof AppProfile>(k: K, v: AppProfile[K]) => setA({ ...a, profile: { ...profile, [k]: v } });
  const num = (v: string) => (v.trim() === "" || !Number.isFinite(+v) ? undefined : Math.max(0, Math.round(+v)));
  const [accessSnap] = useAccessSnapshot();
  const isNew = !initial.name;
  const accessApp = accessSnap?.apps.find(
    (x) =>
      (a.discovery?.servicePrincipalId && x.spId.toLowerCase() === a.discovery.servicePrincipalId.toLowerCase()) ||
      (x.appId && [a.discovery?.appId, a.oidc?.clientId].some((v) => v && v.toLowerCase() === x.appId.toLowerCase())) ||
      (!!a.example && !!accessSnap.example && x.name.toLowerCase() === a.name.toLowerCase()),
  );
  const access = accessSnap && accessApp ? accessRow(accessSnap, accessApp, [a]) : null;
  const save = async () => {
    if (!a.name.trim()) throw new Error("Give the integration a name");
    if (!store) throw new Error("Storage isn't connected yet. Wait a moment and try again.");
    await store.put("apps", { ...a, updatedAt: new Date().toISOString() });
    toast("Integration saved");
    onClose();
  };
  const del = async () => {
    if (!store) throw new Error("Storage isn't connected yet. Wait a moment and try again.");
    await store.remove("apps", a.id);
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
            {a.provisioning === "scim" && <button className="btn sm" onClick={() => go("scim", { app: a.id })}>Check a SCIM message for this app</button>}
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
              {PROTOCOLS.filter((p) => p.id !== "scim").map((p) => <option key={p.id} value={p.id} disabled={p.status === "planned"}>{p.name}{p.status === "planned" ? " (coming soon)" : ""}</option>)}
            </select>
          </label>
          <Field id="a-env" label="Environment" value={a.environment} onChange={(v) => set("environment", v)} options={envOpts} />
          <Field id="a-status" label="Status" value={a.status} onChange={(v) => set("status", v)} options={["live", "testing", "planned", "broken"]} />
          <Field id="a-owner" label="Owner" value={a.owner} onChange={(v) => set("owner", v)} placeholder="Team or person accountable" />
          <Field id="a-prov" label="Provisioning" value={a.provisioning} onChange={(v) => set("provisioning", v)} options={["none", "scim", "jit", "manual"]} hint="How accounts get created in the app. SCIM is set here, alongside the sign-in protocol." />
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

        {a.provisioning === "scim" && (
          <fieldset className="panel stack" style={{ margin: 0 }}>
            <legend className="eyebrow">SCIM provisioning</legend>
            <Field id="c-url" label="SCIM endpoint (Tenant URL)" value={scim.endpoint} onChange={(v) => sc("endpoint", v)} placeholder="https://app.example.com/scim/v2" hint="The base URL Entra calls. /Users and /Groups are added to it." />
            <div className="grid-2">
              <Field id="c-exp" label="SCIM token expires" type="date" value={scim.tokenExpires} onChange={(v) => sc("tokenExpires", v)} hint="Record the date only. Never store the token here." />
              <Field id="c-match" label="Matching attribute" value={scim.matchAttribute} onChange={(v) => sc("matchAttribute", v)} options={["userName", "externalId", "emails[type eq \"work\"].value"]} hint="What Entra searches on to find an existing account." />
            </div>
            <Field id="c-src" label="userName comes from" value={scim.userNameSource} onChange={(v) => sc("userNameSource", v)} placeholder="userPrincipalName" hint={a.protocol === "saml" ? `Should be the same source as the SAML NameID (${a.saml.nameIdSource || "not recorded"}).` : "Should be the same value the app matches on at sign-in."} />
          </fieldset>
        )}

        {a.discovery && <DiscoveryPanel d={a.discovery} />}

        {!isNew && (
          <fieldset className="panel stack" style={{ margin: 0 }}>
            <legend className="eyebrow">How access ends{access ? ` · from the scan of ${accessSnap!.collectedAt.slice(0, 10)}` : ""}</legend>
            {access ? (
              <AccessCard row={{ ...access, profile: a.profile }} example={accessSnap!.example} />
            ) : (
              <p className="small muted">
                No access scan matches this app yet. <button className="btn sm" onClick={() => go("access")}>Open How access ends</button> and read the tenant, then run
                Discover so the app is matched by its app ID.
              </p>
            )}
          </fieldset>
        )}

        <fieldset className="panel stack" style={{ margin: 0 }}>
          <legend className="eyebrow">Declared app profile · from the vendor's docs, not Entra</legend>
          <p className="small muted">Entra can't see how long the app keeps people signed in. Record what the vendor documents, so User lookup can estimate how long access lasts after a disable.</p>
          <div className="grid-2">
            <Field id="p-sess" label="App session lasts (minutes)" type="number" value={profile.sessionMinutes?.toString() ?? ""} onChange={(v) => sp("sessionMinutes", num(v))} hint="For example 480 for 8 hours, 20160 for 14 days." />
            <Field id="p-idle" label="Idle timeout (minutes)" type="number" value={profile.idleMinutes?.toString() ?? ""} onChange={(v) => sp("idleMinutes", num(v))} hint="Leave empty if none or unknown." />
            <Field id="p-scim" label="Ends open sessions on SCIM disable" value={profile.endsSessionOnScimDisable} onChange={(v) => sp("endsSessionOnScimDisable", v as AppProfile["endsSessionOnScimDisable"])} options={["unknown", "yes", "no"]} />
            <Field id="p-slo" label="Supports single logout" value={profile.singleLogout} onChange={(v) => sp("singleLogout", v as AppProfile["singleLogout"])} options={["unknown", "yes", "no"]} />
            <Field id="p-cae" label="Honours continuous access evaluation" value={profile.cae} onChange={(v) => sp("cae", v as AppProfile["cae"])} options={["unknown", "yes", "no"]} hint="Only Microsoft's own services do today." />
            <Field id="p-src" label="Source" value={profile.source} onChange={(v) => sp("source", v)} placeholder="Vendor doc URL" />
          </div>
        </fieldset>

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
            <ActionButton className="btn primary" busy="Saving…" onClick={save}>Save integration</ActionButton>
            <button className="btn" onClick={onClose}>Cancel</button>
          </div>
          {!isNew && (confirmDel ? (
            <div className="row"><span className="small">Delete for good?</span><ActionButton className="btn danger" busy="Deleting…" onClick={del}>Yes, delete</ActionButton><button className="btn" onClick={() => setConfirmDel(false)}>Keep</button></div>
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
    setErr(null);
    try {
      const d = JSON.parse(text);
      if (!Array.isArray(d.tenants) || !Array.isArray(d.apps)) throw new Error("Expected { tenants: [...], apps: [...] }.");
      if (!store) throw new Error("storage isn't connected yet. Wait a moment and try again.");
      await Promise.all([...d.tenants.map((t: Tenant) => store.put("tenants", t)), ...d.apps.map((a: AppIntegration) => store.put("apps", a))]);
      toast(`Imported ${d.tenants.length} tenants and ${d.apps.length} apps`);
      onClose();
    } catch (e: any) {
      setErr("Couldn't import: " + e.message);
      throw new Error("Couldn't import. See the message above.");
    }
  };
  return (
    <div className="drawer-bg" onClick={onClose}>
      <div className="drawer" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="Import or export">
        <div className="spread"><h2>Back up or move your inventory</h2><button className="btn ghost" onClick={onClose}>Close</button></div>
        <p className="muted">Copy the JSON to save it in a file or a Git repository. Paste JSON below to import; items with the same ID are replaced.</p>
        <div className="row"><ActionButton className="btn primary" busy="Copying…" onClick={() => copyNow(json)}>Copy inventory JSON</ActionButton><span className="small muted">{tenants.length} tenants, {apps.length} apps</span></div>
        <Field id="imp" label="Import JSON" value={text} onChange={(v) => { setText(v); setErr(null); }} multiline rows={10} error={err} placeholder='{"tenants": [...], "apps": [...]}' />
        <div><ActionButton busy="Importing…" onClick={doImport} disabled={!text.trim()}>Import</ActionButton></div>
      </div>
    </div>
  );
}

function CredentialsExport({ onClose }: { onClose: () => void }) {
  const { tenants, apps } = useApp();
  // Remembered, so reopening the drawer (or reloading) doesn't silently drop the example apps and leave nothing to export.
  const [withExamples, setWithExamples] = usePref("credx-examples", false);
  const [saved, setSaved] = useState<string | null>(null);
  const doc = buildCredentialsExport(tenants, apps, { includeExamples: withExamples });
  const fileName = `f360-credentials-${doc.generatedAt.slice(0, 10)}.json`;
  assertNoSecretMaterial(doc);
  const json = JSON.stringify(doc, null, 2);
  const hasExamples = apps.some((a) => a.example);
  const download = () => {
    const msg = downloadFile(fileName, json, "application/json");
    setSaved(fileName);
    return `${msg} ${doc.counts.total} credentials.`;
  };
  return (
    <div className="drawer-bg" onClick={onClose}>
      <div className="drawer" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="Export expiry report">
        <div className="spread"><h2>Export expiry report for certificates-360</h2><button className="btn ghost" onClick={onClose}>Close</button></div>
        <p className="muted">A list of every federation credential in this inventory and when it expires: app client secrets and certificates, SAML signing certificates and SCIM tokens. It holds names, IDs, certificate thumbprints and dates only. Secret values, private keys and tokens are never included, and the file is checked for them before it is saved.</p>
        <p className="small">Keep the file internal: it lists your apps and which of their credentials expire when. Import it into certificates-360 for one view of every expiry.</p>
        <p className="small">
          <strong>{doc.counts.total}</strong> credentials: {doc.counts.expired} expired, {doc.counts.expiring} expiring within {doc.expiringDays} days, {doc.counts.ok} fine, {doc.counts.unknown} with no expiry recorded.
        </p>
        {hasExamples && (
          <label className="row small"><input type="checkbox" checked={withExamples} onChange={(e) => setWithExamples(e.target.checked)} /> Include the fictional example apps (marked <code>"example": true</code>)</label>
        )}
        <div className="row">
          {/* Never disabled: you can download again as often as you like, and an empty file is still a valid export. */}
          <ActionButton className="btn primary" busy="Building report…" onClick={download}>Download expiry report</ActionButton>
          <ActionButton busy="Copying…" onClick={() => copyNow(json)}>Copy JSON</ActionButton>
        </div>
        {saved && (
          <div className="callout" role="status">
            Saved <span className="mono">{saved}</span> to your browser's downloads folder, normally <span className="mono">C:\Users\&lt;you&gt;\Downloads</span>.
            Press <span className="mono">Ctrl+J</span> in the browser to see it in the downloads list. Download again any time.
          </div>
        )}
        {!doc.counts.total && (
          <div className="callout warn" role="status">
            {hasExamples && !withExamples
              ? <>The file will be empty: the only credentials in this inventory belong to the fictional example apps, and those are left out. Tick <strong>Include the fictional example apps</strong> above to put them in.</>
              : <>The file will be empty: this inventory has no credentials yet. Run Discover against a tenant, or record expiry dates on your integrations.</>}
          </div>
        )}
        <details><summary>Preview</summary><pre className="small mono" style={{ maxHeight: 320, overflow: "auto" }}>{json}</pre></details>
      </div>
    </div>
  );
}

export default function Inventory() {
  const { tenants, apps, params, loading, loadExamples, store, toast, go } = useApp();
  const [tenantFilter, setTenantFilter] = useState(params.tenant ?? "");
  const [q, setQ] = useState("");
  const [editingApp, setEditingApp] = useState<AppIntegration | null>(() => (params.app ? apps.find((a) => a.id === params.app) ?? null : null));
  const [editingTenant, setEditingTenant] = useState<Tenant | null>(() =>
    params.add === "tenant" ? { id: newId(), name: "", platform: "entra", tenantRef: "", domain: "", environment: "prod", notes: "", updatedAt: "" } : null,
  );
  const [io, setIo] = useState(false);
  const [credx, setCredx] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);

  const shown = apps.filter((a) => (!tenantFilter || a.tenantId === tenantFilter) && (!q || (a.name + a.owner + a.saml.entityId + a.oidc.clientId).toLowerCase().includes(q.toLowerCase())));
  const tenantName = (id: string) => tenants.find((t) => t.id === id)?.name ?? "—";
  const examples = [...tenants.filter((t) => t.example), ...apps.filter((a) => a.example)];
  const clearExamples = async () => {
    if (!store) throw new Error("Storage isn't connected yet. Wait a moment and try again.");
    const n = examples.length;
    await Promise.all([...tenants.filter((t) => t.example).map((t) => store.remove("tenants", t.id)), ...apps.filter((a) => a.example).map((a) => store.remove("apps", a.id))]);
    setConfirmClear(false);
    toast(`Removed ${n} example items`);
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Inventory</h1>
          <p>Every tenant and every app integration, with the values you need when something breaks: identifiers, URLs, certificate and secret expiry, and an owner.</p>
        </div>
        <div className="row">
          <button className="btn" onClick={() => go("discover")}>Discover from tenant</button>
          <button className="btn" onClick={() => setIo(true)}>Back up / import</button>
          <button className="btn" onClick={() => setCredx(true)}>Export expiry report</button>
          <button className="btn" onClick={() => setEditingTenant({ id: newId(), name: "", platform: "entra", tenantRef: "", domain: "", environment: "prod", notes: "", updatedAt: "" })}>Add tenant</button>
          <button className="btn primary" disabled={!tenants.length} onClick={() => setEditingApp(blankApp(tenantFilter || tenants[0]?.id || ""))}>Add integration</button>
        </div>
      </div>

      {examples.length > 0 && (
        <div className="callout spread">
          <span>{examples.length} fictional example items are loaded so you can explore. Remove them when you add your own.</span>
          {confirmClear ? (
            <span className="row"><ActionButton className="btn sm danger" busy="Removing…" onClick={clearExamples}>Remove all examples</ActionButton><button className="btn sm" onClick={() => setConfirmClear(false)}>Keep</button></span>
          ) : <button className="btn sm" onClick={() => setConfirmClear(true)}>Remove examples</button>}
        </div>
      )}

      <Section className="panel">
        <div className="panel-head"><h2>Tenants</h2><span className="sub">Click to edit</span></div>
        {loading ? <p className="muted">Loading…</p> : tenants.length === 0 ? (
          <div className="empty">
            <p>No tenants yet. A tenant is one identity provider instance: an Entra tenant, an AWS IAM Identity Center instance, an Okta org.</p>
            <div className="row"><button className="btn primary" onClick={() => go("discover")}>Discover from your tenant</button><ActionButton busy="Loading examples…" onClick={loadExamples}>Load example data</ActionButton></div>
          </div>
        ) : (
          <div className="grid-3">
            {tenants.map((t) => (
              <button key={t.id} className="panel card-btn" style={{ padding: 12, ...(tenantFilter === t.id ? { background: "var(--btn-hover-bg)", borderColor: "var(--accent-strong)" } : {}) }} onClick={() => setEditingTenant(t)}>
                <div className="spread"><strong>{t.name}</strong>{t.example && <span className="example-flag">Example</span>}</div>
                <span className="small muted">{PLATFORM_LABEL[t.platform]} · {ENV_LABEL[t.environment]}</span>
                <span className="small mono" style={{ overflowWrap: "anywhere" }}>{t.tenantRef || "no ID recorded"}</span>
                <span className="small">{apps.filter((a) => a.tenantId === t.id).length} integrations</span>
              </button>
            ))}
          </div>
        )}
      </Section>

      <Section className="stack">
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
                    <td><strong>{a.name}</strong>{a.example && <> <span className="example-flag">Example</span></>}{a.discovery && <> <span className="tag" title={`Last scanned ${a.discovery.lastSeen.slice(0, 10)}`}>{a.discovery.missing ? "Not found in last scan" : "From tenant"}</span></>}</td>
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
      </Section>

      {editingApp && <AppEditor initial={editingApp} onClose={() => setEditingApp(null)} />}
      {editingTenant && <TenantEditor initial={editingTenant} onClose={() => setEditingTenant(null)} />}
      {io && <ImportExport onClose={() => setIo(false)} />}
      {credx && <CredentialsExport onClose={() => setCredx(false)} />}
    </div>
  );
}

import type { AppIntegration, Finding, Severity } from "./types";

export const daysUntil = (iso: string, now = new Date()) =>
  iso ? Math.floor((new Date(iso + (iso.length === 10 ? "T00:00:00Z" : "")).getTime() - now.getTime()) / 86400000) : NaN;

const RANK: Record<Severity, number> = { ok: 0, info: 1, warn: 2, critical: 3 };
export const worst = (fs: Finding[]): Severity =>
  fs.reduce<Severity>((w, f) => (RANK[f.severity] > RANK[w] ? f.severity : w), "ok");

/** Configuration hygiene checks for one inventory entry. */
export function appHealth(app: AppIntegration, now = new Date()): Finding[] {
  const f: Finding[] = [];
  if (app.status === "broken") f.push({ severity: "critical", title: "Marked as broken", detail: app.notes || undefined });
  if (app.protocol === "saml") {
    const s = app.saml;
    if (!s.entityId) f.push({ severity: "warn", title: "Entity ID (Identifier) not recorded" });
    if (!s.acsUrl) f.push({ severity: "warn", title: "ACS (Reply) URL not recorded" });
    else if (s.acsUrl.startsWith("http://")) f.push({ severity: "critical", title: "ACS URL uses plain HTTP", detail: s.acsUrl });
    const d = daysUntil(s.certExpires, now);
    if (!s.certExpires) f.push({ severity: "info", title: "Signing certificate expiry not recorded" });
    else if (d < 0) f.push({ severity: "critical", title: `Signing certificate expired ${-d} days ago`, playbook: "cert-rollover" });
    else if (d <= 30) f.push({ severity: "warn", title: `Signing certificate expires in ${d} days`, playbook: "cert-rollover" });
    else if (d <= 60) f.push({ severity: "info", title: `Signing certificate expires in ${d} days` });
    if (!s.certThumbprint) f.push({ severity: "info", title: "Certificate thumbprint not recorded", detail: "Record it so the SAML decoder can confirm which certificate signed a response." });
  }
  if (app.protocol === "oidc" || app.protocol === "oauth") {
    const o = app.oidc;
    if (!o.clientId) f.push({ severity: "warn", title: "Client ID not recorded" });
    const uris = o.redirectUris.split(/\s+/).filter(Boolean);
    if (o.grantType === "authorization_code" && !uris.length) f.push({ severity: "warn", title: "No redirect URIs recorded" });
    for (const u of uris) {
      if (u.startsWith("http://") && !/localhost|127\.0\.0\.1/.test(u)) f.push({ severity: "critical", title: "Redirect URI uses plain HTTP", detail: u });
      if (u.includes("*")) f.push({ severity: "warn", title: "Wildcard redirect URI", detail: `${u}. Wildcards let attackers capture codes on look-alike paths.` });
      if (app.environment === "prod" && /localhost|127\.0\.0\.1/.test(u)) f.push({ severity: "warn", title: "Localhost redirect URI on a production app", detail: u });
    }
    if (o.grantType === "implicit") f.push({ severity: "warn", title: "Implicit flow", detail: "Move to authorization code with PKCE. Implicit is deprecated in OAuth 2.1." });
    const tenantSaysNoCredential = !!app.discovery && !app.discovery.credentials.some((c) => c.on === "application");
    if (o.clientType === "confidential" && !tenantSaysNoCredential) {
      const d = daysUntil(o.secretExpires, now);
      if (!o.secretExpires) f.push({ severity: "info", title: "Secret/certificate expiry not recorded" });
      else if (d < 0) f.push({ severity: "critical", title: `Client secret expired ${-d} days ago`, playbook: "AADSTS7000222" });
      else if (d <= 30) f.push({ severity: "warn", title: `Client secret expires in ${d} days`, playbook: "AADSTS7000222" });
      else if (d <= 60) f.push({ severity: "info", title: `Client secret expires in ${d} days` });
    }
  }
  if (app.provisioning === "scim") {
    const s = app.scim;
    if (!s?.endpoint) f.push({ severity: "info", title: "SCIM endpoint (Tenant URL) not recorded" });
    else if (s.endpoint.startsWith("http://")) f.push({ severity: "critical", title: "SCIM endpoint uses plain HTTP", detail: `${s.endpoint}. User data and the bearer token would travel unencrypted.` });
    const d = daysUntil(s?.tokenExpires ?? "", now);
    if (!s?.tokenExpires) f.push({ severity: "info", title: "SCIM token expiry not recorded", detail: "When the token expires, provisioning stops without any sign-in error: joiners get no account and leavers keep theirs." });
    else if (d < 0) f.push({ severity: "critical", title: `SCIM token expired ${-d} days ago`, detail: "Provisioning has stopped. New users have no account in the app and leavers are not being disabled.", playbook: "scim-401" });
    else if (d <= 30) f.push({ severity: "warn", title: `SCIM token expires in ${d} days`, playbook: "scim-401" });
    else if (d <= 60) f.push({ severity: "info", title: `SCIM token expires in ${d} days` });
    if (s && app.protocol === "saml" && s.userNameSource && app.saml.nameIdSource) {
      const norm = (v: string) => v.toLowerCase().replace(/^user\./, "").trim();
      if (norm(s.userNameSource) !== norm(app.saml.nameIdSource)) {
        f.push({
          severity: "warn",
          title: "Sign-in and provisioning use different source attributes",
          detail: `SAML NameID comes from ${app.saml.nameIdSource}; SCIM userName comes from ${s.userNameSource}. Users whose two values differ pass Entra sign-in and are “not found” by the app.`,
          playbook: "scim-identifier-mismatch",
        });
      }
    }
  }
  if (app.provisioning === "jit") f.push({ severity: "info", title: "Accounts are created at first sign-in (JIT)", detail: "Nothing removes the account when someone leaves. Add SCIM or a manual leaver step.", playbook: "scim-leaver" });
  if (app.discovery) {
    const d = app.discovery;
    if (d.missing) f.push({ severity: "warn", title: "Not found in the last tenant scan", detail: "It may have been deleted or renamed in the identity provider. Check, then delete this entry if it's gone." });
    if (!d.enabled && d.servicePrincipalId) f.push({ severity: "info", title: "Sign-in is disabled for this app in the tenant" });
    for (const c of d.credentials) {
      const left = daysUntil(c.end.slice(0, 10), now);
      if (left < 0 && !(app.protocol === "saml" && c.thumbprint && c.thumbprint === app.saml.certThumbprint))
        f.push({ severity: "info", title: `${c.kind === "secret" ? "Secret" : "Certificate"} “${c.name}” expired ${-left} days ago and is still attached`, detail: "Remove credentials you no longer use so nobody can mistake them for the live one." });
    }
  }
  if (!app.owner) f.push({ severity: "info", title: "No owner recorded", detail: "Every integration needs an accountable owner for access reviews and incidents." });
  return f;
}

/** The credential on this integration that expires soonest. */
export function nextExpiry(app: AppIntegration): { date: string; what: string } | null {
  const all: { date: string; what: string }[] = [];
  if (app.protocol === "saml" && app.saml.certExpires) all.push({ date: app.saml.certExpires, what: "Signing certificate" });
  if ((app.protocol === "oidc" || app.protocol === "oauth") && app.oidc.clientType === "confidential" && app.oidc.secretExpires)
    all.push({ date: app.oidc.secretExpires, what: "Client secret" });
  if (app.provisioning === "scim" && app.scim?.tokenExpires) all.push({ date: app.scim.tokenExpires, what: "SCIM token" });
  return all.sort((a, b) => a.date.localeCompare(b.date))[0] ?? null;
}

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
    if (o.clientType === "confidential") {
      const d = daysUntil(o.secretExpires, now);
      if (!o.secretExpires) f.push({ severity: "info", title: "Secret/certificate expiry not recorded" });
      else if (d < 0) f.push({ severity: "critical", title: `Client secret expired ${-d} days ago`, playbook: "AADSTS7000222" });
      else if (d <= 30) f.push({ severity: "warn", title: `Client secret expires in ${d} days`, playbook: "AADSTS7000222" });
      else if (d <= 60) f.push({ severity: "info", title: `Client secret expires in ${d} days` });
    }
  }
  if (!app.owner) f.push({ severity: "info", title: "No owner recorded", detail: "Every integration needs an accountable owner for access reviews and incidents." });
  return f;
}

export function nextExpiry(app: AppIntegration): { date: string; what: string } | null {
  if (app.protocol === "saml" && app.saml.certExpires) return { date: app.saml.certExpires, what: "Signing certificate" };
  if ((app.protocol === "oidc" || app.protocol === "oauth") && app.oidc.clientType === "confidential" && app.oidc.secretExpires)
    return { date: app.oidc.secretExpires, what: "Client secret" };
  return null;
}

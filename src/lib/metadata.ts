import { parseCertificate, type CertInfo } from "./x509";
import type { Finding } from "./types";

const MD = "urn:oasis:names:tc:SAML:2.0:metadata";
const DS = "http://www.w3.org/2000/09/xmldsig#";

export interface Endpoint {
  kind: string;
  binding: string;
  location: string;
  index?: string;
}

export interface SamlMetadata {
  entityId: string;
  roles: ("IdP" | "SP")[];
  endpoints: Endpoint[];
  nameIdFormats: string[];
  certs: { use: string; role: string; cert?: CertInfo; error?: string }[];
  wantAuthnRequestsSigned?: boolean;
  wantAssertionsSigned?: boolean;
  validUntil?: string;
}

const short = (b: string) => b.split(":").pop() ?? b;

export async function parseSamlMetadata(xml: string): Promise<SamlMetadata> {
  const doc = new DOMParser().parseFromString(xml.trim(), "application/xml");
  if (doc.getElementsByTagName("parsererror")[0]) throw new Error("The metadata isn't valid XML. Paste the whole file.");
  const ed = doc.getElementsByTagNameNS(MD, "EntityDescriptor")[0];
  if (!ed) throw new Error("No <EntityDescriptor> found. This doesn't look like SAML metadata.");
  const out: SamlMetadata = {
    entityId: ed.getAttribute("entityID") ?? "",
    roles: [],
    endpoints: [],
    nameIdFormats: [],
    certs: [],
    validUntil: ed.getAttribute("validUntil") ?? undefined,
  };
  const roleEls: [Element, "IdP" | "SP"][] = [
    ...Array.from(ed.getElementsByTagNameNS(MD, "IDPSSODescriptor")).map((e) => [e, "IdP"] as [Element, "IdP"]),
    ...Array.from(ed.getElementsByTagNameNS(MD, "SPSSODescriptor")).map((e) => [e, "SP"] as [Element, "SP"]),
  ];
  for (const [el, role] of roleEls) {
    out.roles.push(role);
    if (role === "IdP") out.wantAuthnRequestsSigned = el.getAttribute("WantAuthnRequestsSigned") === "true";
    if (role === "SP") out.wantAssertionsSigned = el.getAttribute("WantAssertionsSigned") === "true";
    for (const child of Array.from(el.children)) {
      const n = child.localName;
      if (["SingleSignOnService", "SingleLogoutService", "AssertionConsumerService", "ArtifactResolutionService"].includes(n))
        out.endpoints.push({
          kind: n,
          binding: short(child.getAttribute("Binding") ?? ""),
          location: child.getAttribute("Location") ?? "",
          index: child.getAttribute("index") ?? undefined,
        });
      if (n === "NameIDFormat") out.nameIdFormats.push(child.textContent?.trim() ?? "");
      if (n === "KeyDescriptor") {
        const b64 = child.getElementsByTagNameNS(DS, "X509Certificate")[0]?.textContent ?? "";
        const entry: SamlMetadata["certs"][number] = { use: child.getAttribute("use") ?? "signing+encryption", role };
        try {
          entry.cert = await parseCertificate(b64);
        } catch {
          entry.error = "Couldn't parse this certificate.";
        }
        out.certs.push(entry);
      }
    }
  }
  return out;
}

export function checkSamlMetadata(m: SamlMetadata): Finding[] {
  const f: Finding[] = [];
  if (!m.entityId) f.push({ severity: "critical", title: "entityID is missing" });
  else f.push({ severity: "ok", title: `Entity ID: ${m.entityId}`, detail: m.roles.includes("IdP") ? "This is the Issuer value the app (SP) must trust." : "This is the Identifier (Entity ID) to enter at the identity provider." });
  if (m.validUntil && new Date(m.validUntil) < new Date()) f.push({ severity: "critical", title: "Metadata validUntil has passed", detail: m.validUntil });
  for (const e of m.endpoints) {
    if (e.location.startsWith("http://") && !/localhost|127\.0\.0\.1/.test(e.location))
      f.push({ severity: "critical", title: `${e.kind} uses plain HTTP`, detail: e.location });
  }
  if (m.roles.includes("IdP") && !m.endpoints.some((e) => e.kind === "SingleSignOnService"))
    f.push({ severity: "critical", title: "No SingleSignOnService endpoint" });
  if (m.roles.includes("SP") && !m.endpoints.some((e) => e.kind === "AssertionConsumerService"))
    f.push({ severity: "critical", title: "No AssertionConsumerService endpoint" });
  const signing = m.certs.filter((c) => c.use !== "encryption" && c.cert);
  if (!signing.length && m.roles.includes("IdP")) f.push({ severity: "critical", title: "No signing certificate in the IdP metadata" });
  for (const c of m.certs) {
    if (!c.cert) continue;
    const d = c.cert.daysLeft;
    const label = `${c.role} ${c.use} certificate (${c.cert.subject})`;
    if (d < 0) f.push({ severity: "critical", title: `${label} expired ${-d} days ago`, playbook: "cert-rollover" });
    else if (d < 30) f.push({ severity: "warn", title: `${label} expires in ${d} days`, detail: c.cert.notAfter.toDateString(), playbook: "cert-rollover" });
    else if (d < 90) f.push({ severity: "info", title: `${label} expires in ${d} days`, detail: c.cert.notAfter.toDateString() });
    else f.push({ severity: "ok", title: `${label} valid for ${d} more days`, detail: c.cert.notAfter.toDateString() });
  }
  if (signing.length > 1)
    f.push({ severity: "info", title: `${signing.length} signing certificates published`, detail: "Usually means a certificate rollover is in progress. Apps that only accept one certificate need the new one uploaded before the switch." });
  return f;
}

export interface OidcDiscovery {
  [k: string]: any;
}

export function checkDiscovery(d: OidcDiscovery, sourceUrl?: string): Finding[] {
  const f: Finding[] = [];
  const req = ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"];
  for (const k of req) if (!d[k]) f.push({ severity: "critical", title: `Missing ${k}` });
  if (d.issuer) {
    f.push({ severity: "ok", title: `Issuer: ${d.issuer}`, detail: "Tokens' iss claim must equal this exactly." });
    if (/\{tenantid\}/i.test(d.issuer))
      f.push({ severity: "info", title: "Multi-tenant (common/organizations) discovery", detail: "The issuer contains {tenantid}. Your app must substitute the token's tid and check it against allowed tenants." });
    if (sourceUrl && !/\{tenantid\}/i.test(d.issuer)) {
      const base = sourceUrl.replace(/\/\.well-known\/openid-configuration.*$/, "");
      if (base.replace(/\/$/, "") !== String(d.issuer).replace(/\/$/, ""))
        f.push({ severity: "warn", title: "Issuer differs from the discovery URL", detail: `URL base ${base}, issuer ${d.issuer}. The OIDC spec requires them to match.` });
    }
  }
  for (const k of ["authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "end_session_endpoint"]) {
    if (d[k] && !String(d[k]).startsWith("https://")) f.push({ severity: "critical", title: `${k} isn't HTTPS`, detail: d[k] });
  }
  const pkce: string[] = d.code_challenge_methods_supported ?? [];
  if (pkce.includes("S256")) f.push({ severity: "ok", title: "PKCE (S256) supported" });
  else if (pkce.length) f.push({ severity: "warn", title: "PKCE S256 not listed", detail: pkce.join(", ") });
  else f.push({ severity: "info", title: "code_challenge_methods_supported not published", detail: "Entra supports PKCE S256 even though its discovery document doesn't list it." });
  const rt: string[] = d.response_types_supported ?? [];
  if (rt.length) f.push({ severity: "info", title: "Response types", detail: rt.join(", ") });
  const algs: string[] = d.id_token_signing_alg_values_supported ?? [];
  if (algs.includes("none")) f.push({ severity: "critical", title: "Accepts unsigned ID tokens (alg none)" });
  else if (algs.length) f.push({ severity: "info", title: "ID token signing algorithms", detail: algs.join(", ") });
  return f;
}

export async function jwksSummary(jwks: any) {
  const keys: any[] = jwks?.keys ?? [];
  return Promise.all(
    keys.map(async (k) => {
      let cert: CertInfo | undefined;
      if (k.x5c?.[0]) {
        try {
          cert = await parseCertificate(k.x5c[0]);
        } catch {
          /* ignore */
        }
      }
      return { kid: k.kid as string, kty: k.kty as string, alg: k.alg as string | undefined, use: k.use as string | undefined, cert };
    }),
  );
}

/** Well-known URLs for common identity providers. */
export function wellKnownUrls(platform: string, ref: string, appId?: string) {
  const t = ref.trim() || "{tenant}";
  if (platform === "entra")
    return [
      { label: "OIDC discovery (v2.0)", url: `https://login.microsoftonline.com/${t}/v2.0/.well-known/openid-configuration` },
      { label: "JWKS signing keys (v2.0)", url: `https://login.microsoftonline.com/${t}/discovery/v2.0/keys${appId ? `?appid=${appId}` : ""}` },
      { label: "SAML federation metadata (tenant)", url: `https://login.microsoftonline.com/${t}/federationmetadata/2007-06/federationmetadata.xml` },
      ...(appId ? [{ label: "SAML federation metadata (this app)", url: `https://login.microsoftonline.com/${t}/federationmetadata/2007-06/federationmetadata.xml?appid=${appId}` }] : []),
      { label: "OIDC discovery (v1.0)", url: `https://login.microsoftonline.com/${t}/.well-known/openid-configuration` },
    ];
  if (platform === "okta")
    return [
      { label: "OIDC discovery (org)", url: `https://${t.replace(/^https?:\/\//, "")}/.well-known/openid-configuration` },
      { label: "OAuth discovery (default auth server)", url: `https://${t.replace(/^https?:\/\//, "")}/oauth2/default/.well-known/openid-configuration` },
    ];
  if (platform === "ping")
    return [{ label: "OIDC discovery", url: `${t.replace(/\/$/, "")}/.well-known/openid-configuration` }];
  if (platform === "adfs")
    return [
      { label: "OIDC discovery", url: `https://${t}/adfs/.well-known/openid-configuration` },
      { label: "Federation metadata", url: `https://${t}/FederationMetadata/2007-06/FederationMetadata.xml` },
    ];
  return [];
}

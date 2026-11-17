/**
 * Federation credentials export (the expiry report) from the Federation 360 inventory.
 *
 * The contract (types, status rule, item IDs, Entra rotation links, schema, secret guard) lives in
 * the shared package @sectechtalk/f360-collector, which certificates-360 also uses to build the same document
 * straight from a scan. This module adds only what is Federation 360's own: items a person recorded
 * (SCIM tokens, hand-entered expiries) and the Federation 360 app ID and environment on every item.
 * Schema: node_modules/@sectechtalk/f360-collector/schema/f360-federation-credentials.v1.schema.json
 */
import {
  credentialStatus, discoveredCredentialType, entraManageUrl, finishCredentialsExport, recordedCredentialId, scannedCredentialId,
  type CredentialItem, type CredentialsExport, type CredentialType,
} from "@sectechtalk/f360-collector";
import type { AppIntegration, Tenant } from "./types";

export {
  CREDENTIALS_FORMAT, CREDENTIALS_VERSION, EXPIRING_DAYS, FORBIDDEN_KEYS, assertNoSecretMaterial,
  type CredentialItem, type CredentialsExport, type CredentialStatus, type CredentialType,
} from "@sectechtalk/f360-collector";

const nn = (s?: string | null) => (s && s.trim() ? s : null);

function manageUrl(type: CredentialType, app: AppIntegration, tenant?: Tenant): string | null {
  if (tenant?.platform !== "entra") return null;
  const d = app.discovery;
  if (type === "saml-signing-certificate" || type === "scim-token") return entraManageUrl(type, { appId: d?.appId, servicePrincipalId: d?.servicePrincipalId });
  return entraManageUrl(type, { appId: d?.appId || app.oidc.clientId || "" });
}

export interface BuildOptions {
  now?: Date;
  includeExamples?: boolean;
  generatorVersion?: string;
}

/** Every federation credential Federation 360 knows about, one item per credential. */
export function buildCredentialsExport(tenants: Tenant[], apps: AppIntegration[], opts: BuildOptions = {}): CredentialsExport {
  const now = opts.now ?? new Date();
  const items: CredentialItem[] = [];
  const tenantById = new Map(tenants.map((t) => [t.id, t]));

  for (const app of apps) {
    const tenant = tenantById.get(app.tenantId);
    const example = !!(app.example || tenant?.example);
    if (example && !opts.includeExamples) continue;
    const d = app.discovery;
    const tenantRef = nn(tenant?.tenantRef);

    const base = (type: CredentialType, name: string, expiresAt: string | null, extra: Partial<CredentialItem>, source: CredentialItem["source"]) => {
      const s = credentialStatus(expiresAt, now);
      const item: CredentialItem = {
        id: "",
        type,
        name,
        status: s.status,
        daysLeft: s.daysLeft,
        expiresAt,
        createdAt: null,
        thumbprint: null,
        keyId: null,
        source,
        observedAt: (source === "tenant-scan" ? d?.lastSeen : app.updatedAt) || app.updatedAt || now.toISOString(),
        app: {
          f360Id: app.id,
          name: app.name,
          protocol: app.protocol,
          environment: app.environment,
          owner: nn(app.owner),
          appId: nn(d?.appId) ?? (app.protocol !== "saml" ? nn(app.oidc.clientId) : null),
          objectId: nn(d?.objectId),
          servicePrincipalId: nn(d?.servicePrincipalId),
          missingFromTenant: !!d?.missing,
        },
        tenant: { id: tenantRef, name: tenant?.name ?? "(unknown tenant)", domain: nn(tenant?.domain), platform: tenant?.platform ?? null },
        manageUrl: manageUrl(type, app, tenant),
        ...extra,
      };
      if (example) item.example = true;
      items.push(item);
    };

    // 1. What the tenant scan read. Authoritative, one item per credential.
    const scanned = d?.credentials ?? [];
    for (const c of scanned) {
      const type = discoveredCredentialType(c);
      const appKey = d?.appId || app.id;
      base(type, c.name, nn(c.end), {
        id: scannedCredentialId(d!.provider, tenantRef ?? app.tenantId, appKey, c),
        createdAt: nn(c.start),
        thumbprint: nn(c.thumbprint),
        keyId: nn(c.keyId),
      }, "tenant-scan");
    }

    // 2. What a person recorded, only where the scan has nothing of that kind.
    const rec = (type: CredentialType, name: string, date: string) =>
      base(type, name, nn(date), { id: recordedCredentialId(app.id, type), thumbprint: type === "saml-signing-certificate" ? nn(app.saml.certThumbprint) : null }, "recorded");

    if (app.protocol === "saml" && !scanned.some((c) => c.on === "servicePrincipal") && (app.saml.certExpires || app.saml.certThumbprint))
      rec("saml-signing-certificate", "SAML signing certificate", app.saml.certExpires);

    const isClient = app.protocol === "oidc" || app.protocol === "oauth";
    if (isClient && app.oidc.clientType === "confidential" && !d && app.oidc.secretExpires)
      rec("app-credential", "Client secret or certificate", app.oidc.secretExpires);

    // Graph can't read SCIM tokens (synchronization/secrets is write-only), so these are always recorded.
    if (app.provisioning === "scim" && app.scim) rec("scim-token", "SCIM secret token", app.scim.tokenExpires);
  }

  // "f-360" is a fixed value in the v1 format (generator.name), which certificates-360 reads. Keep it.
  return finishCredentialsExport(items, { name: "f-360", version: opts.generatorVersion ?? "0.1.0" }, now);
}

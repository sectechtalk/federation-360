/**
 * Merge a discovery snapshot into the inventory.
 *
 * Rules (the same for every provider):
 * - The tenant is matched on its directory ID; a new tenant entry is created if there is none.
 * - An app is matched by its discovery key, then by client ID, then by SAML entity ID, so
 *   entries you typed by hand (or imported from the lab kit) are adopted instead of duplicated.
 * - The identity provider wins for technical facts: name, protocol, identifiers, URLs,
 *   certificates, secrets, owners. You win for status, environment, provisioning, SCIM and notes.
 * - Nothing is deleted. An app a previous scan found that this scan didn't is flagged "missing".
 */
import {
  emptyOidc, emptySaml, newId,
  type AppIntegration, type OidcSettings, type SamlSettings, type Tenant,
} from "../types";
import type { DiscoveredApp, DiscoverySnapshot } from "@sectechtalk/f360-collector";

export interface AppChange {
  before: AppIntegration;
  after: AppIntegration;
  changes: string[];
  /** Matched an entry that wasn't discovered before (hand-entered or lab import). */
  adopted: boolean;
}

export interface MergePlan {
  tenant: Tenant;
  tenantIsNew: boolean;
  creates: AppIntegration[];
  updates: AppChange[];
  unchanged: AppIntegration[];
  missing: AppIntegration[];
}

const lc = (s?: string) => (s ?? "").trim().toLowerCase();

function fillDefined<T extends object>(base: T, patch: Partial<T>): T {
  const out = { ...base };
  for (const [k, v] of Object.entries(patch)) if (v !== undefined) (out as any)[k] = v;
  return out;
}

const LABELS: Record<string, string> = {
  name: "Name", protocol: "Protocol", owner: "Owner",
  "saml.entityId": "Entity ID", "saml.acsUrl": "ACS URL", "saml.signOnUrl": "Sign-on URL", "saml.idpEntityId": "IdP entity ID",
  "saml.certThumbprint": "Signing cert thumbprint", "saml.certExpires": "Signing cert expiry",
  "oidc.clientId": "Client ID", "oidc.redirectUris": "Redirect URIs", "oidc.grantType": "Grant type", "oidc.clientType": "Client type",
  "oidc.scopes": "Scopes", "oidc.audience": "Audience", "oidc.issuer": "Issuer", "oidc.secretExpires": "Secret/cert expiry",
};

function diff(a: AppIntegration, b: AppIntegration): string[] {
  const out: string[] = [];
  for (const k of ["name", "protocol", "owner"] as const) if (a[k] !== b[k]) out.push(LABELS[k]);
  const sec = b.protocol === "saml" ? "saml" : "oidc";
  const A = a[sec] as unknown as Record<string, string>;
  const B = b[sec] as unknown as Record<string, string>;
  for (const k of Object.keys(B)) if ((A?.[k] ?? "") !== (B[k] ?? "") && LABELS[`${sec}.${k}`]) out.push(LABELS[`${sec}.${k}`]);
  const da = a.discovery, db = b.discovery;
  if (!da) out.push("Linked to the tenant");
  else {
    if (JSON.stringify(da.credentials) !== JSON.stringify(db?.credentials)) out.push("Credentials");
    if (JSON.stringify(da.permissions) !== JSON.stringify(db?.permissions)) out.push("Permissions");
    if (da.missing && !db?.missing) out.push("Found again");
    if (da.enabled !== db?.enabled) out.push(db?.enabled ? "Enabled" : "Disabled");
  }
  return out;
}

export function planMerge(snap: DiscoverySnapshot, tenants: Tenant[], apps: AppIntegration[], now = new Date(), opts: { example?: boolean } = {}): MergePlan {
  const stamp = now.toISOString();
  // Fictional example entries never absorb a real scan (and vice versa for the sample tenant).
  tenants = tenants.filter((t) => !!t.example === !!opts.example);
  apps = apps.filter((a) => !!a.example === !!opts.example);
  const existingTenant = tenants.find((t) => t.platform === snap.provider && lc(t.tenantRef) === lc(snap.tenant.ref));
  const tenant: Tenant = existingTenant
    ? { ...existingTenant, domain: existingTenant.domain || snap.tenant.domain }
    : {
        id: `${snap.provider}-${lc(snap.tenant.ref)}`,
        name: snap.tenant.name,
        platform: snap.provider,
        tenantRef: snap.tenant.ref,
        domain: snap.tenant.domain,
        environment: "test",
        notes: "Created by live tenant discovery. Set the environment to match how this tenant is used.",
        updatedAt: stamp,
        ...(opts.example ? { example: true } : {}),
      };

  const inTenant = apps.filter((a) => a.tenantId === tenant.id);
  const claimed = new Set<string>();
  const creates: AppIntegration[] = [];
  const updates: AppChange[] = [];
  const unchanged: AppIntegration[] = [];

  const findMatch = (d: DiscoveredApp): AppIntegration | undefined => {
    const free = (a: AppIntegration) => !claimed.has(a.id);
    const key = d.discovery.externalId;
    return (
      apps.find((a) => free(a) && a.discovery?.externalId === key) ??
      inTenant.find((a) => free(a) && !a.discovery && d.discovery.appId && lc(a.oidc?.clientId) === lc(d.discovery.appId)) ??
      inTenant.find((a) => free(a) && !a.discovery && d.protocol === "saml" && a.saml?.entityId && d.discovery.identifierUris.map(lc).includes(lc(a.saml.entityId)))
    );
  };

  for (const d of snap.apps) {
    const match = findMatch(d);
    if (match) {
      claimed.add(match.id);
      const after: AppIntegration = {
        ...match,
        name: d.name,
        protocol: d.protocol,
        owner: d.owner || match.owner,
        saml: fillDefined<SamlSettings>(match.saml ?? emptySaml(), d.saml),
        oidc: fillDefined<OidcSettings>(match.oidc ?? emptyOidc(), d.oidc),
        discovery: { ...d.discovery, missing: undefined },
      };
      const changes = diff(match, after);
      if (changes.length) updates.push({ before: match, after: { ...after, updatedAt: stamp }, changes, adopted: !match.discovery });
      else unchanged.push(match);
    } else {
      creates.push({
        id: newId(),
        tenantId: tenant.id,
        name: d.name,
        protocol: d.protocol,
        environment: tenant.environment,
        owner: d.owner,
        status: d.discovery.enabled ? "live" : "planned",
        provisioning: "none",
        saml: fillDefined(emptySaml(), d.saml),
        oidc: fillDefined(emptyOidc(), d.oidc),
        discovery: d.discovery,
        notes: `${d.kind}. Discovered in ${snap.tenant.name} on ${snap.collectedAt.slice(0, 10)}.`,
        updatedAt: stamp,
        ...(opts.example ? { example: true } : {}),
      });
    }
  }

  const missing = apps
    .filter((a) => a.tenantId === tenant.id && a.discovery?.provider === snap.provider && !claimed.has(a.id) && !a.discovery.missing)
    .map((a) => ({ ...a, discovery: { ...a.discovery!, missing: true }, updatedAt: stamp }));

  return { tenant, tenantIsNew: !existingTenant, creates, updates, unchanged, missing };
}

export interface Writer {
  put(col: "tenants" | "apps", row: { id: string } & Record<string, any>): Promise<void>;
}

/** Writes the plan. Returns how many rows were written. */
export async function applyMerge(store: Writer, plan: MergePlan, opts: { flagMissing?: boolean } = {}): Promise<number> {
  const rows: Promise<void>[] = [store.put("tenants", plan.tenant as any)];
  for (const a of plan.creates) rows.push(store.put("apps", a as any));
  for (const u of plan.updates) rows.push(store.put("apps", u.after as any));
  if (opts.flagMissing !== false) for (const m of plan.missing) rows.push(store.put("apps", m as any));
  await Promise.all(rows);
  return rows.length;
}

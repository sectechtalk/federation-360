// Reads an access snapshot from Microsoft Graph with a delegated token (browser sign-in on the "How access ends"
// page). GET requests only. access/Export-F360Access.ps1 makes the same file from PowerShell.
//
// Delegated permissions, all read-only:
//   Application.Read.All       enterprise apps (service principals)
//   Policy.Read.All            token lifetime policies and Conditional Access policies
//   Synchronization.Read.All   each enterprise app's provisioning (SCIM) job: schedule, last cycle, quarantine
// Conditional Access needs Entra ID P1. On a Free tenant that read fails, and the page shows Entra's defaults instead.
import { graphGetter } from "./postureCollect";
import { ACCESS_FORMAT, parseCaPolicy, parseSyncJob, parseTokenPolicy, type AccessApp, type AccessSnapshot, type CaPolicy, type TokenPolicy } from "./access";

export { graphGetter };

export const ACCESS_SCOPES = ["Application.Read.All", "Policy.Read.All", "Synchronization.Read.All"];

/** Per-app provisioning reads are one call each; above this the scan stops and says how many it left out. */
export const APP_LIMIT = 500;

const MS_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a";

type Get = (path: string) => Promise<any>;

async function all(get: Get, path: string, max = Infinity): Promise<any[]> {
  const out: any[] = [];
  let next: string | undefined = path;
  while (next && out.length < max) {
    const j = await get(next);
    out.push(...(j.value ?? []));
    next = j["@odata.nextLink"];
  }
  return out;
}

export async function collectAccess(get: Get, tenantId: string, progress: (msg: string) => void = () => {}): Promise<AccessSnapshot> {
  const warnings: string[] = [];
  progress("Reading the organisation…");
  // The organisation read needs User.Read or higher, which the three scopes above don't include. It only supplies the
  // tenant's name and domain, so a 403 here is noted and the scan carries on.
  let org: any = {};
  try {
    org = (await get("organization?$select=id,displayName,verifiedDomains")).value?.[0] ?? {};
  } catch {
    org = {};
  }

  progress("Reading token lifetime policies…");
  let tokenPolicies: TokenPolicy[] | null = null;
  try {
    tokenPolicies = [];
    for (const p of await all(get, "policies/tokenLifetimePolicies")) {
      let appliesTo: string[] = [];
      try {
        appliesTo = (await all(get, `policies/tokenLifetimePolicies/${p.id}/appliesTo?$select=id,appId`)).flatMap((x) => [x.id, x.appId].filter(Boolean));
      } catch (e: any) {
        warnings.push(`Couldn't read which apps use the token lifetime policy "${p.displayName}" (${e.message}).`);
      }
      tokenPolicies.push(parseTokenPolicy(p, appliesTo));
    }
  } catch (e: any) {
    tokenPolicies = null;
    warnings.push(`Token lifetime policies couldn't be read (${e.message}). It needs Policy.Read.All.`);
  }

  progress("Reading Conditional Access policies…");
  let caPolicies: CaPolicy[] | null = null;
  let caNote: string | undefined;
  try {
    caPolicies = (await all(get, "identity/conditionalAccess/policies")).map(parseCaPolicy);
  } catch (e: any) {
    caNote =
      e.status === 403
        ? `Conditional Access couldn't be read (${e.message}). It needs Entra ID P1 and Policy.Read.All. Entra's defaults are shown instead.`
        : `Conditional Access couldn't be read (${e.message}).`;
  }

  progress("Reading enterprise apps…");
  let rawSps: any[];
  try {
    rawSps = await all(get, "servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,preferredSingleSignOnMode,tags,servicePrincipalType&$top=999");
  } catch (e: any) {
    throw new Error(
      e.status === 403
        ? `Enterprise apps couldn't be read (${e.message}). Consent Application.Read.All for F360-Discovery, then sign in again.`
        : `Enterprise apps couldn't be read (${e.message}).`,
    );
  }
  const sps = rawSps
    .filter((s) => s.servicePrincipalType === "Application" && (s.appOwnerOrganizationId ?? "").toLowerCase() !== MS_TENANT)
    .filter((s) => (s.tags ?? []).includes("WindowsAzureActiveDirectoryIntegratedApp") || !!s.preferredSingleSignOnMode);
  if (sps.length > APP_LIMIT) warnings.push(`This scan reads provisioning for the first ${APP_LIMIT} apps only. Run Export-F360Access.ps1 for all ${sps.length}.`);

  const apps: AccessApp[] = [];
  let syncDenied = 0;
  for (const [i, s] of sps.slice(0, APP_LIMIT).entries()) {
    if (i % 10 === 0) progress(`Reading provisioning jobs: ${i} of ${Math.min(sps.length, APP_LIMIT)} apps…`);
    let syncJobs: AccessApp["syncJobs"] = [];
    try {
      syncJobs = (await all(get, `servicePrincipals/${s.id}/synchronization/jobs`)).map(parseSyncJob);
    } catch (e: any) {
      if (e.status === 403 || e.status === 401) {
        syncDenied++;
        syncJobs = null;
      } else if (e.status !== 404 && e.status !== 400) throw e;
    }
    apps.push({ spId: s.id, appId: s.appId, name: s.displayName ?? s.appId, ssoMode: s.preferredSingleSignOnMode ?? "", syncJobs });
  }
  if (syncDenied)
    warnings.push(`Provisioning jobs couldn't be read for ${syncDenied} app${syncDenied === 1 ? "" : "s"} (403). Make sure Synchronization.Read.All was consented, and sign in as Global Reader, Application Administrator or higher.`);

  const domain = org.verifiedDomains?.find((d: any) => d.isDefault)?.name ?? org.verifiedDomains?.[0]?.name ?? "";
  return {
    format: ACCESS_FORMAT,
    version: 1,
    collectedAt: new Date().toISOString(),
    collector: "browser",
    tenant: { id: org.id ?? tenantId, name: org.displayName ?? "", domain },
    tokenPolicies,
    caPolicies,
    caNote,
    apps,
    warnings,
  };
}

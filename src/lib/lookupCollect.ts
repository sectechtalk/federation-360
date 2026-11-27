// Reads one person's access from Microsoft Graph with a delegated token (browser sign-in on User lookup). GET only.
// Export-F360UserAccess.ps1 makes the same file from PowerShell.
//
// Delegated permissions, read-only: Directory.Read.All (the account, app assignments direct and through groups,
// consent grants, devices) and AuditLog.Read.All (signInActivity, which also needs Entra ID P1; skipped without it).
import { USER_ACCESS_FORMAT, type UserAccessSnapshot, type UserAssignment, type UserDevice, type UserGrant } from "./lookup";

export const LOOKUP_SCOPES = ["Directory.Read.All", "AuditLog.Read.All"];
const GROUP_LIMIT = 200;

type Get = (path: string) => Promise<any>;

async function all(get: Get, path: string, max = 5000): Promise<any[]> {
  const out: any[] = [];
  let next: string | undefined = path;
  while (next && out.length < max) {
    const j = await get(next);
    out.push(...(j.value ?? []));
    next = j["@odata.nextLink"];
  }
  return out;
}

export async function collectUserAccess(get: Get, who: string, progress: (m: string) => void = () => {}): Promise<UserAccessSnapshot> {
  const warnings: string[] = [];
  const id = encodeURIComponent(who.trim());
  const base = "id,displayName,userPrincipalName,accountEnabled,signInSessionsValidFromDateTime,lastPasswordChangeDateTime";
  progress(`Reading ${who}…`);
  let u: any;
  try {
    u = await get(`users/${id}?$select=${base},signInActivity`);
  } catch (e: any) {
    if (e.status === 404) throw new Error(`No user ${who} in this tenant. Use their full sign-in name (UPN) or object ID.`);
    if (e.status !== 403 && e.status !== 400) throw e;
    warnings.push("Last sign-in times (signInActivity) weren't read: they need Entra ID P1 and AuditLog.Read.All. Activity fills them in from logs.");
    u = await get(`users/${id}?$select=${base}`);
  }

  progress("Reading app assignments…");
  const appIds: Record<string, string> = {};
  const spNames = new Map<string, string>();
  const assignments: UserAssignment[] = (await all(get, `users/${u.id}/appRoleAssignments`)).map((a) => {
    spNames.set(a.resourceId, a.resourceDisplayName);
    return { spId: a.resourceId, app: a.resourceDisplayName ?? a.resourceId, via: "direct" as const, roleId: a.appRoleId, created: a.createdDateTime };
  });

  progress("Reading groups and their app assignments…");
  const groups = await all(get, `users/${u.id}/transitiveMemberOf/microsoft.graph.group?$select=id,displayName&$top=999`);
  if (groups.length > GROUP_LIMIT) warnings.push(`${u.userPrincipalName} is in ${groups.length} groups; app assignments were read for the first ${GROUP_LIMIT}. Run Export-F360UserAccess.ps1 for all.`);
  for (const [i, g] of groups.slice(0, GROUP_LIMIT).entries()) {
    if (i % 20 === 0) progress(`Reading group app assignments: ${i} of ${Math.min(groups.length, GROUP_LIMIT)} groups…`);
    for (const a of await all(get, `groups/${g.id}/appRoleAssignments`)) {
      spNames.set(a.resourceId, a.resourceDisplayName);
      assignments.push({ spId: a.resourceId, app: a.resourceDisplayName ?? a.resourceId, via: "group", group: g.displayName, roleId: a.appRoleId, created: a.createdDateTime });
    }
  }

  progress("Reading consent grants…");
  const grants: UserGrant[] = [];
  for (const g of await all(get, `users/${u.id}/oauth2PermissionGrants`)) grants.push({ spId: g.clientId, app: g.clientId, scope: String(g.scope ?? "").trim(), consentType: g.consentType === "AllPrincipals" ? "AllPrincipals" : "Principal" });

  progress("Reading app IDs…");
  for (const spId of new Set([...assignments.map((a) => a.spId), ...grants.map((g) => g.spId)])) {
    try {
      const sp = await get(`servicePrincipals/${spId}?$select=id,appId,displayName`);
      appIds[spId] = sp.appId;
      spNames.set(spId, sp.displayName);
    } catch {
      /* a deleted app */
    }
  }
  for (const g of grants) g.app = spNames.get(g.spId) ?? g.app;

  progress("Reading devices…");
  let devices: UserDevice[] = [];
  try {
    const seen = new Set<string>();
    for (const d of [...(await all(get, `users/${u.id}/registeredDevices?$select=id,displayName,operatingSystem,trustType,accountEnabled`)), ...(await all(get, `users/${u.id}/ownedDevices?$select=id,displayName,operatingSystem,trustType,accountEnabled`))]) {
      if (seen.has(d.id)) continue;
      seen.add(d.id);
      devices.push({ id: d.id, name: d.displayName ?? d.id, os: d.operatingSystem ?? "", trustType: d.trustType ?? "", enabled: d.accountEnabled !== false });
    }
  } catch (e: any) {
    devices = [];
    warnings.push(`Devices couldn't be read (${e.message}).`);
  }

  return {
    format: USER_ACCESS_FORMAT,
    version: 1,
    collectedAt: new Date().toISOString(),
    collector: "browser",
    user: {
      id: u.id,
      upn: u.userPrincipalName ?? who,
      name: u.displayName ?? "",
      enabled: u.accountEnabled !== false,
      sessionsValidFrom: u.signInSessionsValidFromDateTime ?? undefined,
      lastPasswordChange: u.lastPasswordChangeDateTime ?? undefined,
      lastSignIn: u.signInActivity?.lastSignInDateTime ?? undefined,
      lastNonInteractive: u.signInActivity?.lastNonInteractiveSignInDateTime ?? undefined,
    },
    assignments,
    grants,
    devices,
    appIds,
    warnings,
  };
}

// Reads a posture snapshot from Microsoft Graph with a delegated token (browser sign-in on the MFA and SSO coverage
// page). GET requests only. Export-F360Posture.ps1 makes the same file from PowerShell.
//
// Delegated permissions it needs, on top of Discover's Application.Read.All + Directory.Read.All:
//   UserAuthenticationMethod.Read.All  each user's registered sign-in methods (names and types only, never secrets)
//   Policy.Read.All                    authentication methods policy and security defaults
// The signed-in person also needs a directory role that can read methods, such as Authentication Administrator,
// Privileged Authentication Administrator, Global Reader or Global Administrator.
import { methodKind, POSTURE_FORMAT, type MethodPolicyEntry, type PostureApp, type PostureSnapshot, type PostureUser } from "./posture";

export const POSTURE_SCOPES = ["Application.Read.All", "Directory.Read.All", "UserAuthenticationMethod.Read.All", "Policy.Read.All"];

/** Per-user method reads are one call each; above this the scan stops and says how many it left out. */
export const USER_LIMIT = 1000;

const MS_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a";
const METHOD_IDS = ["Fido2", "MicrosoftAuthenticator", "Sms", "Voice", "SoftwareOath", "HardwareOath", "TemporaryAccessPass", "Email", "X509Certificate"];

type Get = (path: string) => Promise<any>;

export function graphGetter(token: string, fetchImpl: typeof fetch = fetch): Get {
  return async (path: string) => {
    const url = path.startsWith("https://") ? path : `https://graph.microsoft.com/v1.0/${path}`;
    for (let attempt = 0; ; attempt++) {
      const r = await fetchImpl(url, { headers: { Authorization: `Bearer ${token}` } });
      if (r.status === 429 && attempt < 3) {
        await new Promise((ok) => setTimeout(ok, 1000 * (Number(r.headers.get("Retry-After")) || 2)));
        continue;
      }
      const j = await r.json().catch(() => ({}));
      if (!r.ok) {
        const what = url.replace("https://graph.microsoft.com/", "").split("?")[0];
        const e = new Error(`${r.status} ${j?.error?.code ?? ""}: ${j?.error?.message ?? r.statusText} (GET ${what})`.replace(/ +/g, " ").trim()) as Error & { status?: number; path?: string };
        e.path = what;
        e.status = r.status;
        throw e;
      }
      return j;
    }
  };
}

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

const targets = (c: any): string[] => (c?.includeTargets ?? []).map((t: any) => String(t.id));

export async function collectPosture(get: Get, tenantId: string, progress: (msg: string) => void = () => {}): Promise<PostureSnapshot> {
  const warnings: string[] = [];
  progress("Reading the organisation…");
  const org = (await get("organization?$select=id,displayName,verifiedDomains")).value?.[0] ?? {};

  progress("Reading security defaults…");
  let securityDefaults: boolean | null = null;
  try {
    securityDefaults = !!(await get("policies/identitySecurityDefaultsEnforcementPolicy")).isEnabled;
  } catch (e: any) {
    warnings.push(`Security defaults couldn't be read (${e.message}). It needs Policy.Read.All.`);
  }

  progress("Reading the authentication methods policy…");
  let methodsPolicy: MethodPolicyEntry[] | null = null;
  try {
    const p = await get("policies/authenticationMethodsPolicy");
    let configs: any[] = p.authenticationMethodConfigurations ?? [];
    if (!configs.length) {
      configs = [];
      for (const id of METHOD_IDS) {
        try {
          configs.push(await get(`policies/authenticationMethodsPolicy/authenticationMethodConfigurations/${id}`));
        } catch {
          /* a method this tenant doesn't have */
        }
      }
    }
    methodsPolicy = configs.map((c) => ({ id: String(c.id), state: c.state === "enabled" ? "enabled" : "disabled", targets: targets(c) }));
  } catch (e: any) {
    warnings.push(`The authentication methods policy couldn't be read (${e.message}). It needs Policy.Read.All.`);
  }

  progress("Reading admin roles…");
  const roles = new Map<string, string[]>();
  for (const r of await all(get, "directoryRoles?$select=id,displayName&$expand=members($select=id)")) {
    for (const m of r.members ?? []) roles.set(m.id, [...(roles.get(m.id) ?? []), r.displayName]);
  }

  progress("Reading users…");
  const raw = await all(get, "users?$select=id,displayName,userPrincipalName,accountEnabled,userType&$top=999", USER_LIMIT + 1);
  const usersNotRead = Math.max(0, raw.length - USER_LIMIT);
  if (usersNotRead) warnings.push(`This scan reads the first ${USER_LIMIT} users only. Run Export-F360Posture.ps1 for the whole tenant.`);
  const users: PostureUser[] = [];
  let denied = 0;
  for (const [i, u] of raw.slice(0, USER_LIMIT).entries()) {
    if (i % 10 === 0) progress(`Reading sign-in methods: ${i} of ${Math.min(raw.length, USER_LIMIT)} users…`);
    let methods: string[] = [];
    try {
      methods = [...new Set<string>((await all(get, `users/${u.id}/authentication/methods`)).map((m) => methodKind(m["@odata.type"] ?? "")))];
    } catch (e: any) {
      if (e.status === 403) denied++;
      else throw e;
    }
    users.push({ id: u.id, upn: u.userPrincipalName ?? "", name: u.displayName ?? "", enabled: u.accountEnabled !== false, guest: u.userType === "Guest", roles: roles.get(u.id) ?? [], methods });
  }
  if (denied)
    warnings.push(`${denied} user${denied === 1 ? "'s" : "s'"} sign-in methods couldn't be read (403). Sign in with Authentication Administrator, Global Reader or higher, and make sure UserAuthenticationMethod.Read.All was consented.`);

  progress("Reading enterprise apps…");
  const sps = await all(get, "servicePrincipals?$select=id,appId,displayName,accountEnabled,appOwnerOrganizationId,preferredSingleSignOnMode,appRoleAssignmentRequired,tags,servicePrincipalType&$top=999");
  const apps: PostureApp[] = sps
    .filter((s) => s.servicePrincipalType === "Application" && (s.tags ?? []).includes("WindowsAzureActiveDirectoryIntegratedApp") && (s.appOwnerOrganizationId ?? "").toLowerCase() !== MS_TENANT)
    .map((s) => ({
      appId: s.appId,
      spId: s.id,
      name: s.displayName ?? s.appId,
      ssoMode: s.preferredSingleSignOnMode ?? "",
      assignmentRequired: !!s.appRoleAssignmentRequired,
      thirdParty: !!s.appOwnerOrganizationId && s.appOwnerOrganizationId.toLowerCase() !== (org.id ?? tenantId).toLowerCase(),
      enabled: s.accountEnabled !== false,
    }));

  const domain = org.verifiedDomains?.find((d: any) => d.isDefault)?.name ?? org.verifiedDomains?.[0]?.name ?? "";
  return {
    format: POSTURE_FORMAT,
    version: 1,
    collectedAt: new Date().toISOString(),
    collector: "browser",
    tenant: { id: org.id ?? tenantId, name: org.displayName ?? "", domain },
    securityDefaults,
    methodsPolicy,
    users,
    usersNotRead: usersNotRead || undefined,
    apps,
    warnings,
  };
}

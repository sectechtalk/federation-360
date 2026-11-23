import { methodKind, mfaLevel, mfaReport, parsePosture, ssoReport, waveCsv, type PostureSnapshot } from "../src/lib/posture";
import { collectPosture } from "../src/lib/postureCollect";
import { samplePosture } from "../src/data/samplePosture";
import { exampleData } from "../src/data/seed";
import { playbookById } from "../src/data/playbooks";
import type { AppIntegration } from "../src/lib/types";

test("method types from Graph are shortened, and levels follow the strongest method", () => {
  expect(methodKind("#microsoft.graph.fido2AuthenticationMethod")).toBe("fido2");
  expect(methodKind("#microsoft.graph.windowsHelloForBusinessAuthenticationMethod")).toBe("windowsHelloForBusiness");
  expect(mfaLevel({ methods: ["password", "phone", "fido2"] })).toBe("phishing-resistant");
  expect(mfaLevel({ methods: ["password", "platformCredential"] })).toBe("phishing-resistant");
  expect(mfaLevel({ methods: ["password", "microsoftAuthenticator"] })).toBe("phishable");
  expect(mfaLevel({ methods: ["password", "email"] })).toBe("none"); // email is for password reset, not MFA
  expect(mfaLevel({ methods: ["password", "temporaryAccessPass"] })).toBe("none");
});

test("sample: counts enabled members only, finds admins without strong MFA, and builds three waves", () => {
  const r = mfaReport(samplePosture());
  expect(r.members).toHaveLength(18); // 20 minus one disabled leaver and one guest
  expect(r.guests).toBe(1);
  expect(r.disabled).toBe(1);
  expect(r.counts).toEqual({ "phishing-resistant": 4, phishable: 11, none: 3 });
  expect(r.percent["phishing-resistant"]).toBe(22);
  expect(r.admins).toHaveLength(5);
  expect(r.adminsResistant).toBe(2);
  const titles = r.findings.map((f) => `${f.severity}: ${f.title}`);
  expect(titles).toContain("critical: 1 admin has no MFA method at all");
  expect(titles).toContain("warn: 2 admins use only phishable MFA");
  expect(titles).toContain("info: Passkeys are on for selected groups only");
  expect(titles).toContain("info: SMS sign-in is still allowed");
  expect(r.waves.map((w) => w.id)).toEqual(["admins", "pilot", "everyone"]);
  expect(r.waves[0].todo.map((u) => u.upn.split("@")[0])).toEqual(["blair.ops", "casey.helpdesk", "dana.apps"]);
  // Every non-admin lands in exactly one of the later waves.
  const later = [...r.waves[1].todo, ...r.waves[2].todo].length + r.waves[1].done + r.waves[2].done;
  expect(later).toBe(r.members.length - r.admins.length);
});

test("passkeys off and security defaults off are warnings", () => {
  const s: PostureSnapshot = { ...samplePosture(), securityDefaults: false, methodsPolicy: [{ id: "Fido2", state: "disabled", targets: [] }] };
  const titles = mfaReport(s).findings.map((f) => `${f.severity}: ${f.title}`);
  expect(titles).toContain("warn: Passkeys (FIDO2) are switched off in the authentication methods policy");
  expect(titles).toContain("warn: Security defaults are off");
  expect(titles).toContain("warn: 3 of 18 people have no MFA method registered");
});

test("SSO coverage: assignment, password vault and SCIM gaps, joined to the inventory by app ID", () => {
  const s = samplePosture();
  const inv: AppIntegration[] = [{ ...exampleData().apps.find((a) => a.id === "ex-partner")!, protocol: "oidc", provisioning: "scim", discovery: { appId: s.apps[2].appId } as any }];
  const r = ssoReport(s, inv);
  const by = (n: string) => r.rows.find((x) => x.name === n)!;
  expect(by("Partner Portal")).toMatchObject({ signIn: "oidc", scim: true, inventoryId: "ex-partner" }); // no SSO mode, but Inventory says OIDC
  expect(by("Payroll Cloud").findings.map((f) => f.title)).toContain("Anyone in the tenant can sign in");
  expect(by("Shipping Tracker").findings.map((f) => f.title)).toContain("Password vault, not single sign-on");
  expect(by("Expense Portal").findings.map((f) => f.title)).toEqual(["No SCIM: leavers keep their account in the app"]);
  expect(by("Vendor Wiki").signIn).toBe("linked");
  expect(r).toMatchObject({ total: 6, sso: 4, assigned: 2, scim: 1 });
});

test("posture files: format checked with plain-words errors", () => {
  expect(parsePosture(JSON.stringify(samplePosture())).users).toHaveLength(20);
  expect(() => parsePosture("nope")).toThrow(/isn't JSON/);
  expect(() => parsePosture(JSON.stringify({ format: "f360.entra.export" }))).toThrow(/Discover export/);
  expect(() => parsePosture(JSON.stringify({ format: "f360-posture", version: 2 }))).toThrow(/newer/);
});

test("wave CSV lists the people still to go, never phone numbers", () => {
  const csv = waveCsv(mfaReport(samplePosture()).waves[0]);
  expect(csv.split("\n")[0]).toBe("User principal name,Display name,Admin roles,MFA today,Methods registered");
  expect(csv).toContain("dana.apps@f360sample.onmicrosoft.com,Dana Apps,Application Administrator,No MFA method,Password");
});

test("Graph reader: GETs only, follows paging, maps methods, roles and apps, and reports 403s on method reads", async () => {
  const calls: string[] = [];
  const pages: Record<string, any> = {
    "organization?$select=id,displayName,verifiedDomains": { value: [{ id: "tid", displayName: "Lab", verifiedDomains: [{ name: "lab.example", isDefault: true }] }] },
    "policies/identitySecurityDefaultsEnforcementPolicy": { isEnabled: true },
    "policies/authenticationMethodsPolicy": { authenticationMethodConfigurations: [{ id: "Fido2", state: "enabled", includeTargets: [{ id: "all_users" }] }] },
    "directoryRoles?$select=id,displayName&$expand=members($select=id)": { value: [{ displayName: "Global Administrator", members: [{ id: "u1" }] }] },
    "users?$select=id,displayName,userPrincipalName,accountEnabled,userType&$top=999": { value: [{ id: "u1", userPrincipalName: "a@lab.example", displayName: "A" }], "@odata.nextLink": "https://graph.microsoft.com/v1.0/next-users" },
    "https://graph.microsoft.com/v1.0/next-users": { value: [{ id: "u2", userPrincipalName: "b@lab.example", displayName: "B", userType: "Guest" }] },
    "users/u1/authentication/methods": { value: [{ "@odata.type": "#microsoft.graph.passwordAuthenticationMethod" }, { "@odata.type": "#microsoft.graph.fido2AuthenticationMethod" }] },
    "servicePrincipals?$select=id,appId,displayName,accountEnabled,appOwnerOrganizationId,preferredSingleSignOnMode,appRoleAssignmentRequired,tags,servicePrincipalType&$top=999": {
      value: [
        { id: "sp1", appId: "app1", displayName: "SAML app", appOwnerOrganizationId: "other", preferredSingleSignOnMode: "saml", appRoleAssignmentRequired: true, tags: ["WindowsAzureActiveDirectoryIntegratedApp"], servicePrincipalType: "Application" },
        { id: "sp2", appId: "app2", displayName: "Graph", appOwnerOrganizationId: "f8cdef31-a31e-4b4a-93e4-5f571e91255a", tags: ["WindowsAzureActiveDirectoryIntegratedApp"], servicePrincipalType: "Application" },
        { id: "sp3", appId: "app3", displayName: "mi", servicePrincipalType: "ManagedIdentity", tags: [] },
      ],
    },
  };
  const get = async (p: string) => {
    calls.push(p);
    if (p === "users/u2/authentication/methods") throw Object.assign(new Error("403 Forbidden"), { status: 403 });
    if (!(p in pages)) throw new Error("unexpected " + p);
    return pages[p];
  };
  const s = await collectPosture(get, "tid");
  expect(s.users).toEqual([
    { id: "u1", upn: "a@lab.example", name: "A", enabled: true, guest: false, roles: ["Global Administrator"], methods: ["password", "fido2"] },
    { id: "u2", upn: "b@lab.example", name: "B", enabled: true, guest: true, roles: [], methods: [] },
  ]);
  expect(s.methodsPolicy).toEqual([{ id: "Fido2", state: "enabled", targets: ["all_users"] }]);
  expect(s.apps).toEqual([{ appId: "app1", spId: "sp1", name: "SAML app", ssoMode: "saml", assignmentRequired: true, thirdParty: true, enabled: true }]);
  expect(s.warnings.join(" ")).toMatch(/1 user's sign-in methods couldn't be read \(403\)/);
  expect(s.tenant).toEqual({ id: "tid", name: "Lab", domain: "lab.example" });
});

test("rollout playbook exists and points at the page", () => {
  expect(playbookById("mfa-phishing-resistant-rollout")?.tools).toEqual(["posture"]);
});

test("pilot wave takes about 10% of non-admins who still need a passkey, starting with authenticator users", () => {
  const w = mfaReport(samplePosture()).waves;
  expect(w[1].todo.map((u) => u.upn.split("@")[0])).toEqual(["gray.finance", "harper.sales"]);
  expect(w[1].done).toBe(2);
  expect(w[2].todo).toHaveLength(9);
});

import { grantFindings, grantRows, grantsCsv, grantSummary, rateGrant, grantPortalLinks } from "../src/lib/grants";
import { appHealth } from "../src/lib/health";
import { exampleData } from "../src/data/seed";
import { playbookById } from "../src/data/playbooks";
import type { AppIntegration, DiscoveredPermission } from "../src/lib/types";
import { emptyOidc, emptySaml } from "../src/lib/types";

const G = "Microsoft Graph";
const perm = (value: string, type: DiscoveredPermission["type"], status: DiscoveredPermission["status"] = "granted", consent?: string): DiscoveredPermission => ({ resource: G, value, type, status, consent });

function app(p: Partial<AppIntegration> & { perms: DiscoveredPermission[]; thirdParty?: boolean; objectId?: string }): AppIntegration {
  return {
    id: p.id ?? "a1",
    tenantId: "t1",
    name: p.name ?? "Test app",
    protocol: "oauth",
    environment: "prod",
    owner: p.owner ?? "Team",
    status: "live",
    provisioning: "none",
    saml: emptySaml(),
    oidc: { ...emptyOidc(), clientType: "public" },
    notes: "",
    updatedAt: "",
    discovery: {
      provider: "entra", externalId: "entra:x", appId: "11111111-2222-3333-4444-555555555555", servicePrincipalId: "sp-1", objectId: p.objectId,
      lastSeen: "", enabled: true, owners: [], identifierUris: [], redirectUris: [], implicit: { idToken: false, accessToken: false },
      credentials: [], permissions: p.perms, thirdParty: p.thirdParty, publisher: p.thirdParty ? "Shady Co" : undefined,
    },
  };
}

test("ratings: takeover permissions are critical, bulk data high, directory reads medium, sign-in low, unknown APIs unrated", () => {
  expect(rateGrant(perm("RoleManagement.ReadWrite.Directory", "application")).risk).toBe("critical");
  expect(rateGrant(perm("AppRoleAssignment.ReadWrite.All", "application")).risk).toBe("critical");
  expect(rateGrant(perm("Application.ReadWrite.All", "application")).risk).toBe("critical");
  expect(rateGrant(perm("Application.ReadWrite.All", "delegated")).risk).toBe("high");
  expect(rateGrant(perm("Mail.Read", "application")).risk).toBe("high");
  expect(rateGrant(perm("Sites.Read.All", "delegated")).risk).toBe("medium");
  expect(rateGrant(perm("Directory.Read.All", "application")).risk).toBe("medium");
  expect(rateGrant(perm("User.Read", "delegated")).risk).toBe("low");
  expect(rateGrant({ resource: "Office 365 Exchange Online", value: "full_access_as_app", type: "application" }).risk).toBe("critical");
  expect(rateGrant({ resource: "LAB-API", value: "Jobs.Read.All", type: "application" }).risk).toBe("unrated");
  // Not on the list: the name decides, cautiously.
  expect(rateGrant(perm("Widgets.ReadWrite.All", "application")).risk).toBe("high");
  expect(rateGrant(perm("Widgets.Read", "delegated")).risk).toBe("low");
  // Prototype names never match a rule.
  expect(rateGrant(perm("constructor", "delegated")).risk).toBe("low");
});

test("an app that can grant itself more access is critical and points at the playbook", () => {
  const f = grantFindings(app({ perms: [perm("AppRoleAssignment.ReadWrite.All", "application")] }));
  expect(f[0]).toMatchObject({ severity: "critical", playbook: "oauth-risky-grant" });
  expect(f[0].title).toMatch(/take over the tenant: AppRoleAssignment\.ReadWrite\.All/);
});

test("delegated critical permissions count as takeover only with admin consent", () => {
  expect(grantFindings(app({ perms: [perm("RoleManagement.ReadWrite.Directory", "delegated", "granted", "AllPrincipals")] }))[0].severity).toBe("critical");
  expect(grantFindings(app({ perms: [perm("RoleManagement.ReadWrite.Directory", "delegated", "granted", "Principal")] })).some((x) => /take over/.test(x.title))).toBe(false);
});

test("application access to everyone's mail is a warning for your app and critical for a third party", () => {
  const mine = grantFindings(app({ perms: [perm("Mail.Read", "application")] }));
  expect(mine.find((x) => /everyone's data/.test(x.title))?.severity).toBe("warn");
  const theirs = grantFindings(app({ thirdParty: true, perms: [perm("Mail.Read", "application")] }));
  expect(theirs.find((x) => /Third-party app reads everyone's data/.test(x.title))?.severity).toBe("critical");
});

test("shadow IT: users who consented themselves to a third-party app are counted, and offline_access is called out", () => {
  const perms = ["u1", "u2"].flatMap(() => [perm("Mail.Read", "delegated", "granted", "Principal"), perm("offline_access", "delegated", "granted", "Principal")]);
  const a = app({ thirdParty: true, perms });
  const f = grantFindings(a);
  const shadow = f.find((x) => /Shadow IT/.test(x.title))!;
  expect(shadow.title).toBe("Shadow IT: 2 users consented themselves to Mail.Read");
  expect(shadow.detail).toMatch(/offline_access/);
  expect(shadow.playbook).toBe("oauth-user-consent");
  // One row per permission and consent kind, with the user count.
  const rows = grantRows([a]);
  expect(rows.find((r) => r.value === "Mail.Read")).toMatchObject({ consent: "user", users: 2, thirdParty: true, publisher: "Shady Co" });
  // Your own app with user consent is not shadow IT.
  expect(grantFindings(app({ perms })).some((x) => /Shadow IT/.test(x.title))).toBe(false);
});

test("powerful permissions with no owner, and grants the app no longer requests", () => {
  const a = app({ owner: "", objectId: "obj-1", perms: [perm("User.Read.All", "application", "requested"), perm("User.Read.All", "application"), perm("Files.ReadWrite.All", "application")] });
  const f = grantFindings(a);
  expect(f.some((x) => x.title === "Powerful permissions and no owner")).toBe(true);
  expect(f.find((x) => /no longer requested/.test(x.title))?.title).toBe("Granted but no longer requested: Files.ReadWrite.All");
  // Without the app registration (third-party or enterprise app only) nobody can tell what is requested, so nothing is called stale.
  expect(grantRows([app({ perms: [perm("Files.ReadWrite.All", "application")] })])[0].stale).toBe(false);
});

test("low-risk sign-in grants raise nothing", () => {
  expect(grantFindings(app({ thirdParty: true, perms: ["openid", "profile", "User.Read"].map((v) => perm(v, "delegated", "granted", "Principal")) }))).toEqual([]);
});

test("example data shows a shadow IT app and an over-permissioned automation app on Overview", () => {
  const apps = exampleData().apps;
  const notes = appHealth(apps.find((a) => a.id === "ex-notes")!);
  expect(notes.some((x) => /Shadow IT: 3 users/.test(x.title))).toBe(true);
  const helpdesk = appHealth(apps.find((a) => a.id === "ex-helpdesk")!);
  expect(helpdesk.some((x) => x.severity === "critical" && /Application\.ReadWrite\.All/.test(x.title))).toBe(true);
  expect(helpdesk.some((x) => /no longer requested: Application\.ReadWrite\.All/.test(x.title))).toBe(true);
  const s = grantSummary(grantRows(apps));
  expect(s).toMatchObject({ takeoverApps: 1, shadowApps: 1 });
  // Example apps never link to a real portal object.
  expect(grantPortalLinks(apps.find((a) => a.id === "ex-helpdesk")!)).toEqual([]);
});

test("portal links: enterprise app permissions in Entra and Azure, plus API permissions for your own app registration", () => {
  const links = grantPortalLinks(app({ objectId: "obj-1", perms: [] }));
  expect(links.map((l) => l.url)).toEqual([
    "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Permissions/objectId/sp-1/appId/11111111-2222-3333-4444-555555555555",
    "https://portal.azure.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Permissions/objectId/sp-1/appId/11111111-2222-3333-4444-555555555555",
    "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/11111111-2222-3333-4444-555555555555",
  ]);
  expect(grantPortalLinks(app({ thirdParty: true, objectId: "obj-1", perms: [] }))).toHaveLength(2);
});

test("CSV: one header and one line per grant, commas and quotes escaped, never a secret", () => {
  const a = app({ name: 'Billing, "new"', perms: [perm("Mail.Send", "application")] });
  const csv = grantsCsv(grantRows([a]));
  const lines = csv.trim().split("\n");
  expect(lines[0]).toMatch(/^App,Publisher,API,Permission,Type,Consent/);
  expect(lines[1].startsWith('"Billing, ""new""",Your organisation,Microsoft Graph,Mail.Send,application,Admin (all users)')).toBe(true);
});

test("both grant playbooks exist", () => {
  expect(playbookById("oauth-risky-grant")?.tools).toContain("grants");
  expect(playbookById("oauth-user-consent")).toBeTruthy();
});

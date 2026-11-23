// OAuth grant review: rates every permission an app holds in the tenant and turns the risky ones into findings.
// Discover already collects requested and granted permissions (oauth2PermissionGrants for delegated consent,
// appRoleAssignments for application permissions). This file only reads them; nothing here calls Graph.
//
// Ratings follow what the permission lets the app do on its own, not what a typical app uses it for:
//   critical: the app could make itself or anyone a Global Administrator, or sign in as anyone (tenant takeover)
//   high:     the app can read or change every user's mail, files, chats or accounts
//   medium:   the app can read the whole directory or other people's data in a limited way
//   low:      sign-in and the signed-in user's own basic profile
//   unrated:  an API Federation 360 has no list for (your own APIs, third-party APIs)
import type { AppIntegration, DiscoveredPermission, Finding, Severity } from "./types";

export type GrantRisk = "critical" | "high" | "medium" | "low" | "unrated";

export const RISK_LABEL: Record<GrantRisk, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  unrated: "Not rated",
};

export const RISK_ORDER: GrantRisk[] = ["critical", "high", "medium", "low", "unrated"];

/** The Sev chip colour used for each rating. */
export const RISK_SEVERITY: Record<GrantRisk, Severity> = { critical: "critical", high: "warn", medium: "info", low: "ok", unrated: "ok" };

interface Rule {
  /** Both permission types unless set. */
  type?: DiscoveredPermission["type"];
  risk: GrantRisk;
  why: string;
}

const GRAPH = "Microsoft Graph";
const EXCHANGE = "Office 365 Exchange Online";

// Microsoft Graph permissions, by value. Delegated permissions are limited to what the signed-in user can do, so the
// same name is often rated lower as delegated than as application. Wording is what the permission lets the app do.
const GRAPH_RULES: Record<string, Rule[]> = {
  "RoleManagement.ReadWrite.Directory": [
    { type: "application", risk: "critical", why: "Can assign any directory role, including Global Administrator, to any account, including itself." },
    { type: "delegated", risk: "critical", why: "Lets the app assign directory roles with the signed-in admin's rights. Consent phishing an admin with this gives away the tenant." },
  ],
  "AppRoleAssignment.ReadWrite.All": [
    { type: "application", risk: "critical", why: "Can grant itself or any app any application permission, so it can reach every other permission on this list." },
    { type: "delegated", risk: "high", why: "Lets the app grant app permissions with the signed-in admin's rights." },
  ],
  "Application.ReadWrite.All": [
    { type: "application", risk: "critical", why: "Can add a secret or certificate to any app registration and then act as that app, including apps with more powerful permissions." },
    { type: "delegated", risk: "high", why: "Lets the app add credentials to apps the signed-in user can manage." },
  ],
  "Directory.ReadWrite.All": [
    { type: "application", risk: "critical", why: "Can create, change and delete users, groups and most directory objects, including resetting how accounts are set up." },
    { type: "delegated", risk: "high", why: "Lets the app change directory objects with the signed-in user's rights." },
  ],
  "Directory.AccessAsUser.All": [{ type: "delegated", risk: "high", why: "Acts with every right the signed-in user has in the directory. For an admin, that is the whole tenant." }],
  "UserAuthenticationMethod.ReadWrite.All": [
    { type: "application", risk: "critical", why: "Can add a phone or other sign-in method to any account, including admins, and then pass MFA as them." },
    { type: "delegated", risk: "high", why: "Lets the app change other users' sign-in methods with the signed-in admin's rights." },
  ],
  "Policy.ReadWrite.ConditionalAccess": [{ risk: "critical", why: "Can switch off or rewrite the Conditional Access policies that enforce MFA and block risky sign-ins." }],
  "Policy.ReadWrite.AuthenticationMethod": [{ risk: "critical", why: "Can change which sign-in methods the tenant allows, for example turn SMS back on or switch passkeys off." }],
  "Policy.ReadWrite.PermissionGrant": [{ risk: "critical", why: "Can change who may consent to apps, so it can open the door to more risky consent." }],
  "Domain.ReadWrite.All": [{ type: "application", risk: "critical", why: "Can add a domain and set it to federated, which lets an outside identity provider sign in as your users." }],
  "RoleManagementPolicy.ReadWrite.Directory": [{ risk: "critical", why: "Can change Privileged Identity Management rules, such as removing approval or MFA from role activation." }],
  "PrivilegedAccess.ReadWrite.AzureADGroup": [{ risk: "critical", why: "Can change who is eligible for privileged groups through Privileged Identity Management." }],

  "Mail.ReadWrite": [
    { type: "application", risk: "high", why: "Can read, change and delete every mailbox in the organisation." },
    { type: "delegated", risk: "high", why: "Can read, change and delete the user's mail. The classic target of consent phishing." },
  ],
  "Mail.Read": [
    { type: "application", risk: "high", why: "Can read every mailbox in the organisation." },
    { type: "delegated", risk: "high", why: "Can read all of the user's mail, including password reset and MFA emails." },
  ],
  "Mail.Send": [
    { type: "application", risk: "high", why: "Can send mail as any user in the organisation." },
    { type: "delegated", risk: "high", why: "Can send mail as the user, for example internal phishing from a trusted address." },
  ],
  "MailboxSettings.ReadWrite": [{ risk: "high", why: "Can create inbox rules and forwarding, a common way attackers hide replies and keep copies of mail." }],
  "Files.ReadWrite.All": [
    { type: "application", risk: "high", why: "Can read, change and delete every file in OneDrive and SharePoint." },
    { type: "delegated", risk: "high", why: "Can read, change and delete every file the user can open, including shared ones." },
  ],
  "Files.Read.All": [
    { type: "application", risk: "high", why: "Can read every file in OneDrive and SharePoint." },
    { type: "delegated", risk: "high", why: "Can read every file the user can open, including files shared with them." },
  ],
  "Sites.FullControl.All": [{ risk: "high", why: "Full control of every SharePoint site the app can reach, including permissions." }],
  "Sites.Manage.All": [{ risk: "high", why: "Can create and change lists and libraries on every SharePoint site the app can reach." }],
  "Sites.ReadWrite.All": [{ risk: "high", why: "Can read and change items on every SharePoint site the app can reach." }],
  "Sites.Read.All": [
    { type: "application", risk: "high", why: "Can read every SharePoint site." },
    { type: "delegated", risk: "medium", why: "Can read every SharePoint site the user can open." },
  ],
  "Chat.ReadWrite.All": [{ risk: "high", why: "Can read and send Teams chat messages for every user." }],
  "Chat.Read.All": [{ risk: "high", why: "Can read every Teams chat in the organisation." }],
  "Chat.ReadWrite": [{ type: "delegated", risk: "high", why: "Can read and send the user's Teams chats." }],
  "Chat.Read": [{ type: "delegated", risk: "medium", why: "Can read the user's Teams chats." }],
  "ChannelMessage.Read.All": [{ risk: "high", why: "Can read every Teams channel message." }],
  "User.ReadWrite.All": [
    { type: "application", risk: "high", why: "Can change every user's profile, including fields other systems trust, and disable accounts." },
    { type: "delegated", risk: "high", why: "Can change other users' profiles with the signed-in user's rights." },
  ],
  "Group.ReadWrite.All": [{ risk: "high", why: "Can change any group and its members, including groups used to grant access to apps." }],
  "GroupMember.ReadWrite.All": [{ risk: "high", why: "Can add anyone to any group, including groups that grant access or admin rights." }],
  "Calendars.ReadWrite": [{ risk: "high", why: "Can read and change calendars (every user's, when it is an application permission)." }],
  "Contacts.ReadWrite": [{ risk: "medium", why: "Can read and change contacts." }],
  "Notes.ReadWrite.All": [{ risk: "high", why: "Can read and change OneNote notebooks the app can reach." }],
  "AuditLog.Read.All": [{ risk: "medium", why: "Can read sign-in and audit logs, which show who signs in from where." }],
  "Directory.Read.All": [{ risk: "medium", why: "Can read every user, group and app in the directory. Useful to an attacker planning the next step." }],
  "User.Read.All": [{ risk: "medium", why: "Can read every user's profile." }],
  "Group.Read.All": [{ risk: "medium", why: "Can read every group and its members." }],
  "Application.Read.All": [{ risk: "medium", why: "Can read every app registration and enterprise app, including which permissions they hold." }],
  "Policy.Read.All": [{ risk: "medium", why: "Can read the tenant's security policies, including Conditional Access." }],
  "Calendars.Read": [{ risk: "medium", why: "Can read calendars (every user's, when it is an application permission)." }],
  "Contacts.Read": [{ risk: "medium", why: "Can read contacts." }],
  "People.Read.All": [{ risk: "medium", why: "Can read the people each user works with most." }],

  "User.Read": [{ type: "delegated", risk: "low", why: "Sign in and read the signed-in user's own profile." }],
  "User.ReadBasic.All": [{ type: "delegated", risk: "low", why: "Read basic profiles (name, email, photo) of other users." }],
  openid: [{ type: "delegated", risk: "low", why: "Sign the user in." }],
  profile: [{ type: "delegated", risk: "low", why: "Read the user's name." }],
  email: [{ type: "delegated", risk: "low", why: "Read the user's email address." }],
  offline_access: [{ type: "delegated", risk: "low", why: "Keeps access after the user leaves the app (refresh token). Low on its own, but it makes every other permission last for months." }],
};

const EXCHANGE_RULES: Record<string, Rule[]> = {
  full_access_as_app: [{ type: "application", risk: "critical", why: "Full access to every mailbox through Exchange Web Services, with no user signed in." }],
  "Exchange.ManageAsApp": [{ type: "application", risk: "high", why: "Runs Exchange Online PowerShell as the app. What it can change depends on the Exchange role it was given." }],
  "EWS.AccessAsUser.All": [{ type: "delegated", risk: "high", why: "Full access to the user's mailbox through Exchange Web Services." }],
  "Mail.ReadWrite": GRAPH_RULES["Mail.ReadWrite"],
  "Mail.Read": GRAPH_RULES["Mail.Read"],
  "Mail.Send": GRAPH_RULES["Mail.Send"],
};

export interface RatedGrant {
  risk: GrantRisk;
  why: string;
}

/** Rates one permission. Unknown APIs are "unrated", never guessed. */
export function rateGrant(p: Pick<DiscoveredPermission, "resource" | "value" | "type">): RatedGrant {
  const table = p.resource === GRAPH ? GRAPH_RULES : p.resource === EXCHANGE ? EXCHANGE_RULES : null;
  if (!table) return { risk: "unrated", why: `${p.resource} is not a Microsoft API Federation 360 has a list for. Ask the app's owner what ${p.value} allows.` };
  const rules = Object.prototype.hasOwnProperty.call(table, p.value) ? table[p.value] : undefined;
  const rule = rules?.find((r) => !r.type || r.type === p.type);
  if (rule) return { risk: rule.risk, why: rule.why };
  // Not on the list: say what the name suggests, at a cautious medium for anything tenant-wide that writes.
  if (/\.ReadWrite\.All$|\.Send$|FullControl/.test(p.value)) return { risk: p.type === "application" ? "high" : "medium", why: "Not on Federation 360's list, but the name says it can change data across the organisation. Check Microsoft's permissions reference." };
  if (/\.All$/.test(p.value)) return { risk: "medium", why: "Not on Federation 360's list. The name says it reaches data across the organisation." };
  return { risk: "low", why: "Not on Federation 360's list, and the name suggests it is limited to the user's own data." };
}

export interface GrantRow {
  app: AppIntegration;
  resource: string;
  value: string;
  type: DiscoveredPermission["type"];
  /** "admin" = an admin consented for everyone (delegated AllPrincipals, or any application permission). "user" = individual users consented. */
  consent: "admin" | "user";
  /** How many users consented themselves (delegated, consent = Principal). 0 for admin consent. */
  users: number;
  thirdParty: boolean;
  publisher: string;
  /** Granted in the tenant but no longer listed on the app registration (only known for your own app registrations). */
  stale: boolean;
  risk: GrantRisk;
  why: string;
}

const key = (p: { resource: string; value: string; type: string }) => `${p.type}|${p.resource}|${p.value}`;

/** Every granted permission across the inventory, one row per app + API + permission + consent kind. */
export function grantRows(apps: AppIntegration[]): GrantRow[] {
  const rows: GrantRow[] = [];
  for (const app of apps) {
    const d = app.discovery;
    if (!d) continue;
    const requested = new Set(d.permissions.filter((p) => p.status === "requested").map(key));
    // Requested permissions are only known for app registrations in this tenant (objectId set).
    const canTellStale = !!d.objectId && !d.thirdParty;
    const merged = new Map<string, GrantRow>();
    for (const p of d.permissions) {
      if (p.status !== "granted") continue;
      const consent: GrantRow["consent"] = p.type === "delegated" && p.consent === "Principal" ? "user" : "admin";
      const k = key(p) + "|" + consent;
      const prev = merged.get(k);
      if (prev) {
        if (consent === "user") prev.users++;
        continue;
      }
      const r = rateGrant(p);
      merged.set(k, {
        app,
        resource: p.resource,
        value: p.value,
        type: p.type,
        consent,
        users: consent === "user" ? 1 : 0,
        thirdParty: !!d.thirdParty,
        publisher: d.thirdParty ? d.publisher ?? "Another organisation" : "Your organisation",
        stale: canTellStale && !requested.has(key(p)),
        risk: r.risk,
        why: r.why,
      });
    }
    rows.push(...merged.values());
  }
  return rows.sort((a, b) => RISK_ORDER.indexOf(a.risk) - RISK_ORDER.indexOf(b.risk) || a.app.name.localeCompare(b.app.name) || a.value.localeCompare(b.value));
}

const list = (rows: GrantRow[]) => {
  const names = [...new Set(rows.map((r) => r.value))];
  return names.length <= 4 ? names.join(", ") : `${names.slice(0, 4).join(", ")} and ${names.length - 4} more`;
};

/** Findings for one app's grants. Added to appHealth, so they show on Overview and in Inventory. */
export function grantFindings(app: AppIntegration): Finding[] {
  const rows = grantRows([app]);
  if (!rows.length) return [];
  const f: Finding[] = [];
  const appOnly = rows.filter((r) => r.type === "application");
  const delegated = rows.filter((r) => r.type === "delegated");
  const third = !!app.discovery?.thirdParty;
  const who = third ? `${app.discovery?.publisher ?? "another organisation"}'s app` : "This app";

  const takeover = rows.filter((r) => r.risk === "critical" && (r.type === "application" || r.consent === "admin"));
  if (takeover.length)
    f.push({
      severity: "critical",
      title: `Can take over the tenant: ${list(takeover)}`,
      detail: `${who} holds ${takeover.length === 1 ? "a permission" : "permissions"} that let it give itself more access or sign in as anyone. ${takeover[0].why} Remove ${takeover.length === 1 ? "it" : "them"} unless the owner can say exactly why ${takeover.length === 1 ? "it is" : "they are"} needed, and make sure the app's credentials are tightly held.`,
      playbook: "oauth-risky-grant",
    });

  const bulk = appOnly.filter((r) => r.risk === "high");
  if (bulk.length)
    f.push({
      severity: third ? "critical" : "warn",
      title: `${third ? "Third-party app reads" : "Reads"} everyone's data with no user signed in: ${list(bulk)}`,
      detail: `Application permissions work for every user in the tenant, all the time.${third ? ` The app is run by ${app.discovery?.publisher ?? "another organisation"}, so your data leaves your control.` : ""} ${bulk[0].why} Narrow it (for example an Exchange application access policy or Sites.Selected), or remove it.`,
      playbook: "oauth-risky-grant",
    });

  const userRisky = delegated.filter((r) => r.consent === "user" && (r.risk === "critical" || r.risk === "high"));
  if (third && userRisky.length) {
    const users = Math.max(...userRisky.map((r) => r.users));
    const longLived = delegated.some((r) => r.value === "offline_access");
    f.push({
      severity: "warn",
      title: `Shadow IT: ${users} user${users === 1 ? "" : "s"} consented themselves to ${list(userRisky)}`,
      detail: `Nobody in IT approved this app. ${userRisky[0].why}${longLived ? " It also has offline_access, so it keeps that access for months without the user coming back." : ""} This is the shape of a consent-phishing attack. Check with the users, then remove the grant or approve it properly, and turn off user consent for unverified apps.`,
      playbook: "oauth-user-consent",
    });
  }

  const adminRisky = delegated.filter((r) => r.consent === "admin" && r.risk === "high");
  if (third && adminRisky.length)
    f.push({
      severity: "warn",
      title: `Third-party app has admin consent for every user: ${list(adminRisky)}`,
      detail: `An admin approved this for the whole organisation, so it works for anyone who signs in to it. ${adminRisky[0].why} Confirm the vendor and the business need are still current.`,
      playbook: "oauth-risky-grant",
    });

  const powerful = rows.filter((r) => r.risk === "critical" || (r.risk === "high" && r.type === "application"));
  if (powerful.length && !app.owner.trim())
    f.push({
      severity: "warn",
      title: "Powerful permissions and no owner",
      detail: `${list(powerful)} with nobody accountable. Find an owner or remove the permissions; an orphaned app with these is an easy way in for an attacker.`,
      playbook: "oauth-risky-grant",
    });

  const stale = rows.filter((r) => r.stale);
  if (stale.length)
    f.push({
      severity: "info",
      title: `Granted but no longer requested: ${list(stale)}`,
      detail: "The app registration doesn't ask for these any more, but the consent is still in the tenant. Remove the leftover grant (least privilege).",
      playbook: "oauth-risky-grant",
    });
  return f;
}

/** Counts for the summary tiles. */
export function grantSummary(rows: GrantRow[]) {
  const apps = (pred: (r: GrantRow) => boolean) => new Set(rows.filter(pred).map((r) => r.app.id)).size;
  return {
    grants: rows.length,
    apps: new Set(rows.map((r) => r.app.id)).size,
    takeoverApps: apps((r) => r.risk === "critical" && (r.type === "application" || r.consent === "admin")),
    bulkApps: apps((r) => r.risk === "high" && r.type === "application"),
    shadowApps: apps((r) => r.thirdParty && r.consent === "user" && (r.risk === "critical" || r.risk === "high")),
    staleGrants: rows.filter((r) => r.stale).length,
    byRisk: Object.fromEntries(RISK_ORDER.map((k) => [k, rows.filter((r) => r.risk === k).length])) as Record<GrantRisk, number>,
  };
}

/** Portal pages where this app's permissions can be changed. One link per portal, never a list page. */
export function grantPortalLinks(app: AppIntegration): { label: string; url: string }[] {
  const d = app.discovery;
  if (!d?.appId || app.example) return [];
  const out: { label: string; url: string }[] = [];
  if (d.servicePrincipalId) {
    const path = `#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Permissions/objectId/${d.servicePrincipalId}/appId/${d.appId}`;
    out.push({ label: "Entra: enterprise app permissions", url: `https://entra.microsoft.com/${path}` });
    out.push({ label: "Azure portal: enterprise app permissions", url: `https://portal.azure.com/${path}` });
  }
  if (d.objectId && !d.thirdParty) {
    const path = `#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/${d.appId}`;
    out.push({ label: "Entra: app registration API permissions", url: `https://entra.microsoft.com/${path}` });
  }
  return out;
}

export const CONSENT_SETTINGS_URL = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings";

const csvCell = (v: string | number) => {
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

/** CSV for a spreadsheet or a ticket. Names, permissions and ratings only; never secrets. */
export function grantsCsv(rows: GrantRow[]): string {
  const head = ["App", "Publisher", "API", "Permission", "Type", "Consent", "Users who consented", "Risk", "Why", "No longer requested", "Owner", "App ID"];
  const lines = rows.map((r) =>
    [r.app.name, r.publisher, r.resource, r.value, r.type, r.consent === "admin" ? "Admin (all users)" : "Users themselves", r.users || "", RISK_LABEL[r.risk], r.why, r.stale ? "Yes" : "", r.app.owner, r.app.discovery?.appId ?? ""]
      .map(csvCell)
      .join(","),
  );
  return [head.join(","), ...lines].join("\n") + "\n";
}

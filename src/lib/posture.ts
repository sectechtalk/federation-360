// MFA and SSO coverage: how far the tenant is from phishing-resistant MFA for everyone, and how many apps really sit
// behind single sign-on, assignment and SCIM. Works from a read-only posture snapshot (browser sign-in or
// Export-F360Posture.ps1) plus the inventory. Nothing here changes the tenant.
//
// Licensing (checked against Microsoft Learn, 2026-11-22): reading the authentication methods policy, each user's
// registered methods, directory roles and security defaults works on Entra ID Free. Microsoft's ready-made
// registration report (reports/authenticationMethods/userRegistrationDetails) and enforcing with Conditional Access
// authentication strengths need P1, so this file builds its own numbers from per-user reads instead.
import type { AppIntegration, Finding } from "./types";

export const POSTURE_FORMAT = "f360-posture";

/** Short method names, from the Graph @odata.type with "#microsoft.graph." and "AuthenticationMethod" removed. */
export type MethodKind =
  | "fido2"
  | "windowsHelloForBusiness"
  | "platformCredential"
  | "x509Certificate"
  | "microsoftAuthenticator"
  | "softwareOath"
  | "hardwareOath"
  | "phone"
  | "email"
  | "temporaryAccessPass"
  | "password"
  | string;

export interface PostureUser {
  id: string;
  upn: string;
  name: string;
  enabled: boolean;
  guest: boolean;
  /** Directory role names, e.g. Global Administrator. Empty for normal users. */
  roles: string[];
  methods: MethodKind[];
}

export interface MethodPolicyEntry {
  /** Graph id of the method configuration, e.g. Fido2, MicrosoftAuthenticator, Sms. */
  id: string;
  state: "enabled" | "disabled";
  /** "all_users" or group IDs/names the method is turned on for. */
  targets: string[];
}

export interface PostureApp {
  appId: string;
  spId: string;
  name: string;
  /** preferredSingleSignOnMode: saml, oidc, password, notSupported, or empty. */
  ssoMode: string;
  assignmentRequired: boolean;
  thirdParty: boolean;
  enabled: boolean;
}

export interface PostureSnapshot {
  format: typeof POSTURE_FORMAT;
  version: 1;
  collectedAt: string;
  collector: "browser" | "powershell" | "sample";
  tenant: { id: string; name: string; domain: string };
  /** null when it couldn't be read. */
  securityDefaults: boolean | null;
  methodsPolicy: MethodPolicyEntry[] | null;
  users: PostureUser[];
  /** Users left out because the scan hit its limit. */
  usersNotRead?: number;
  apps: PostureApp[];
  warnings: string[];
  example?: boolean;
}

export type MfaLevel = "phishing-resistant" | "phishable" | "none";

export const LEVEL_LABEL: Record<MfaLevel, string> = {
  "phishing-resistant": "Phishing-resistant",
  phishable: "MFA, but phishable",
  none: "No MFA method",
};

export const METHOD_LABEL: Record<string, string> = {
  fido2: "Passkey (FIDO2)",
  windowsHelloForBusiness: "Windows Hello for Business",
  platformCredential: "Platform SSO (macOS)",
  x509Certificate: "Certificate (CBA)",
  microsoftAuthenticator: "Microsoft Authenticator",
  softwareOath: "Authenticator app code (OATH)",
  hardwareOath: "Hardware token (OATH)",
  phone: "Phone (SMS or call)",
  email: "Email (password reset only)",
  temporaryAccessPass: "Temporary Access Pass",
  password: "Password",
};

/** Methods that can't be replayed on a fake sign-in page: the key is bound to the real site or the device. */
export const PHISHING_RESISTANT = new Set<MethodKind>([
  "fido2", // passkeys, including passkeys in Microsoft Authenticator, and security keys
  "windowsHelloForBusiness",
  "platformCredential", // macOS Platform SSO with Secure Enclave
  "x509Certificate", // certificate-based authentication set to multifactor
]);
/** Second factors a user can be tricked into approving or typing into a fake page. */
export const PHISHABLE_MFA = new Set<MethodKind>([
  "microsoftAuthenticator",
  "passwordlessMicrosoftAuthenticator", // older type name for Authenticator phone sign-in
  "softwareOath",
  "hardwareOath",
  "phone",
]);

/** "#microsoft.graph.fido2AuthenticationMethod" -> "fido2" */
export const methodKind = (odataType: string): MethodKind =>
  odataType.replace(/^#?microsoft\.graph\./, "").replace(/AuthenticationMethod$/, "");

export function mfaLevel(u: Pick<PostureUser, "methods">): MfaLevel {
  if (u.methods.some((m) => PHISHING_RESISTANT.has(m))) return "phishing-resistant";
  if (u.methods.some((m) => PHISHABLE_MFA.has(m))) return "phishable";
  return "none";
}

const pct = (n: number, d: number) => (d ? Math.round((n / d) * 100) : 0);

export interface UserRow extends PostureUser {
  level: MfaLevel;
  admin: boolean;
}

export interface MfaReport {
  users: UserRow[];
  /** Enabled member accounts: the people the rollout is for. Guests do MFA in their home tenant. */
  members: UserRow[];
  guests: number;
  disabled: number;
  counts: Record<MfaLevel, number>;
  percent: Record<MfaLevel, number>;
  admins: UserRow[];
  adminsResistant: number;
  findings: Finding[];
  waves: Wave[];
}

export interface Wave {
  id: "admins" | "pilot" | "everyone";
  title: string;
  why: string;
  /** People in this wave who still need a phishing-resistant method. */
  todo: UserRow[];
  done: number;
}

const policyEntry = (s: PostureSnapshot, id: string) => s.methodsPolicy?.find((m) => m.id.toLowerCase() === id.toLowerCase());

export function mfaReport(s: PostureSnapshot): MfaReport {
  const users: UserRow[] = s.users.map((u) => ({ ...u, level: mfaLevel(u), admin: u.roles.length > 0 }));
  const members = users.filter((u) => u.enabled && !u.guest);
  const counts = { "phishing-resistant": 0, phishable: 0, none: 0 } as Record<MfaLevel, number>;
  for (const u of members) counts[u.level]++;
  const percent = { "phishing-resistant": pct(counts["phishing-resistant"], members.length), phishable: pct(counts.phishable, members.length), none: pct(counts.none, members.length) };
  const admins = members.filter((u) => u.admin);
  const adminsResistant = admins.filter((u) => u.level === "phishing-resistant").length;

  const f: Finding[] = [];
  const adminsNone = admins.filter((u) => u.level === "none");
  const adminsPhishable = admins.filter((u) => u.level === "phishable");
  if (adminsNone.length)
    f.push({
      severity: "critical",
      title: `${adminsNone.length} admin${adminsNone.length === 1 ? " has" : "s have"} no MFA method at all`,
      detail: `${adminsNone.slice(0, 5).map((u) => u.upn).join(", ")}${adminsNone.length > 5 ? " and more" : ""}. A stolen password is enough to take these accounts. Register a passkey for them first, using a Temporary Access Pass if they have nothing else.`,
      playbook: "mfa-phishing-resistant-rollout",
    });
  if (adminsPhishable.length)
    f.push({
      severity: "warn",
      title: `${adminsPhishable.length} admin${adminsPhishable.length === 1 ? " uses" : "s use"} only phishable MFA`,
      detail: `${adminsPhishable.slice(0, 5).map((u) => u.upn).join(", ")}${adminsPhishable.length > 5 ? " and more" : ""}. Push approvals, codes and SMS can all be relayed by a fake sign-in page (adversary-in-the-middle) or approved by a tired admin (MFA fatigue). Admins are wave 1 of the rollout.`,
      playbook: "mfa-phishing-resistant-rollout",
    });
  if (counts.none)
    f.push({
      severity: s.securityDefaults ? "info" : "warn",
      title: `${counts.none} of ${members.length} people have no MFA method registered`,
      detail: s.securityDefaults
        ? "Security defaults will ask them to register Microsoft Authenticator at their next sign-in (they get 14 days). Point them at a passkey instead."
        : "Nothing has made them register. Until they do, their password alone signs them in.",
      playbook: "mfa-phishing-resistant-rollout",
    });

  const fido = policyEntry(s, "Fido2");
  if (s.methodsPolicy && (!fido || fido.state !== "enabled"))
    f.push({
      severity: "warn",
      title: "Passkeys (FIDO2) are switched off in the authentication methods policy",
      detail: "Nobody can register a passkey or security key until it's on. Turn it on for a pilot group first: Authentication methods > Policies > Passkey (FIDO2). Free on every tenant.",
      playbook: "mfa-phishing-resistant-rollout",
    });
  else if (fido && !fido.targets.includes("all_users"))
    f.push({ severity: "info", title: "Passkeys are on for selected groups only", detail: `Targets: ${fido.targets.join(", ") || "none"}. Widen it as each rollout wave finishes.` });

  const sms = policyEntry(s, "Sms");
  const voice = policyEntry(s, "Voice");
  if (sms?.state === "enabled" || voice?.state === "enabled")
    f.push({
      severity: "info",
      title: `${[sms?.state === "enabled" && "SMS", voice?.state === "enabled" && "voice call"].filter(Boolean).join(" and ")} sign-in is still allowed`,
      detail: "Phone codes can be intercepted by SIM swap and relayed by fake sign-in pages. Plan to switch them off once everyone has a stronger method.",
    });

  if (s.securityDefaults === false)
    f.push({
      severity: "warn",
      title: "Security defaults are off",
      detail: "On Entra ID Free, security defaults are the only thing that makes people register and use MFA. If the tenant has P1, check that Conditional Access requires MFA for everyone instead (Federation 360 can't read Conditional Access on a Free tenant).",
    });

  const resistant = (u: UserRow) => u.level === "phishing-resistant";
  // Pilot: non-admins who already use Authenticator or another app, because moving them to a passkey is the smallest step.
  const nonAdmins = members.filter((u) => !u.admin);
  const pilotPool = nonAdmins.filter((u) => u.level === "phishable");
  const pilotSize = Math.max(1, Math.ceil(nonAdmins.length * 0.1));
  // People who already have a phishing-resistant method count as done in the pilot; they don't take a pilot place.
  const pilotTodo = pilotPool.slice(0, pilotSize);
  const pilotIds = new Set(pilotTodo.map((u) => u.id));
  const rest = nonAdmins.filter((u) => !pilotIds.has(u.id) && !resistant(u));
  const waves: Wave[] = [
    { id: "admins", title: "Wave 1: everyone with an admin role", why: "Admins are the accounts attackers want first, and there are few of them.", todo: admins.filter((u) => !resistant(u)), done: admins.filter(resistant).length },
    { id: "pilot", title: "Wave 2: pilot group (about 10% of people)", why: "People who already use an authenticator app, so moving to a passkey is a small step. They find the rough edges before everyone else.", todo: pilotTodo, done: nonAdmins.filter(resistant).length },
    { id: "everyone", title: "Wave 3: everyone else", why: "Once the pilot is smooth, widen the passkey policy to all users and run a registration campaign.", todo: rest, done: 0 },
  ];

  return { users, members, guests: users.filter((u) => u.guest).length, disabled: users.filter((u) => !u.enabled).length, counts, percent, admins, adminsResistant, findings: f, waves };
}

// ---------------------------------------------------------------- SSO coverage

export type SignInKind = "saml" | "oidc" | "password" | "linked" | "none";

export const SIGNIN_LABEL: Record<SignInKind, string> = {
  saml: "SAML SSO",
  oidc: "OpenID Connect SSO",
  password: "Password vault (not real SSO)",
  linked: "Link only (app has its own sign-in)",
  none: "Not known (no SSO mode set; often an OIDC app)",
};

export interface SsoRow {
  name: string;
  appId: string;
  spId: string;
  signIn: SignInKind;
  assignmentRequired: boolean;
  scim: boolean;
  owner: string;
  thirdParty: boolean;
  inventoryId?: string;
  findings: Finding[];
}

export interface SsoReport {
  rows: SsoRow[];
  total: number;
  sso: number;
  assigned: number;
  scim: number;
  percent: { sso: number; assigned: number; scim: number };
}

function signInKind(app: PostureApp, inv?: AppIntegration): SignInKind {
  const m = (app.ssoMode || "").toLowerCase();
  if (m === "saml") return "saml";
  if (m === "oidc") return "oidc";
  if (m === "password") return "password";
  if (m === "external" || m === "notsupported") return "linked";
  // preferredSingleSignOnMode is empty for most OIDC apps; the inventory knows better when the app was discovered or entered.
  if (inv?.protocol === "oidc" || inv?.protocol === "oauth") return "oidc";
  if (inv?.protocol === "saml") return "saml";
  return "none";
}

/** One row per enterprise app the snapshot found, joined to the inventory by app ID for SCIM and owner. */
export function ssoReport(s: PostureSnapshot, inventory: AppIntegration[]): SsoReport {
  const byAppId = new Map(inventory.filter((a) => a.discovery?.appId).map((a) => [a.discovery!.appId!.toLowerCase(), a]));
  const rows: SsoRow[] = s.apps
    .filter((a) => a.enabled)
    .map((a) => {
      const inv = byAppId.get(a.appId.toLowerCase());
      const signIn = signInKind(a, inv);
      const scim = inv?.provisioning === "scim";
      const f: Finding[] = [];
      if ((signIn === "saml" || signIn === "oidc" || signIn === "password") && !a.assignmentRequired)
        f.push({
          severity: a.thirdParty || signIn === "password" ? "warn" : "info",
          title: "Anyone in the tenant can sign in",
          detail: "Assignment required is off, so every user (and guest) gets a token for this app. Turn it on and assign the groups that need it: Enterprise applications > the app > Properties > Assignment required = Yes.",
        });
      if (signIn === "password")
        f.push({ severity: "warn", title: "Password vault, not single sign-on", detail: "The app still has its own password. Phishing-resistant MFA in Entra doesn't protect the app's own login page. Move it to SAML or OIDC if the vendor supports it." });
      if ((signIn === "saml" || signIn === "oidc") && !scim)
        f.push({ severity: "info", title: "No SCIM: leavers keep their account in the app", detail: "Single sign-on stops new sign-ins when an account is disabled, but the app account, its API tokens and any local password stay until someone removes them." });
      return { name: a.name, appId: a.appId, spId: a.spId, signIn, assignmentRequired: a.assignmentRequired, scim, owner: inv?.owner ?? "", thirdParty: a.thirdParty, inventoryId: inv?.id, findings: f };
    })
    .sort((x, y) => x.name.localeCompare(y.name));
  const total = rows.length;
  const sso = rows.filter((r) => r.signIn === "saml" || r.signIn === "oidc").length;
  const ssoRows = rows.filter((r) => r.signIn === "saml" || r.signIn === "oidc");
  const assigned = ssoRows.filter((r) => r.assignmentRequired).length;
  const scim = ssoRows.filter((r) => r.scim).length;
  return { rows, total, sso, assigned, scim, percent: { sso: pct(sso, total), assigned: pct(assigned, ssoRows.length), scim: pct(scim, ssoRows.length) } };
}

// ---------------------------------------------------------------- loading and portal links

/** Checks a pasted or dropped file is a posture snapshot. Throws a plain-words error otherwise. */
export function parsePosture(text: string): PostureSnapshot {
  let j: any;
  try {
    j = JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    throw new Error("That isn't JSON. Load the f360-posture.json file Export-F360Posture.ps1 saved.");
  }
  if (j?.format !== POSTURE_FORMAT) throw new Error(`That file isn't a posture scan (format is ${JSON.stringify(j?.format ?? null)}, expected "${POSTURE_FORMAT}"). Is it the Discover export instead?`);
  if (j.version !== 1) throw new Error(`Posture scan version ${j.version} is newer than this Federation 360. Update it and try again.`);
  if (!Array.isArray(j.users) || !Array.isArray(j.apps)) throw new Error("The posture scan is missing its users or apps list.");
  return { warnings: [], ...j } as PostureSnapshot;
}

export const PORTAL = {
  methodsPolicy: "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods",
  securityDefaults: "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Properties",
  registerMethods: "https://mysignins.microsoft.com/security-info",
  userMethods: (id: string) => `https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/UserAuthMethods/userId/${id}`,
  userAdmin: (id: string) => `https://admin.cloud.microsoft/#/users/:/UserDetails/${id}`,
  appProperties: (spId: string, appId: string) => `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Properties/objectId/${spId}/appId/${appId}`,
  appSso: (spId: string, appId: string) => `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/SingleSignOn/objectId/${spId}/appId/${appId}`,
};

const csvCell = (v: string | number) => {
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

/** The people in one rollout wave, for a pilot group import or an email list. */
export function waveCsv(w: Wave): string {
  const head = ["User principal name", "Display name", "Admin roles", "MFA today", "Methods registered"];
  const lines = w.todo.map((u) => [u.upn, u.name, u.roles.join("; "), LEVEL_LABEL[u.level], u.methods.map((m) => METHOD_LABEL[m] ?? m).join("; ")].map(csvCell).join(","));
  return [head.join(","), ...lines].join("\n") + "\n";
}

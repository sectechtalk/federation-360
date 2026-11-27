// How access ends, per app: the Entra settings that decide how long a person keeps getting in to an app after you
// disable them, plus what the app's vendor says about its own session ("declared"). Works from a read-only access
// snapshot (browser sign-in on the "How access ends" page, or access/Export-F360Access.ps1). Nothing here changes
// the tenant.
//
// Facts used here (checked against Microsoft Learn, 2026-11-24):
// - Access tokens default to a random 60 to 90 minutes. ID tokens and SAML tokens default to 60 minutes. A token
//   lifetime policy (assigned to the app, or the organization default) changes these. Delegated reads of the
//   policies need Policy.Read.All (works on Entra ID Free).
// - Conditional Access sign-in frequency, persistent browser session and the continuous access evaluation (CAE)
//   session control need Entra ID P1. Without a sign-in frequency policy, Entra uses a rolling 90-day window.
// - CAE only shortens access to resources that understand it: Microsoft Graph, Exchange Online, SharePoint Online and
//   Teams. A third-party SAML or OIDC app keeps accepting the access token or session it already has.
// - Entra provisioning (SCIM) runs on a schedule, about every 40 minutes, or at once with Provision on demand. The
//   job's schedule and status come from servicePrincipals/{id}/synchronization/jobs (Synchronization.Read.All).
// - Refresh tokens last 90 days (24 hours for single-page apps) and stop working when the account is disabled or its
//   sessions are revoked.
import type { AppIntegration, AppProfile, Finding, Severity } from "./types";

export const ACCESS_FORMAT = "f360-access";

export interface TokenPolicy {
  id: string;
  name: string;
  isOrganizationDefault: boolean;
  /** Minutes, when the policy sets them. Undefined means Entra's default for that token. */
  accessTokenMinutes?: number;
  idTokenMinutes?: number;
  samlTokenMinutes?: number;
  /** Service principal or application object IDs the policy is assigned to. */
  appliesTo: string[];
}

export interface CaPolicy {
  id: string;
  name: string;
  state: "enabled" | "disabled" | "enabledForReportingButNotEnforced";
  /** includeApplications / excludeApplications: app IDs, "All", "Office365", "None". */
  includeApps: string[];
  excludeApps: string[];
  /** Plain words, e.g. "All users" or "2 groups". */
  users: string;
  /** True when the policy targets all users (exclusions aside). Older files don't have it; read from users. */
  allUsers?: boolean;
  /** Minutes between forced sign-ins, or "everyTime". Undefined when the policy doesn't set it. */
  signInFrequency?: number | "everyTime";
  persistentBrowser?: "always" | "never";
  cae?: "strictEnforcement" | "disabled" | "strictLocation";
}

export interface SyncRun {
  began: string;
  ended?: string;
  state: string;
  error?: string;
}

export interface SyncJob {
  id: string;
  templateId: string;
  /** Minutes between cycles. */
  intervalMinutes?: number;
  scheduleState: string;
  /** NotConfigured, NotRun, Active, Paused, Quarantine. */
  status: string;
  lastRun?: SyncRun;
  lastSuccess?: string;
  quarantine?: { reason: string; since?: string; nextAttempt?: string };
  failures: number;
  /** Users the last run counted as in scope for provisioning. */
  inScope?: number;
}

export interface AccessApp {
  spId: string;
  appId: string;
  name: string;
  /** preferredSingleSignOnMode: saml, oidc, password, notSupported, or empty. */
  ssoMode: string;
  /** Null when the jobs couldn't be read. Empty when the app has no provisioning job. */
  syncJobs: SyncJob[] | null;
}

export interface AccessSnapshot {
  format: typeof ACCESS_FORMAT;
  version: 1;
  collectedAt: string;
  collector: "browser" | "powershell" | "sample";
  tenant: { id: string; name: string; domain: string };
  /** Null when the policies couldn't be read. */
  tokenPolicies: TokenPolicy[] | null;
  /** Null when Conditional Access couldn't be read (no P1, or no permission). See caNote. */
  caPolicies: CaPolicy[] | null;
  caNote?: string;
  apps: AccessApp[];
  warnings: string[];
  example?: boolean;
}

// ------------------------------------------------------------------ parsing

/** "PT40M", "PT1H30M", "P1D" -> minutes. */
export function isoMinutes(d: string | undefined | null): number | undefined {
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(String(d ?? "").trim());
  if (!m || !d || d === "P" || d === "PT") return undefined;
  return (+(m[1] ?? 0)) * 1440 + (+(m[2] ?? 0)) * 60 + (+(m[3] ?? 0)) + Math.round(+(m[4] ?? 0) / 60);
}

/** Token lifetime policy values: "8:00:00", "1.00:00:00", "00:30:00" -> minutes. */
export function timespanMinutes(s: string | undefined | null): number | undefined {
  const m = /^(?:(\d+)\.)?(\d{1,2}):(\d{2})(?::(\d{2}))?$/.exec(String(s ?? "").trim());
  if (!m) return undefined;
  return (+(m[1] ?? 0)) * 1440 + +m[2] * 60 + +m[3] + Math.round(+(m[4] ?? 0) / 60);
}

/** One tokenLifetimePolicy from Graph (definition is an array of JSON strings). */
export function parseTokenPolicy(p: any, appliesTo: string[]): TokenPolicy {
  let def: any = {};
  for (const d of p?.definition ?? []) {
    try {
      def = { ...def, ...(JSON.parse(d)?.TokenLifetimePolicy ?? {}) };
    } catch {
      /* a definition that isn't JSON */
    }
  }
  return {
    id: String(p?.id ?? ""),
    name: String(p?.displayName ?? "Token lifetime policy"),
    isOrganizationDefault: !!p?.isOrganizationDefault,
    accessTokenMinutes: timespanMinutes(def.AccessTokenLifetime),
    idTokenMinutes: timespanMinutes(def.IdTokenLifetime) ?? timespanMinutes(def.AccessTokenLifetime),
    samlTokenMinutes: timespanMinutes(def.SamlTokenLifetime) ?? timespanMinutes(def.AccessTokenLifetime),
    appliesTo,
  };
}

/** One conditionalAccessPolicy from Graph. */
export function parseCaPolicy(p: any): CaPolicy {
  const apps = p?.conditions?.applications ?? {};
  const u = p?.conditions?.users ?? {};
  const inc: string[] = u.includeUsers ?? [];
  const parts: string[] = [];
  if (inc.includes("All")) parts.push("All users");
  else {
    if (inc.length) parts.push(`${inc.length} user${inc.length === 1 ? "" : "s"}`);
    if (u.includeGroups?.length) parts.push(`${u.includeGroups.length} group${u.includeGroups.length === 1 ? "" : "s"}`);
    if (u.includeRoles?.length) parts.push(`${u.includeRoles.length} role${u.includeRoles.length === 1 ? "" : "s"}`);
    if (u.includeGuestsOrExternalUsers) parts.push("guests");
  }
  const exclusions = (u.excludeUsers?.length ?? 0) + (u.excludeGroups?.length ?? 0) + (u.excludeRoles?.length ?? 0);
  const s = p?.sessionControls ?? {};
  let signInFrequency: CaPolicy["signInFrequency"];
  if (s.signInFrequency?.isEnabled) {
    if (s.signInFrequency.frequencyInterval === "everyTime") signInFrequency = "everyTime";
    else if (s.signInFrequency.value) signInFrequency = s.signInFrequency.value * (s.signInFrequency.type === "days" ? 1440 : 60);
  }
  return {
    id: String(p?.id ?? ""),
    name: String(p?.displayName ?? "Conditional Access policy"),
    state: p?.state === "enabled" || p?.state === "disabled" ? p.state : "enabledForReportingButNotEnforced",
    includeApps: apps.includeApplications ?? [],
    excludeApps: apps.excludeApplications ?? [],
    users: (parts.join(", ") || "Nobody") + (exclusions ? ` (${exclusions} excluded)` : ""),
    allUsers: inc.includes("All"),
    signInFrequency,
    persistentBrowser: s.persistentBrowser?.isEnabled ? s.persistentBrowser.mode : undefined,
    cae: s.continuousAccessEvaluation?.mode,
  };
}

/** One synchronizationJob from Graph. */
export function parseSyncJob(j: any): SyncJob {
  const st = j?.status ?? {};
  const run = (x: any): SyncRun | undefined =>
    x?.timeBegan && !String(x.timeBegan).startsWith("0001") ? { began: x.timeBegan, ended: x.timeEnded ?? undefined, state: x.state ?? "", error: x.error?.message || x.error?.code || undefined } : undefined;
  const last = run(st.lastExecution);
  const ok = run(st.lastSuccessfulExecution);
  return {
    id: String(j?.id ?? ""),
    templateId: String(j?.templateId ?? ""),
    intervalMinutes: isoMinutes(j?.schedule?.interval),
    scheduleState: String(j?.schedule?.state ?? ""),
    status: String(st.code ?? "NotRun"),
    lastRun: last,
    lastSuccess: ok?.ended ?? ok?.began,
    quarantine: st.quarantine ? { reason: String(st.quarantine.reason ?? "Unknown"), since: st.quarantine.seriesBegan ?? st.quarantine.currentBegan, nextAttempt: st.quarantine.nextAttempt } : undefined,
    failures: Number(st.countSuccessiveCompleteFailures ?? 0),
    inScope: st.lastExecution?.countEntitledForProvisioning ?? undefined,
  };
}

export function parseAccess(text: string): AccessSnapshot {
  let j: any;
  try {
    j = JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    throw new Error("That file isn't JSON. Load the f360-access.json file that Export-F360Access.ps1 saved.");
  }
  if (j?.format !== ACCESS_FORMAT) throw new Error(`That isn't an access export (format should be "${ACCESS_FORMAT}"). Load f360-access.json.`);
  if (!Array.isArray(j.apps)) throw new Error("The access export has no apps list.");
  if (j.rawGraph) {
    // Export-F360Access.ps1 saves Graph's own objects; turn them into the same shape the browser scan makes.
    const { rawGraph: _raw, ...rest } = j;
    return {
      ...rest,
      tokenPolicies: Array.isArray(j.tokenPolicies) ? j.tokenPolicies.map((t: any) => parseTokenPolicy(t.policy ?? t, (t.appliesTo ?? []).map(String))) : null,
      caPolicies: Array.isArray(j.caPolicies) ? j.caPolicies.map(parseCaPolicy) : null,
      caNote: j.caNote ?? undefined,
      warnings: Array.isArray(j.warnings) ? j.warnings : [],
      apps: j.apps.map((a: any) => ({
        spId: String(a.spId ?? ""),
        appId: String(a.appId ?? ""),
        name: String(a.name ?? a.appId ?? ""),
        ssoMode: String(a.ssoMode ?? ""),
        syncJobs: Array.isArray(a.syncJobs) ? a.syncJobs.map(parseSyncJob) : null,
      })),
    };
  }
  return {
    ...j,
    tokenPolicies: Array.isArray(j.tokenPolicies) ? j.tokenPolicies : null,
    caPolicies: Array.isArray(j.caPolicies) ? j.caPolicies : null,
    warnings: Array.isArray(j.warnings) ? j.warnings : [],
    apps: j.apps.map((a: any) => ({ ...a, syncJobs: Array.isArray(a.syncJobs) ? a.syncJobs : null })),
  };
}

// ------------------------------------------------------------------ evaluation

/** Microsoft resources that honour CAE. Third-party apps don't. */
export const CAE_RESOURCES: Record<string, string> = {
  "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
  "00000002-0000-0ff1-ce00-000000000000": "Exchange Online",
  "00000003-0000-0ff1-ce00-000000000000": "SharePoint Online",
  "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe": "Microsoft Teams",
};

export const DEFAULTS = {
  accessTokenMin: 60,
  accessTokenMax: 90,
  idTokenMinutes: 60,
  samlTokenMinutes: 60,
  scimIntervalMinutes: 40,
  signInFrequencyDays: 90,
  refreshTokenDays: 90,
  caeMinutes: 15,
};

export interface Lifetime {
  /** Shortest and longest in minutes (the same unless Entra randomises). */
  min: number;
  max: number;
  source: "default" | "org-default" | "app-policy";
  policy?: string;
}

export interface ScimHealth {
  severity: Severity;
  label: string;
  detail: string;
  /** Worst case minutes from a disable to the SCIM push reaching the app on the normal schedule. */
  delayMinutes?: number;
}

export interface AccessRow {
  key: string;
  name: string;
  appId: string;
  spId: string;
  ssoMode: string;
  inventoryId?: string;
  accessToken: Lifetime;
  idToken: Lifetime;
  samlToken: Lifetime;
  /** Enabled policies that cover this app, and report-only ones (marked). */
  caPolicies: CaPolicy[];
  signInFrequency: { text: string; minutes?: number; source: "policy" | "default" | "not-read" };
  persistentBrowser: string;
  cae: { text: string; applies: boolean };
  scim: ScimHealth;
  syncJob?: SyncJob;
  profile?: AppProfile;
  findings: Finding[];
}

const fmtMin = (m: number) =>
  m % 1440 === 0 ? `${m / 1440} day${m === 1440 ? "" : "s"}` : m % 60 === 0 ? `${m / 60} hour${m === 60 ? "" : "s"}` : m > 90 ? `${Math.floor(m / 60)} h ${m % 60} min` : `${m} min`;
export const formatMinutes = fmtMin;
export const formatLifetime = (l: Lifetime) => (l.min === l.max ? fmtMin(l.min) : `${l.min} to ${l.max} min`);

function lifetime(snap: AccessSnapshot, ids: string[], pick: (p: TokenPolicy) => number | undefined, def: [number, number]): Lifetime {
  const pols = snap.tokenPolicies ?? [];
  const own = pols.find((p) => p.appliesTo.some((x) => ids.includes(x.toLowerCase())) && pick(p) !== undefined);
  if (own) return { min: pick(own)!, max: pick(own)!, source: "app-policy", policy: own.name };
  const org = pols.find((p) => p.isOrganizationDefault && pick(p) !== undefined);
  if (org) return { min: pick(org)!, max: pick(org)!, source: "org-default", policy: org.name };
  return { min: def[0], max: def[1], source: "default" };
}

/** Policies that cover this app (any users). Disabled policies are left out. */
export function policiesForApp(caPolicies: CaPolicy[], appId: string): CaPolicy[] {
  const id = appId.toLowerCase();
  return caPolicies.filter(
    (p) =>
      p.state !== "disabled" &&
      (p.includeApps.includes("All") || p.includeApps.some((x) => x.toLowerCase() === id)) &&
      !p.excludeApps.some((x) => x.toLowerCase() === id),
  );
}

const isAllUsers = (p: CaPolicy) => p.allUsers ?? /^All users/.test(p.users);

const ago = (iso: string, now: Date) => Math.round((now.getTime() - new Date(iso).getTime()) / 60000);

export function scimHealth(jobs: SyncJob[] | null, provisioning: AppIntegration["provisioning"] | undefined, now = new Date()): { health: ScimHealth; job?: SyncJob } {
  if (jobs === null) return { health: { severity: "info", label: "Not read", detail: "The provisioning job couldn't be read. It needs Synchronization.Read.All." } };
  const job = jobs.find((j) => j.status !== "NotConfigured") ?? jobs[0];
  if (!job) {
    return {
      health:
        provisioning === "scim"
          ? { severity: "warn", label: "No job in Entra", detail: "Inventory says this app uses SCIM, but Entra has no provisioning job for it. Leavers aren't removed automatically." }
          : { severity: "info", label: "No SCIM", detail: "No provisioning job. Accounts in the app are not removed when someone leaves; the app must check at sign-in or be cleaned by hand." },
    };
  }
  const interval = job.intervalMinutes ?? DEFAULTS.scimIntervalMinutes;
  const delayMinutes = interval + 5;
  if (job.status === "Quarantine")
    return { job, health: { severity: "critical", label: "Quarantined", detail: `Provisioning is in quarantine (${job.quarantine?.reason ?? "Unknown"}). Disables are NOT reaching the app until it's fixed.` } };
  if (job.status === "Paused" || job.scheduleState === "Paused" || job.scheduleState === "Disabled")
    return { job, health: { severity: "warn", label: "Paused", detail: "Provisioning is paused. Disables are not reaching the app; Provision on demand still works." } };
  if (job.status === "NotRun" || job.status === "NotConfigured" || !job.lastRun)
    return { job, health: { severity: "warn", label: "Never ran", detail: "The provisioning job exists but has never run a cycle." } };
  if (job.lastRun.state === "Failed")
    return { job, health: { severity: "warn", label: "Last cycle failed", detail: `The last cycle failed${job.lastRun.error ? `: ${job.lastRun.error}` : ""}. ${job.failures} failure${job.failures === 1 ? "" : "s"} in a row.`, delayMinutes } };
  if (job.lastSuccess && ago(job.lastSuccess, now) > interval * 3)
    return { job, health: { severity: "warn", label: "Behind", detail: `The last clean cycle was ${fmtMin(Math.max(1, ago(job.lastSuccess, now)))} ago, more than three cycles.`, delayMinutes } };
  return {
    job,
    health: {
      severity: job.lastRun.state === "EntryLevelErrors" ? "warn" : "ok",
      label: job.lastRun.state === "EntryLevelErrors" ? "Running, some errors" : "Healthy",
      detail: `Runs every ${fmtMin(interval)}. A disable reaches the app within about ${fmtMin(delayMinutes)}, or in seconds with Provision on demand.`,
      delayMinutes,
    },
  };
}

const lc = (s?: string) => (s ?? "").toLowerCase();

/** The inventory entry for an app in the snapshot, by app ID, service principal ID or SAML identifier. */
export function inventoryMatch(apps: AppIntegration[], a: { appId: string; spId: string; name: string }): AppIntegration | undefined {
  return (
    apps.find((x) => !x.example && lc(x.discovery?.servicePrincipalId) === lc(a.spId)) ??
    apps.find((x) => !x.example && a.appId && (lc(x.discovery?.appId) === lc(a.appId) || lc(x.oidc?.clientId) === lc(a.appId))) ??
    apps.find((x) => x.example && (lc(x.discovery?.appId) === lc(a.appId) || lc(x.oidc?.clientId) === lc(a.appId) || lc(x.name) === lc(a.name)))
  );
}

export function accessRow(snap: AccessSnapshot, a: AccessApp, inventory: AppIntegration[] = [], now = new Date()): AccessRow {
  const inv = inventoryMatch(inventory, a);
  const ids = [a.spId, a.appId].filter(Boolean).map(lc);
  const accessToken = lifetime(snap, ids, (p) => p.accessTokenMinutes, [DEFAULTS.accessTokenMin, DEFAULTS.accessTokenMax]);
  const idToken = lifetime(snap, ids, (p) => p.idTokenMinutes, [DEFAULTS.idTokenMinutes, DEFAULTS.idTokenMinutes]);
  const samlToken = lifetime(snap, ids, (p) => p.samlTokenMinutes, [DEFAULTS.samlTokenMinutes, DEFAULTS.samlTokenMinutes]);
  const findings: Finding[] = [];

  const ca = snap.caPolicies ? policiesForApp(snap.caPolicies, a.appId) : [];
  const enforced = ca.filter((p) => p.state === "enabled");
  let signInFrequency: AccessRow["signInFrequency"];
  if (!snap.caPolicies) signInFrequency = { text: "Not read", source: "not-read" };
  else {
    // What most people get comes from policies for all users; stricter policies for some people are noted after it.
    const forAll = enforced.filter(isAllUsers);
    const strictest = (ps: CaPolicy[]): number | undefined => {
      if (ps.some((p) => p.signInFrequency === "everyTime")) return 0;
      const mins = ps.map((p) => p.signInFrequency).filter((x): x is number => typeof x === "number");
      return mins.length ? Math.min(...mins) : undefined;
    };
    const words = (m: number) => (m === 0 ? "Every time" : `Every ${fmtMin(m)}`);
    const all = strictest(forAll);
    if (all !== undefined) signInFrequency = { text: words(all), minutes: all, source: "policy" };
    else signInFrequency = { text: `Rolling ${DEFAULTS.signInFrequencyDays} days (Entra default)`, minutes: DEFAULTS.signInFrequencyDays * 1440, source: "default" };
    const narrower = enforced.filter((p) => !isAllUsers(p) && p.signInFrequency !== undefined);
    const some = strictest(narrower);
    if (some !== undefined && (all === undefined || some < all))
      signInFrequency.text += `; ${words(some).toLowerCase()} for ${narrower.find((p) => (p.signInFrequency === "everyTime" ? 0 : p.signInFrequency) === some)?.users ?? "some people"}`;
  }
  const pb = enforced.map((p) => p.persistentBrowser).filter(Boolean);
  const persistentBrowser = !snap.caPolicies ? "Not read" : pb.includes("never") ? "Never (closes with the browser)" : pb.includes("always") ? "Always (survives closing the browser)" : "Not set (user's choice at sign-in)";

  const caeResource = CAE_RESOURCES[lc(a.appId)];
  const caeModes = enforced.map((p) => p.cae).filter(Boolean);
  const caeMode = caeModes.includes("disabled") ? "Turned off by policy" : caeModes.includes("strictEnforcement") ? "Strict enforcement" : caeModes.includes("strictLocation") ? "Strict location" : "On (default)";
  const cae = caeResource
    ? { text: `${caeMode}. ${a.name} honours CAE, so disabling the user ends access within minutes.`, applies: !caeModes.includes("disabled") }
    : { text: "Doesn't apply. Only Microsoft Graph, Exchange, SharePoint and Teams honour CAE; this app keeps the token or session it has.", applies: false };

  const { health: scim, job: syncJob } = scimHealth(a.syncJobs, inv?.provisioning, now);
  const profile = inv?.profile;

  if (accessToken.max > 24 * 60) findings.push({ severity: "warn", title: `Access tokens last ${formatLifetime(accessToken)}`, detail: `Set by ${accessToken.policy}. A disabled user keeps calling the API until it runs out.` });
  if (scim.severity === "critical" || scim.severity === "warn") findings.push({ severity: scim.severity, title: `Provisioning: ${scim.label}`, detail: scim.detail, playbook: "scim-leaver" });
  if (signInFrequency.source === "default" && (a.ssoMode === "saml" || a.ssoMode === "oidc"))
    findings.push({ severity: "info", title: "No sign-in frequency policy", detail: "People are rarely asked to sign in again, so the app's own session decides how long they stay in." });
  if (!profile?.sessionMinutes && (a.ssoMode === "saml" || a.ssoMode === "oidc"))
    findings.push({ severity: "info", title: "App session length not recorded", detail: "Entra can't see how long the app keeps someone signed in. Add it from the vendor's docs under Declared app profile." });
  if (profile?.sessionMinutes && (profile.endsSessionOnScimDisable === "no" || !syncJob))
    findings.push({
      severity: "warn",
      title: `The app keeps its own session for up to ${fmtMin(profile.sessionMinutes)} after a disable`,
      detail: syncJob
        ? "Declared from the vendor's docs: a SCIM disable doesn't end open sessions. Sign the user out in the app itself during offboarding."
        : "Declared from the vendor's docs, and there is no SCIM to tell the app. Sign the user out in the app itself during offboarding.",
    });

  return {
    key: a.spId || a.appId,
    name: a.name,
    appId: a.appId,
    spId: a.spId,
    ssoMode: a.ssoMode,
    inventoryId: inv?.id,
    accessToken,
    idToken,
    samlToken,
    caPolicies: ca,
    signInFrequency,
    persistentBrowser,
    cae,
    scim,
    syncJob,
    profile,
    findings,
  };
}

export interface AccessReport {
  rows: AccessRow[];
  counts: { apps: number; scim: number; scimProblems: number; customLifetimes: number; withProfile: number };
  findings: Finding[];
}

export function accessReport(snap: AccessSnapshot, inventory: AppIntegration[] = [], now = new Date()): AccessReport {
  const rows = snap.apps.map((a) => accessRow(snap, a, inventory, now)).sort((x, y) => x.name.localeCompare(y.name));
  const scimRows = rows.filter((r) => r.syncJob);
  const findings: Finding[] = [];
  const quarantined = rows.filter((r) => r.scim.severity === "critical");
  if (quarantined.length) findings.push({ severity: "critical", title: `${quarantined.length} provisioning job${quarantined.length === 1 ? " is" : "s are"} in quarantine`, detail: quarantined.map((r) => r.name).join(", ") + ". Disables don't reach these apps." });
  const stuck = rows.filter((r) => r.syncJob && r.scim.severity === "warn");
  if (stuck.length) findings.push({ severity: "warn", title: `${stuck.length} provisioning job${stuck.length === 1 ? " needs" : "s need"} attention`, detail: stuck.map((r) => `${r.name} (${r.scim.label})`).join(", ") });
  if (snap.caPolicies === null) findings.push({ severity: "info", title: "Conditional Access wasn't read", detail: snap.caNote ?? "Sign-in frequency and CAE need Entra ID P1 and Policy.Read.All. Entra's defaults are shown instead." });
  const longTokens = rows.filter((r) => r.accessToken.max > 24 * 60);
  if (longTokens.length) findings.push({ severity: "warn", title: `${longTokens.length} app${longTokens.length === 1 ? " has" : "s have"} access tokens longer than a day`, detail: longTokens.map((r) => r.name).join(", ") });
  return {
    rows,
    counts: {
      apps: rows.length,
      scim: scimRows.length,
      scimProblems: scimRows.filter((r) => r.scim.severity !== "ok").length,
      customLifetimes: rows.filter((r) => r.accessToken.source !== "default").length,
      withProfile: rows.filter((r) => r.profile?.sessionMinutes).length,
    },
    findings,
  };
}

/** Links that change each setting. */
export const ACCESS_PORTAL = {
  caPolicies: "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies",
  provisioning: (spId: string, appId: string) => `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/ProvisioningManagement/objectId/${spId}/appId/${appId}`,
  provisioningLogs: "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ProvisioningEventsBlade",
  app: (spId: string, appId: string) => `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/${spId}/appId/${appId}`,
  tokenLifetimeDocs: "https://learn.microsoft.com/entra/identity-platform/configurable-token-lifetimes",
};

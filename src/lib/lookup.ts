// User lookup: for one person, every app they can reach, how they got there, when they last used it, and how long
// they could still get in if you disabled them now (the offboarding exposure window). Combines:
//   - a per-user read from Entra (assignments direct and through groups, consent grants, devices, account state),
//     by browser sign-in, Export-F360UserAccess.ps1, or the sample
//   - the How access ends scan (token life, CAE, SCIM job health, declared app profile)
//   - the Activity summary (last sign-in, last silent refresh, SCIM results, account events)
// Nothing here changes the tenant.
//
// Exposure window, per app, if the account were disabled and its sessions revoked right now:
//   token left    = the access token issued at the person's last sign-in or refresh, until it expires
//                   (15 minutes at most when the app honours CAE). SAML apps get no token they keep using.
//   app session   = what's left of the app's own session (declared profile) since the last interactive sign-in;
//                   cut to the SCIM push time when the app ends sessions on a SCIM disable and SCIM is healthy.
//   window        = the longer of the two. Unknown when the app's session length isn't declared.
// Refresh tokens don't add to it: Entra refuses them once the account is disabled or sessions are revoked.
import { accessRow, DEFAULTS, formatMinutes, type AccessRow, type AccessSnapshot } from "./access";
import type { ActivitySummary, UserActivity, UserAppActivity } from "./activity";
import type { AppIntegration } from "./types";

export const USER_ACCESS_FORMAT = "f360-user-access";

export interface UserAssignment {
  spId: string;
  app: string;
  /** "direct", or the group's name when it comes through a group. */
  via: "direct" | "group";
  group?: string;
  /** App role ID; 00000000-... is "Default Access". */
  roleId: string;
  created?: string;
}

export interface UserGrant {
  /** The client app's service principal ID. */
  spId: string;
  app: string;
  /** Delegated scopes granted. */
  scope: string;
  /** Principal (the person consented for themselves) or AllPrincipals (an admin consented for everyone). */
  consentType: "Principal" | "AllPrincipals";
}

export interface UserDevice {
  id: string;
  name: string;
  os: string;
  /** AzureAd (joined), ServerAd (hybrid joined), Workplace (registered). */
  trustType: string;
  enabled: boolean;
}

export interface UserAccessSnapshot {
  format: typeof USER_ACCESS_FORMAT;
  version: 1;
  collectedAt: string;
  collector: "browser" | "powershell" | "sample";
  user: {
    id: string;
    upn: string;
    name: string;
    enabled: boolean;
    /** Sign-ins and refresh tokens issued before this are invalid (set by Revoke sessions, password change, disable). */
    sessionsValidFrom?: string;
    lastPasswordChange?: string;
    /** signInActivity (needs P1): last interactive and non-interactive sign-in. */
    lastSignIn?: string;
    lastNonInteractive?: string;
  };
  assignments: UserAssignment[];
  grants: UserGrant[];
  devices: UserDevice[];
  /** Service principal ID -> app ID, so assignments match the access scan and logs. */
  appIds: Record<string, string>;
  warnings: string[];
  example?: boolean;
}

export function parseUserAccess(text: string): UserAccessSnapshot {
  let j: any;
  try {
    j = JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    throw new Error("That file isn't JSON. Load the f360-user-access-<name>.json file Export-F360UserAccess.ps1 saved.");
  }
  if (j?.format !== USER_ACCESS_FORMAT) throw new Error(`That isn't a user access file (format should be "${USER_ACCESS_FORMAT}").`);
  if (!j.user?.upn && !j.user?.id) throw new Error("The user access file has no user in it.");
  return { assignments: [], grants: [], devices: [], appIds: {}, warnings: [], ...j };
}

// ------------------------------------------------------------------ rows

export type Exposure =
  | { kind: "none"; minutes: 0; why: string }
  | { kind: "minutes"; minutes: number; why: string; estimate: boolean }
  | { kind: "unknown"; atLeast: number; why: string };

export interface LookupRow {
  key: string;
  app: string;
  appId: string;
  spId: string;
  protocol: string;
  /** How the person can get in, in words: "Assigned directly", "Through group Sales", "Consented: Mail.Read". */
  access: string[];
  assigned: boolean;
  lastInteractive?: number;
  lastSilent?: number;
  lastFailure?: { time: number; code: number };
  scim: string;
  scimSeverity: "ok" | "info" | "warn" | "critical";
  /** The SCIM error or job detail, shown under the label. */
  scimDetail?: string;
  prtDevices: string[];
  /** Plain words about the person's current tokens. */
  tokens: string;
  exposure: Exposure;
  inventoryId?: string;
  access_row?: AccessRow;
  /** Flags for the Microsoft first-party / device code watch (option H). */
  watch: string[];
}

export interface LookupResult {
  user: { upn: string; name: string; id: string; enabled?: boolean; sessionsValidFrom?: number; disabledAt?: number; sessionsRevokedAt?: number };
  rows: LookupRow[];
  devices: UserDevice[];
  /** The longest known window, and whether any app is unknown. */
  longest?: LookupRow;
  unknownCount: number;
  sources: string[];
  warnings: string[];
}

const lc = (s?: string) => (s ?? "").toLowerCase();
const ts = (s?: string) => (s ? Date.parse(s) : undefined);
const DEFAULT_ROLE = "00000000-0000-0000-0000-000000000000";

/** Microsoft apps worth watching in one person's sign-ins (device code phishing, token theft tools). */
export const WATCH_APPS: Record<string, string> = {
  "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Microsoft Azure CLI",
  "1950a258-227b-4e31-a9cf-717495945fc2": "Microsoft Azure PowerShell",
  "14d82eec-204b-4c2f-b7e8-296a70dab67e": "Microsoft Graph Command Line Tools",
  "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
  "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Microsoft Teams",
  "29d9ed98-a469-4536-ade2-f981bc1d605e": "Microsoft Authentication Broker",
};

function userInSummary(sum: ActivitySummary | null, q: { upn?: string; id?: string; name?: string }): UserActivity | undefined {
  if (!sum) return undefined;
  const all = Object.values(sum.users);
  return (
    (q.upn && sum.users[lc(q.upn)]) ||
    all.find((u) => q.id && lc(u.id) === lc(q.id)) ||
    all.find((u) => q.upn && lc(u.upn) === lc(q.upn)) ||
    all.find((u) => q.name && lc(u.name) === lc(q.name)) ||
    undefined
  );
}

export function exposureFor(row: AccessRow | undefined, act: UserAppActivity | undefined, protocol: string, now: number, cutoff?: number): Exposure {
  const isSaml = protocol === "saml" || protocol === "saml20";
  // Revoking sessions or disabling the account stops new tokens, but a token already issued keeps working until it
  // expires. Without activity, the worst case is a sign-in just before the cutoff (or just now, if there was none).
  const lastToken = Math.max(act?.lastInteractive ?? 0, act?.lastSilent ?? 0) || undefined;
  const tokenFrom = lastToken ?? cutoff ?? now;
  const tokenMax = row ? row.accessToken.max : DEFAULTS.accessTokenMax;
  let estimate = !lastToken;
  let tokenLeft = 0;
  if (!isSaml) {
    tokenLeft = Math.max(0, Math.round((tokenFrom + tokenMax * 60000 - now) / 60000));
    if (row?.cae.applies && cutoff) tokenLeft = Math.min(tokenLeft, Math.max(0, Math.round((cutoff + DEFAULTS.caeMinutes * 60000 - now) / 60000)));
    else if (row?.cae.applies) tokenLeft = Math.min(tokenLeft, DEFAULTS.caeMinutes);
  }
  const tokenWhy = tokenLeft ? `access token ${row?.cae.applies ? "until CAE cuts it" : "until it expires"} (${formatMinutes(tokenLeft)}${estimate ? ", worst case" : ""})` : "";
  const profile = row?.profile;
  const session = profile?.sessionMinutes;
  if (!session) {
    if (!row && !act) return { kind: "unknown", atLeast: tokenLeft, why: "No access scan or activity for this app." };
    return { kind: "unknown", atLeast: tokenLeft, why: `The app's own session length isn't declared${tokenWhy ? `; at least the ${tokenWhy}` : ""}. Add it under Declared app profile in Inventory.` };
  }
  const sessionFrom = act?.lastInteractive ?? cutoff ?? now;
  if (!act?.lastInteractive) estimate = true;
  let sessionLeft = Math.max(0, Math.round((sessionFrom + session * 60000 - now) / 60000));
  let sessionWhy = sessionLeft ? `app session (${formatMinutes(sessionLeft)} left${act?.lastInteractive ? "" : ", worst case"})` : "";
  const prov = act?.provisioning;
  const scimDone = !!prov && prov.status === "success" && /disable|delete/i.test(prov.action) && (!cutoff || prov.time >= cutoff - 60000);
  if (sessionLeft && profile?.endsSessionOnScimDisable === "yes") {
    if (scimDone) {
      sessionLeft = 0;
      sessionWhy = "";
    } else if (row?.scim.delayMinutes !== undefined) {
      sessionLeft = Math.min(sessionLeft, row.scim.delayMinutes);
      sessionWhy = `app session until the SCIM disable arrives (about ${formatMinutes(sessionLeft)}; seconds with Provision on demand)`;
    }
  }
  const minutes = Math.max(tokenLeft, sessionLeft);
  if (!minutes) return { kind: "none", minutes: 0, why: scimDone ? "SCIM disabled the account in the app, which ends its sessions." : "No token or app session left from the last sign-in." };
  return { kind: "minutes", minutes, estimate, why: tokenLeft >= sessionLeft ? tokenWhy : sessionWhy };
}

export function lookupUser(opts: {
  query: string;
  snapshot?: UserAccessSnapshot | null;
  access?: AccessSnapshot | null;
  activity?: ActivitySummary | null;
  inventory?: AppIntegration[];
  now?: Date;
}): LookupResult | null {
  const now = (opts.now ?? new Date()).getTime();
  const snap = opts.snapshot ?? null;
  const act = userInSummary(opts.activity ?? null, { upn: snap?.user.upn || opts.query, id: snap?.user.id, name: opts.query });
  if (!snap && !act) return null;
  const inventory = opts.inventory ?? [];
  const access = opts.access ?? null;
  const sources: string[] = [];
  if (snap) sources.push(`Entra read of the account, ${new Date(snap.collectedAt).toLocaleString()}${snap.collector === "sample" ? " (made-up sample)" : ""}`);
  if (act) sources.push("Activity summary");
  if (access) sources.push(`How access ends scan, ${new Date(access.collectedAt).toLocaleString()}${access.example ? " (made-up sample)" : ""}`);

  const sessionsValidFrom = ts(snap?.user.sessionsValidFrom);
  const cutoff = Math.max(act?.sessionsRevokedAt ?? 0, act?.disabledAt ?? 0, snap?.user.enabled === false ? sessionsValidFrom ?? 0 : 0) || undefined;

  // Every app the person can reach or used, keyed by app ID when known.
  type Acc = { app: string; appId: string; spId: string; access: string[]; assigned: boolean; act?: UserAppActivity };
  const apps = new Map<string, Acc>();
  const keyFor = (appId: string, spId: string, name: string) => {
    if (appId) return lc(appId);
    const viaAccess = access?.apps.find((a) => (spId && lc(a.spId) === lc(spId)) || lc(a.name) === lc(name));
    return viaAccess?.appId ? lc(viaAccess.appId) : spId ? `sp:${lc(spId)}` : `name:${lc(name)}`;
  };
  const get = (appId: string, spId: string, name: string): Acc => {
    const k = keyFor(appId, spId, name);
    let a = apps.get(k);
    if (!a) {
      const ac = access?.apps.find((x) => (appId && lc(x.appId) === lc(appId)) || (spId && lc(x.spId) === lc(spId)) || lc(x.name) === lc(name));
      a = { app: name || ac?.name || appId, appId: appId || ac?.appId || "", spId: spId || ac?.spId || "", access: [], assigned: false };
      apps.set(k, a);
    }
    return a;
  };
  for (const as of snap?.assignments ?? []) {
    const a = get(snap?.appIds[as.spId] ?? "", as.spId, as.app);
    a.assigned = true;
    const role = as.roleId && as.roleId !== DEFAULT_ROLE ? " (app role)" : "";
    a.access.push(as.via === "direct" ? `Assigned directly${role}` : `Through group ${as.group ?? ""}${role}`.trim());
  }
  for (const g of snap?.grants ?? []) {
    const a = get(snap?.appIds[g.spId] ?? "", g.spId, g.app);
    a.access.push(g.consentType === "Principal" ? `Consented for themselves: ${g.scope}` : `Admin consent for everyone: ${g.scope}`);
  }
  for (const [, ua] of Object.entries(act?.apps ?? {})) {
    const a = get(ua.appId, "", ua.app);
    a.act = ua;
    if (!a.access.length && (ua.interactive || ua.silent)) a.access.push("Signed in (no assignment found)");
    else if (!a.access.length && ua.provisioning) a.access.push("Provisioned by SCIM (no current assignment)");
  }

  const rows: LookupRow[] = [...apps.entries()].map(([key, a]) => {
    const accApp = access?.apps.find((x) => (a.appId && lc(x.appId) === lc(a.appId)) || (a.spId && lc(x.spId) === lc(a.spId)) || lc(x.name) === lc(a.app));
    const row = access && accApp ? accessRow(access, accApp, inventory, new Date(now)) : undefined;
    const ua = a.act;
    const protocol = lc(row?.ssoMode) || (ua?.protocols.includes("saml20") ? "saml" : ua?.protocols[0] ? lc(ua.protocols[0]) : "");
    const lastToken = Math.max(ua?.lastInteractive ?? 0, ua?.lastSilent ?? 0) || undefined;
    let tokens: string;
    if (cutoff && (!lastToken || cutoff >= lastToken)) tokens = `Sessions ended ${new Date(cutoff).toLocaleString()}; refresh tokens no longer work.`;
    else if (!lastToken) tokens = "No sign-in in the loaded activity.";
    else if (protocol === "saml") tokens = "SAML: no token kept; the app's own session decides.";
    else {
      const tokenMax = row ? row.accessToken.max : DEFAULTS.accessTokenMax;
      const expires = lastToken + tokenMax * 60000;
      const live = expires > now ? `Access token likely valid until ${new Date(expires).toLocaleTimeString()}` : "Last access token has expired";
      const refresh = ua?.silent || /offline_access/i.test(a.access.join(" ")) ? `; refresh token likely live for up to ${DEFAULTS.refreshTokenDays} days` : "";
      tokens = live + refresh + ".";
    }
    const prov = ua?.provisioning;
    let scim = row ? row.scim.label : "Not scanned";
    let scimSeverity: LookupRow["scimSeverity"] = row ? row.scim.severity : "info";
    let scimDetail: string | undefined;
    if (prov) {
      scim = `Last SCIM ${prov.action}: ${prov.status}`;
      scimDetail = prov.error || undefined;
      scimSeverity = prov.status === "failure" ? "critical" : prov.status === "success" ? "ok" : "warn";
    }
    const watch: string[] = [];
    if (WATCH_APPS[lc(a.appId)]) watch.push(`Microsoft app: ${WATCH_APPS[lc(a.appId)]}`);
    if (ua?.protocols.some((p) => /devicecode/i.test(p))) watch.push("Signed in with a device code: check it was really them");
    if (ua?.protocols.some((p) => /ropc/i.test(p))) watch.push("Signed in with a password grant (ROPC): no MFA");
    const exposure = exposureFor(row, ua, protocol, now, cutoff);
    return {
      key,
      app: a.app,
      appId: a.appId,
      spId: a.spId || accApp?.spId || "",
      protocol,
      access: [...new Set(a.access)],
      assigned: a.assigned,
      lastInteractive: ua?.lastInteractive,
      lastSilent: ua?.lastSilent,
      lastFailure: ua?.lastFailure,
      scim,
      scimSeverity,
      scimDetail,
      prtDevices: ua?.prtDevices ?? [],
      tokens,
      exposure,
      inventoryId: row?.inventoryId,
      access_row: row,
      watch,
    };
  });

  const weight = (e: Exposure) => (e.kind === "unknown" ? 1e9 + e.atLeast : e.minutes);
  rows.sort((x, y) => weight(y.exposure) - weight(x.exposure) || x.app.localeCompare(y.app));
  const known = rows.filter((r) => r.exposure.kind === "minutes");
  return {
    user: {
      upn: snap?.user.upn || act?.upn || "",
      name: snap?.user.name || act?.name || "",
      id: snap?.user.id || act?.id || "",
      enabled: snap?.user.enabled,
      sessionsValidFrom,
      disabledAt: act?.disabledAt,
      sessionsRevokedAt: act?.sessionsRevokedAt,
    },
    rows,
    devices: snap?.devices ?? [],
    longest: known.sort((a, b) => (b.exposure as any).minutes - (a.exposure as any).minutes)[0],
    unknownCount: rows.filter((r) => r.exposure.kind === "unknown").length,
    sources,
    warnings: snap?.warnings ?? [],
  };
}

export const exposureText = (e: Exposure) =>
  e.kind === "none" ? "None" : e.kind === "unknown" ? (e.atLeast ? `At least ${formatMinutes(e.atLeast)}; app session unknown` : "Unknown") : `${formatMinutes(e.minutes)}${e.estimate ? " (worst case)" : ""}`;

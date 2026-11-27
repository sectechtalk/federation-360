// Identity detections as code. Each rule is a small pure function over normalised sign-in and audit events
// (events.ts), with its MITRE ATT&CK technique, the data it needs, known false positives, the playbook to respond
// with, and the same logic as a KQL query for Microsoft Sentinel / Log Analytics. Every rule has tests with events
// that must fire and events that must not (tests/detections.test.ts).
import type { Severity } from "../lib/types";
import type { LoadedLogs, SignInEvent } from "./events";

export interface Hit {
  rule: string;
  severity: Exclude<Severity, "ok">;
  user: string;
  time: number;
  title: string;
  evidence: string[];
}

export type Need = "signIns" | "audits" | "sessionIds" | "risk";

export interface Rule {
  id: string;
  title: string;
  /** MITRE ATT&CK technique, e.g. T1621. */
  attack: { id: string; name: string };
  summary: string;
  /** What has to be in the loaded logs for the rule to say anything. */
  needs: Need[];
  falsePositives: string;
  playbook: string;
  kql: string;
  run: (logs: LoadedLogs, earlier: Hit[]) => Hit[];
}

const MIN = 60_000;
const HOUR = 60 * MIN;
export const ERR = { success: 0, badPassword: 50126, mfaNotCompleted: 500121 } as const;

const at = (t: number) => new Date(t).toISOString().replace("T", " ").slice(0, 16) + " UTC";
const where = (e: SignInEvent) => [e.ip, [e.city, e.country].filter(Boolean).join(", ")].filter(Boolean).join(" ");

function byKey<T>(items: T[], key: (x: T) => string): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const x of items) {
    const k = key(x);
    if (!k) continue;
    m.set(k, [...(m.get(k) ?? []), x]);
  }
  return m;
}

/** Groups time-sorted events into bursts: each burst holds events no more than `window` after the burst's first. */
function bursts<T extends { time: number }>(items: T[], window: number): T[][] {
  const out: T[][] = [];
  let cur: T[] = [];
  for (const x of [...items].sort((a, b) => a.time - b.time)) {
    if (cur.length && x.time - cur[0].time > window) {
      out.push(cur);
      cur = [];
    }
    cur.push(x);
  }
  if (cur.length) out.push(cur);
  return out;
}

const ok = (e: SignInEvent) => e.errorCode === ERR.success;

// ---------------------------------------------------------------- rules

export const mfaFatigue: Rule = {
  id: "mfa-fatigue",
  title: "MFA fatigue: repeated MFA prompts denied or ignored",
  attack: { id: "T1621", name: "Multi-Factor Authentication Request Generation" },
  summary:
    "Someone has the user's password and keeps triggering MFA prompts, hoping the user taps Approve to make them stop. Fires on 3 or more MFA prompts that weren't completed within 10 minutes; critical when the same user then signs in successfully within an hour, or reports fraud.",
  needs: ["signIns"],
  falsePositives: "A user whose phone was offline or who kept dismissing prompts by mistake. Ask them; it's quick to rule out.",
  playbook: "incident-mfa-fatigue",
  kql: `SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "500121"
| summarize Denials = count(), IPs = make_set(IPAddress), First = min(TimeGenerated), Last = max(TimeGenerated)
    by UserPrincipalName, Window = bin(TimeGenerated, 10m)
| where Denials >= 3
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(1d) and ResultType == "0"
    | project UserPrincipalName, SuccessTime = TimeGenerated, SuccessIP = IPAddress
  ) on UserPrincipalName
| extend SucceededAfter = SuccessTime between (Last .. (Last + 1h))
| summarize Denials = max(Denials), IPs = take_any(IPs), SucceededAfter = max(toint(SucceededAfter)) by UserPrincipalName, First, Last
| extend Severity = iff(SucceededAfter == 1, "High", "Medium")`,
  run({ signIns }) {
    const hits: Hit[] = [];
    for (const [user, evs] of byKey(signIns, (e) => e.user)) {
      const denied = evs.filter((e) => e.errorCode === ERR.mfaNotCompleted);
      for (const b of bursts(denied, 10 * MIN)) {
        if (b.length < 3) continue;
        const last = b[b.length - 1];
        const after = evs.find((e) => ok(e) && e.time > last.time && e.time - last.time <= HOUR);
        const fraud = b.some((e) => /fraud/i.test(e.details));
        hits.push({
          rule: this.id,
          severity: after || fraud ? "critical" : "warn",
          user,
          time: b[0].time,
          title: after
            ? `${b.length} MFA prompts not completed, then a successful sign-in`
            : fraud
              ? `${b.length} MFA prompts not completed, and the user reported fraud`
              : `${b.length} MFA prompts not completed in ${Math.max(1, Math.round((last.time - b[0].time) / MIN))} minutes`,
          evidence: [
            ...b.map((e) => `${at(e.time)} MFA not completed from ${where(e)}${e.details ? ` (${e.details})` : ""}`),
            ...(after ? [`${at(after.time)} signed in successfully from ${where(after)} to ${after.app || "an app"}`] : []),
          ],
        });
      }
    }
    return hits;
  },
};

export const passwordSpray: Rule = {
  id: "password-spray",
  title: "Password spray: one address tries many accounts",
  attack: { id: "T1110.003", name: "Brute Force: Password Spraying" },
  summary:
    "An attacker tries one or two common passwords against many accounts from the same address, staying under each account's lockout limit. Fires when one IP address fails the password for 10 or more different users within an hour; critical when any account from that address then signs in.",
  needs: ["signIns"],
  falsePositives: "A shared office or VPN exit address after a password policy change, or a misconfigured app retrying with an old service account password.",
  playbook: "incident-account-takeover",
  kql: `SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "50126"
| summarize Users = dcount(UserPrincipalName), UserList = make_set(UserPrincipalName, 50), First = min(TimeGenerated), Last = max(TimeGenerated)
    by IPAddress, Window = bin(TimeGenerated, 1h)
| where Users >= 10
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(1d) and ResultType == "0"
    | project IPAddress, SuccessUser = UserPrincipalName, SuccessTime = TimeGenerated
  ) on IPAddress
| extend Compromised = iff(SuccessTime between (First .. (Last + 1h)), SuccessUser, "")
| summarize Users = max(Users), UserList = take_any(UserList), Compromised = make_set_if(Compromised, Compromised != "") by IPAddress, First, Last`,
  run({ signIns }) {
    const hits: Hit[] = [];
    for (const [ip, evs] of byKey(signIns, (e) => e.ip)) {
      const fails = evs.filter((e) => e.errorCode === ERR.badPassword);
      for (const b of bursts(fails, HOUR)) {
        const users = [...new Set(b.map((e) => e.user))];
        if (users.length < 10) continue;
        const last = b[b.length - 1];
        const wins = evs.filter((e) => ok(e) && e.time >= b[0].time && e.time - last.time <= HOUR);
        const winners = [...new Set(wins.map((e) => e.user))];
        hits.push({
          rule: this.id,
          severity: winners.length ? "critical" : "warn",
          user: winners.join(", ") || `${users.length} accounts`,
          time: b[0].time,
          title: winners.length ? `Password spray from ${ip}, and ${winners.length} account${winners.length === 1 ? "" : "s"} signed in` : `Password spray from ${ip} against ${users.length} accounts`,
          evidence: [
            `${b.length} wrong-password attempts from ${where(b[0])} between ${at(b[0].time)} and ${at(last.time)}`,
            `Accounts tried: ${users.slice(0, 12).join(", ")}${users.length > 12 ? ` and ${users.length - 12} more` : ""}`,
            ...wins.map((e) => `${at(e.time)} ${e.user} signed in successfully from the same address`),
          ],
        });
      }
    }
    return hits;
  },
};

export const bruteForceSuccess: Rule = {
  id: "brute-force-success",
  title: "Password guessed: many failures, then a successful sign-in",
  attack: { id: "T1110.001", name: "Brute Force: Password Guessing" },
  summary: "Fires when one user has 10 or more wrong-password attempts within an hour and then signs in successfully within the next hour. Critical: the password is probably known to someone else.",
  needs: ["signIns"],
  falsePositives: "A user who forgot a recently changed password and finally got it right, or a phone still syncing mail with the old password. The address and device usually make it obvious.",
  playbook: "incident-account-takeover",
  kql: `let failures = SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "50126"
| summarize Failures = count(), LastFailure = max(TimeGenerated), FailIPs = make_set(IPAddress)
    by UserPrincipalName, Window = bin(TimeGenerated, 1h)
| where Failures >= 10;
failures
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(1d) and ResultType == "0"
    | project UserPrincipalName, SuccessTime = TimeGenerated, SuccessIP = IPAddress, AppDisplayName
  ) on UserPrincipalName
| where SuccessTime between (LastFailure .. (LastFailure + 1h))`,
  run({ signIns }) {
    const hits: Hit[] = [];
    for (const [user, evs] of byKey(signIns, (e) => e.user)) {
      const fails = evs.filter((e) => e.errorCode === ERR.badPassword);
      for (const b of bursts(fails, HOUR)) {
        if (b.length < 10) continue;
        const last = b[b.length - 1];
        const win = evs.find((e) => ok(e) && e.time > last.time && e.time - last.time <= HOUR);
        if (!win) continue;
        const sameIp = b.some((e) => e.ip === win.ip);
        hits.push({
          rule: this.id,
          severity: "critical",
          user,
          time: b[0].time,
          title: `${b.length} wrong passwords, then signed in${sameIp ? " from the same address" : ""}`,
          evidence: [
            `${b.length} wrong-password attempts between ${at(b[0].time)} and ${at(last.time)} from ${[...new Set(b.map(where))].slice(0, 3).join("; ")}`,
            `${at(win.time)} signed in successfully from ${where(win)} to ${win.app || "an app"}`,
          ],
        });
      }
    }
    return hits;
  },
};

export const LEGACY_CLIENTS = [
  "Exchange ActiveSync", "IMAP4", "POP3", "Authenticated SMTP", "Exchange Web Services", "Other clients", "AutoDiscover",
  "Outlook Anywhere (RPC over HTTP)", "Offline Address Book", "Reporting Web Services", "Exchange Online PowerShell", "MAPI Over HTTP", "Universal Outlook",
];

export const legacyAuth: Rule = {
  id: "legacy-auth-success",
  title: "Legacy authentication succeeded (no MFA possible)",
  attack: { id: "T1078.004", name: "Valid Accounts: Cloud Accounts" },
  summary: "Old protocols such as IMAP, POP and SMTP AUTH send the password itself and can't do MFA, so they're how sprayed passwords get used. Fires on any successful sign-in through a legacy client.",
  needs: ["signIns"],
  falsePositives: "A printer, scanner or line-of-business app that still sends mail with SMTP AUTH. Move it to a connector or OAuth, then block legacy authentication.",
  playbook: "incident-account-takeover",
  kql: `SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| where ClientAppUsed in (${LEGACY_CLIENTS.map((c) => `"${c}"`).join(", ")})
| project TimeGenerated, UserPrincipalName, ClientAppUsed, AppDisplayName, IPAddress, Location`,
  run({ signIns }) {
    const hits: Hit[] = [];
    const legacy = signIns.filter((e) => ok(e) && LEGACY_CLIENTS.some((c) => c.toLowerCase() === e.client.toLowerCase()));
    for (const [user, evs] of byKey(legacy, (e) => e.user)) {
      const clients = [...new Set(evs.map((e) => e.client))];
      hits.push({
        rule: this.id,
        severity: "warn",
        user,
        time: evs[0].time,
        title: `Signed in with ${clients.join(", ")} (${evs.length} time${evs.length === 1 ? "" : "s"})`,
        evidence: evs.slice(0, 5).map((e) => `${at(e.time)} ${e.client} from ${where(e)}`),
      });
    }
    return hits;
  },
};

export const tokenReplay: Rule = {
  id: "token-replay",
  title: "Session token used from two countries",
  attack: { id: "T1550.001", name: "Use Alternate Authentication Material: Application Access Token" },
  summary:
    "When an attacker steals a session cookie or refresh token (for example with an adversary-in-the-middle phishing kit or infostealer malware), they reuse the user's existing session, so MFA isn't asked again. Fires when one sign-in session ID succeeds from two or more countries within 24 hours.",
  needs: ["signIns", "sessionIds"],
  falsePositives: "A VPN that exits in another country, or a user travelling by plane with the same laptop session. Check the device and whether the second country makes sense.",
  playbook: "incident-token-theft",
  kql: `union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0" and isnotempty(SessionId)
| extend Country = tostring(parse_json(tostring(LocationDetails)).countryOrRegion)
| where isnotempty(Country)
| summarize Countries = make_set(Country), IPs = make_set(IPAddress), First = min(TimeGenerated), Last = max(TimeGenerated)
    by SessionId, UserPrincipalName
| where array_length(Countries) >= 2 and Last - First <= 24h`,
  run({ signIns }) {
    const hits: Hit[] = [];
    for (const [session, evs] of byKey(signIns.filter((e) => ok(e) && e.country), (e) => e.session)) {
      for (const b of bursts(evs, 24 * HOUR)) {
        const countries = [...new Set(b.map((e) => e.country))];
        if (countries.length < 2) continue;
        const firstIn = (c: string) => b.find((e) => e.country === c)!;
        hits.push({
          rule: this.id,
          severity: "critical",
          user: [...new Set(b.map((e) => e.user))].join(", "),
          time: b[0].time,
          title: `One session used from ${countries.join(" and ")}`,
          evidence: [`Session ${session}`, ...countries.map((c) => `${at(firstIn(c).time)} first used from ${where(firstIn(c))}${firstIn(c).interactive ? "" : " (non-interactive: a token was reused)"} for ${firstIn(c).app || "an app"}`)],
        });
      }
    }
    return hits;
  },
};

export const SECURITY_INFO_ADDED = /registered security info|added security info|registered.*authentication method/i;

export const newCountryThenMfaChange: Rule = {
  id: "new-country-mfa-change",
  title: "New sign-in method added right after a sign-in from a new country",
  attack: { id: "T1098.005", name: "Account Manipulation: Device Registration" },
  summary:
    "After taking over an account, attackers add their own phone or authenticator so they keep access after a password reset. Fires when a user registers new security info within 2 hours of their first successful sign-in from a country the log hasn't seen them use before.",
  needs: ["signIns", "audits"],
  falsePositives: "A new starter setting up MFA, or a user who travelled and replaced a lost phone. The rule needs some earlier sign-ins for the user, so it stays quiet on someone it has no history for.",
  playbook: "incident-account-takeover",
  kql: `let changes = AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("User registered security info", "Admin registered security info")
| extend UserPrincipalName = tostring(TargetResources[0].userPrincipalName)
| project ChangeTime = TimeGenerated, UserPrincipalName, OperationName;
let firstSeen = SigninLogs
| where TimeGenerated > ago(30d) and ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize FirstSeen = min(TimeGenerated) by UserPrincipalName, Country;
changes
| join kind=inner firstSeen on UserPrincipalName
| where FirstSeen between ((ChangeTime - 2h) .. ChangeTime)`,
  run({ signIns, audits }) {
    const hits: Hit[] = [];
    const okByUser = byKey(signIns.filter((e) => ok(e) && e.country), (e) => e.user);
    for (const a of audits.filter((x) => SECURITY_INFO_ADDED.test(x.activity))) {
      const user = a.targetUser || a.actor;
      const evs = (okByUser.get(user) ?? []).sort((x, y) => x.time - y.time);
      const recent = evs.filter((e) => e.time <= a.time && a.time - e.time <= 2 * HOUR);
      for (const e of recent) {
        const before = evs.filter((x) => x.time < e.time);
        if (!before.length || before.some((x) => x.country === e.country)) continue;
        hits.push({
          rule: this.id,
          severity: "critical",
          user,
          time: e.time,
          title: `First sign-in from ${e.country}, then new security info ${Math.round((a.time - e.time) / MIN)} minutes later`,
          evidence: [
            `Earlier sign-ins from ${[...new Set(before.map((x) => x.country))].join(", ")}`,
            `${at(e.time)} signed in from ${where(e)}`,
            `${at(a.time)} ${a.activity}${a.actor && a.actor !== user ? ` (by ${a.actor})` : ""}`,
          ],
        });
        break;
      }
    }
    return hits;
  },
};

const RISKY = new Set(["medium", "high"]);
/** Changes an attacker makes to keep or widen access once inside an account. */
export const SENSITIVE_CHANGE =
  /user registered security info|admin registered security info|add member to role|add eligible member to role|add app role assignment|add delegated permission grant|add service principal credentials|update application.*certificates and secrets|add owner to (application|service principal)|reset password|change user password/i;
// App consent is left out on purpose: "App consent right after a suspicious sign-in" already covers it, risky sign-ins included.

export const riskySignIn: Rule = {
  id: "risky-signin",
  title: "Risky sign-in succeeded (Entra ID Protection rated it medium or high)",
  attack: { id: "T1078.004", name: "Valid Accounts: Cloud Accounts" },
  summary:
    "Entra ID Protection scores every sign-in for signs of an attacker: an anonymous or malicious IP address, impossible travel, a token or session that looks stolen, a password seen in a leak. This rule surfaces the ones it rated medium or high that still succeeded, so a person decides whether it was the user. Critical when Microsoft rated it high.",
  needs: ["signIns", "risk"],
  falsePositives: "A user on a new VPN, a hotel or airport network, or travelling. Ask them on a channel the attacker can't see, and check the IP address and device in the evidence.",
  playbook: "incident-account-takeover",
  kql: `SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0 and RiskLevelDuringSignIn in ("medium", "high")
| project TimeGenerated, UserPrincipalName, RiskLevelDuringSignIn, RiskState, RiskEventTypes_V2, IPAddress, Location, AppDisplayName
| order by TimeGenerated desc`,
  run({ signIns }) {
    const hits: Hit[] = [];
    for (const [user, evs] of byKey(signIns.filter((e) => ok(e) && RISKY.has(e.risk ?? "")), (e) => e.user)) {
      for (const day of bursts(evs, 24 * HOUR)) {
        const high = day.some((e) => e.risk === "high");
        hits.push({
          rule: this.id,
          severity: high ? "critical" : "warn",
          user,
          time: day[0].time,
          title: `${day.length} ${high ? "high" : "medium"}-risk sign-in${day.length === 1 ? "" : "s"} succeeded${day[0].country ? ` from ${[...new Set(day.map((e) => e.country).filter(Boolean))].join(", ")}` : ""}`,
          evidence: day.slice(0, 6).map((e) => `${at(e.time)} risk ${e.risk} · ${where(e) || "no address"} · ${e.app}${e.device ? ` · device ${e.device}` : ""}`),
        });
      }
    }
    return hits;
  },
};

export const riskyThenChange: Rule = {
  id: "risky-then-change",
  title: "Sensitive change right after a risky sign-in",
  attack: { id: "T1098", name: "Account Manipulation" },
  summary:
    "What turns a risky sign-in into an incident is what happens next: a new MFA method, a role, a delegated permission grant, new app credentials or a password change, by or to the same person. Fires when one of those audit events follows a medium or high-risk successful sign-in within 4 hours.",
  needs: ["signIns", "audits", "risk"],
  falsePositives: "A user who really did set up a new phone while on a flagged network. Confirm with them before containing, but treat a role or credential change as real until shown otherwise.",
  playbook: "incident-account-takeover",
  kql: `let risky = SigninLogs
| where TimeGenerated > ago(7d) and ResultType == 0 and RiskLevelDuringSignIn in ("medium", "high")
| project RiskyTime = TimeGenerated, UserPrincipalName = tolower(UserPrincipalName), RiskLevelDuringSignIn, IPAddress;
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("security info", "member to role", "app role assignment", "delegated permission grant", "service principal credentials", "Certificates and secrets", "owner to", "password")
| extend Actor = tolower(tostring(InitiatedBy.user.userPrincipalName)), Target = tolower(tostring(TargetResources[0].userPrincipalName))
| extend UserPrincipalName = iff(isnotempty(Target), Target, Actor)
| join kind=inner risky on UserPrincipalName
| where TimeGenerated between (RiskyTime .. RiskyTime + 4h)
| project TimeGenerated, UserPrincipalName, OperationName, RiskyTime, RiskLevelDuringSignIn, IPAddress`,
  run({ signIns, audits }) {
    const hits: Hit[] = [];
    const risky = signIns.filter((e) => ok(e) && RISKY.has(e.risk ?? ""));
    for (const a of audits.filter((x) => SENSITIVE_CHANGE.test(x.activity))) {
      for (const user of new Set([a.actor, a.targetUser].filter(Boolean))) {
        const prior = risky.filter((e) => e.user === user && a.time >= e.time && a.time - e.time <= 4 * HOUR).pop();
        if (!prior) continue;
        hits.push({
          rule: this.id,
          severity: "critical",
          user,
          time: a.time,
          title: `${a.activity}${a.target ? ` (${a.target})` : ""} ${Math.round((a.time - prior.time) / MIN)} minutes after a ${prior.risk}-risk sign-in`,
          evidence: [`${at(prior.time)} sign-in, risk ${prior.risk} · ${where(prior) || "no address"} · ${prior.app}`, `${at(a.time)} ${a.activity}${a.target ? `: ${a.target}` : ""}${a.actor && a.actor !== user ? ` (by ${a.actor})` : ""}`],
        });
        break;
      }
    }
    return hits;
  },
};

export const consentAfterSuspicious: Rule = {
  id: "consent-after-suspicious",
  title: "App consent right after a suspicious sign-in",
  attack: { id: "T1528", name: "Steal Application Access Token" },
  summary:
    "A common way to keep access after taking over an account is to consent to an app that reads mail or files; the app's refresh token keeps working after the password is reset. Fires when a user consents to an app within 24 hours after any other rule here flagged them.",
  needs: ["signIns", "audits"],
  falsePositives: "A user who genuinely added an app the same day they mistyped their password many times. Check the app on the OAuth grants page.",
  playbook: "oauth-user-consent",
  kql: `// Run after the other rules; joins their results (saved as a watchlist or table) with consent events.
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName == "Consent to application"
| extend UserPrincipalName = tolower(tostring(InitiatedBy.user.userPrincipalName)), App = tostring(TargetResources[0].displayName)
| project TimeGenerated, UserPrincipalName, App, Result`,
  run({ audits }, earlier) {
    const hits: Hit[] = [];
    const flagged = earlier.filter((h) => h.rule !== this.id);
    for (const a of audits.filter((x) => /consent to application/i.test(x.activity))) {
      const user = a.actor;
      const prior = flagged.find((h) => h.user.split(", ").includes(user) && a.time >= h.time && a.time - h.time <= 24 * HOUR);
      if (!prior) continue;
      hits.push({
        rule: this.id,
        severity: "critical",
        user,
        time: a.time,
        title: `Consented to ${a.target || "an app"} after: ${prior.title}`,
        evidence: [`${at(prior.time)} ${prior.title}`, `${at(a.time)} ${a.activity}: ${a.target || "unknown app"}`],
      });
    }
    return hits;
  },
};

/** In run order: consentAfterSuspicious reads the hits of the rules before it. */
export const RULES: Rule[] = [mfaFatigue, passwordSpray, bruteForceSuccess, legacyAuth, tokenReplay, newCountryThenMfaChange, riskySignIn, riskyThenChange, consentAfterSuspicious];

export interface RuleResult {
  rule: Rule;
  hits: Hit[];
  /** Set when the logs lack what the rule needs, so "no hits" doesn't read as "all clear". */
  missing?: string;
}

export function runDetections(logs: LoadedLogs): RuleResult[] {
  const all: Hit[] = [];
  const hasSessions = logs.signIns.some((e) => e.session);
  const hasRisk = logs.signIns.some((e) => e.risk);
  return RULES.map((rule) => {
    let missing: string | undefined;
    if (rule.needs.includes("signIns") && !logs.signIns.length) missing = "No sign-in logs loaded.";
    else if (rule.needs.includes("audits") && !logs.audits.length) missing = "Needs audit logs too (Entra audit logs, or Export-F360SignIns.ps1, which saves both).";
    else if (rule.needs.includes("sessionIds") && !hasSessions)
      missing = "These sign-ins have no session IDs. Graph v1.0 doesn't return them; use Export-F360SignIns.ps1 (Graph beta) or a Log Analytics export.";
    else if (rule.needs.includes("risk") && !hasRisk)
      missing = "These sign-ins have no risk level. Entra ID Protection fills it in only with Entra ID P2 (Microsoft 365 E5 and E7 include it); read them with Read from your tenant, Export-F360SignIns.ps1 or a Log Analytics export.";
    const hits = missing ? [] : rule.run.call(rule, logs, all);
    all.push(...hits);
    return { rule, hits, missing };
  });
}

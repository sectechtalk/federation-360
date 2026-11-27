// Investigate: one incident, every source, one timeline.
//
// Pulls together, for one person: sign-ins and audit events (Entra logs, Graph, Entity 360), Detections hits,
// Exchange evidence (inbox rules and message trace, as Exchange 360 and Exchange Online PowerShell export them) and
// any other file worth keeping (a HeatMap 360 scan, a screenshot export). Each step is tagged with its MITRE ATT&CK
// technique. Every file loaded is hashed (SHA-256) and listed in the chain of custody, so the evidence pack can be
// checked later. Nothing is uploaded; everything stays in this browser tab until the pack is downloaded.
import { readLogFile, type AuditEvent, type LoadedLogs, type SignInEvent } from "../detections/events";
import { RULES, SENSITIVE_CHANGE, type Hit } from "../detections/rules";

export type Tactic = "Initial Access" | "Credential Access" | "Persistence" | "Privilege Escalation" | "Defense Evasion" | "Collection" | "Lateral Movement";
export interface Technique {
  id: string;
  name: string;
  tactic: Tactic;
}

/** The techniques Investigate tags, with the tactic each is shown under. */
export const TECHNIQUES: Record<string, Technique> = {
  "T1078.004": { id: "T1078.004", name: "Valid Accounts: Cloud Accounts", tactic: "Initial Access" },
  T1110: { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  "T1110.001": { id: "T1110.001", name: "Brute Force: Password Guessing", tactic: "Credential Access" },
  "T1110.003": { id: "T1110.003", name: "Brute Force: Password Spraying", tactic: "Credential Access" },
  T1621: { id: "T1621", name: "Multi-Factor Authentication Request Generation", tactic: "Credential Access" },
  T1528: { id: "T1528", name: "Steal Application Access Token", tactic: "Credential Access" },
  "T1550.001": { id: "T1550.001", name: "Use Alternate Authentication Material: Application Access Token", tactic: "Lateral Movement" },
  T1098: { id: "T1098", name: "Account Manipulation", tactic: "Persistence" },
  "T1098.001": { id: "T1098.001", name: "Account Manipulation: Additional Cloud Credentials", tactic: "Persistence" },
  "T1098.003": { id: "T1098.003", name: "Account Manipulation: Additional Cloud Roles", tactic: "Privilege Escalation" },
  "T1098.005": { id: "T1098.005", name: "Account Manipulation: Device Registration", tactic: "Persistence" },
  "T1114.003": { id: "T1114.003", name: "Email Collection: Email Forwarding Rule", tactic: "Collection" },
  "T1564.008": { id: "T1564.008", name: "Hide Artifacts: Email Hiding Rules", tactic: "Defense Evasion" },
  T1566: { id: "T1566", name: "Phishing", tactic: "Initial Access" },
};
export const TACTIC_ORDER: Tactic[] = ["Initial Access", "Credential Access", "Persistence", "Privilege Escalation", "Defense Evasion", "Lateral Movement", "Collection"];

export type EventKind = "signin" | "audit" | "detection" | "inbox-rule" | "message";
export interface CaseEvent {
  time: number;
  kind: EventKind;
  /** Lower-case UPN or the key the source uses for the person (Entity 360 CSV rows use the display name). */
  user: string;
  title: string;
  detail: string;
  source: string;
  severity: "critical" | "warn" | "info";
  attack?: string;
  ip?: string;
  country?: string;
  device?: string;
  app?: string;
  /** True for steps worth a person's attention (failures, risk, sensitive changes, detection hits, hiding rules). */
  suspicious: boolean;
}

export interface InboxRule {
  mailbox: string;
  name: string;
  enabled: boolean;
  forwardTo: string[];
  deletes: boolean;
  moveTo: string;
  conditions: string;
}
export interface TraceMessage {
  time: number;
  sender: string;
  recipient: string;
  subject: string;
  status: string;
  fromIp: string;
}

export interface EvidenceFile {
  name: string;
  size: number;
  sha256: string;
  loadedAt: string;
  /** What Federation 360 recognised in it. */
  kind: string;
  records: number;
}

export interface CaseData {
  logs: LoadedLogs;
  hits: Hit[];
  rules: InboxRule[];
  messages: TraceMessage[];
  files: EvidenceFile[];
}
export const EMPTY_CASE: CaseData = { logs: { signIns: [], audits: [], sources: [] }, hits: [], rules: [], messages: [], files: [] };

const lower = (v: unknown) => String(v ?? "").trim().toLowerCase();
const arr = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : v ? [String(v)] : []).filter(Boolean);

export async function sha256(text: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------- reading files

/** Get-InboxRule | ConvertTo-Json (Exchange Online PowerShell), one rule or many. */
export function readInboxRules(j: any): InboxRule[] {
  const rows: any[] = Array.isArray(j) ? j : Array.isArray(j?.value) ? j.value : j ? [j] : [];
  return rows
    .filter((r) => r && typeof r === "object" && "Name" in r && ("ForwardTo" in r || "RedirectTo" in r || "DeleteMessage" in r || "MoveToFolder" in r || "MailboxOwnerId" in r))
    .map((r) => ({
      mailbox: lower(r.MailboxOwnerId ?? String(r.Identity ?? "").split("\\")[0]),
      name: String(r.Name),
      enabled: r.Enabled !== false,
      forwardTo: [...arr(r.ForwardTo), ...arr(r.ForwardAsAttachmentTo), ...arr(r.RedirectTo)],
      deletes: r.DeleteMessage === true || r.SoftDeleteMessage === true,
      moveTo: String(r.MoveToFolder ?? ""),
      conditions: [r.Description, arr(r.SubjectContainsWords).length && `subject contains ${arr(r.SubjectContainsWords).join(", ")}`, arr(r.BodyContainsWords).length && `body contains ${arr(r.BodyContainsWords).join(", ")}`, arr(r.From).length && `from ${arr(r.From).join(", ")}`]
        .filter(Boolean)
        .join("; ")
        .slice(0, 400),
    }));
}

/** Get-MessageTraceV2 / Get-MessageTrace | ConvertTo-Json, or Exchange 360's Trace a message export. */
export function readMessageTrace(j: any): TraceMessage[] {
  const rows: any[] = Array.isArray(j) ? j : Array.isArray(j?.value) ? j.value : Array.isArray(j?.messages) ? j.messages : [];
  return rows
    .filter((r) => r && (r.SenderAddress || r.senderAddress) && (r.RecipientAddress || r.recipientAddress))
    .map((r) => ({
      time: Date.parse(r.Received ?? r.received ?? r.ReceivedDateTime ?? ""),
      sender: lower(r.SenderAddress ?? r.senderAddress),
      recipient: lower(r.RecipientAddress ?? r.recipientAddress),
      subject: String(r.Subject ?? r.subject ?? ""),
      status: String(r.Status ?? r.status ?? ""),
      fromIp: String(r.FromIP ?? r.fromIP ?? r.fromIp ?? ""),
    }))
    .filter((m) => Number.isFinite(m.time));
}

/** A Detections export ("Export detections (JSON)"). */
function readHits(j: any): Hit[] | null {
  if (!j || !Array.isArray(j.hits) || !j.generatedAt) return null;
  return j.hits.filter((h: any) => h && h.rule && h.user && Number.isFinite(h.time));
}

/** Reads one file into the case. Files Federation 360 doesn't recognise are still hashed and kept as evidence. */
export async function addFile(c: CaseData, name: string, text: string, now = new Date()): Promise<{ data: CaseData; note: string }> {
  const hash = await sha256(text);
  if (c.files.some((f) => f.sha256 === hash)) return { data: c, note: `${name} is already in this case (same SHA-256).` };
  const file = (kind: string, records: number): EvidenceFile => ({ name, size: new TextEncoder().encode(text).length, sha256: hash, loadedAt: now.toISOString(), kind, records });
  let j: any = undefined;
  try {
    j = JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    /* CSV or another kind of file */
  }
  if (j !== undefined) {
    const hits = readHits(j);
    if (hits) return { data: { ...c, hits: [...c.hits, ...hits], files: [...c.files, file("Detections export", hits.length)] }, note: `${name}: ${hits.length} detection hits.` };
    const rules = readInboxRules(j);
    if (rules.length) return { data: { ...c, rules: [...c.rules, ...rules], files: [...c.files, file("Exchange inbox rules", rules.length)] }, note: `${name}: ${rules.length} inbox rules.` };
    const msgs = readMessageTrace(j);
    if (msgs.length) return { data: { ...c, messages: [...c.messages, ...msgs], files: [...c.files, file("Exchange message trace", msgs.length)] }, note: `${name}: ${msgs.length} messages.` };
  }
  try {
    const l = readLogFile(name, text);
    const n = l.signIns.length + l.audits.length;
    return {
      data: { ...c, logs: { signIns: [...c.logs.signIns, ...l.signIns].sort((a, b) => a.time - b.time), audits: [...c.logs.audits, ...l.audits].sort((a, b) => a.time - b.time), sources: [...c.logs.sources, ...l.sources] }, files: [...c.files, file(l.signIns.some((s) => s.from === "Entity 360") ? "Entity 360 timeline" : "Sign-in and audit logs", n)] },
      note: l.sources.join(" "),
    };
  } catch {
    const kind = /heatmap|hm-?360|scan/i.test(name) ? "HeatMap 360 scan (kept as evidence; scans leave out computer names, so it isn't joined to the timeline)" : "Other evidence (kept and hashed, not read)";
    return { data: { ...c, files: [...c.files, file(kind, 0)] }, note: `${name}: ${kind}.` };
  }
}

/** Adds logs read through Graph or carried over from Detections, recorded in the chain of custody like a file. */
export async function addLogs(c: CaseData, label: string, logs: LoadedLogs, hits: Hit[] = [], now = new Date()): Promise<CaseData> {
  const text = JSON.stringify({ signIns: logs.signIns, audits: logs.audits, hits });
  const hash = await sha256(text);
  if (c.files.some((f) => f.sha256 === hash)) return c;
  const file: EvidenceFile = { name: label, size: new TextEncoder().encode(text).length, sha256: hash, loadedAt: now.toISOString(), kind: hits.length ? "Logs and hits from Detections" : "Read through Graph", records: logs.signIns.length + logs.audits.length + hits.length };
  return {
    ...c,
    logs: { signIns: [...c.logs.signIns, ...logs.signIns].sort((a, b) => a.time - b.time), audits: [...c.logs.audits, ...logs.audits].sort((a, b) => a.time - b.time), sources: [...c.logs.sources, ...logs.sources] },
    hits: [...c.hits, ...hits],
    files: [...c.files, file],
  };
}

// ---------------------------------------------------------------- the timeline

const LEGACY = /imap|pop3?|smtp|exchange activesync|autodiscover|exchange web services|other clients|mapi/i;
const where = (e: SignInEvent) => [e.ip, [e.city, e.country].filter(Boolean).join(", ")].filter(Boolean).join(" ");

export function tagSignIn(e: SignInEvent): Pick<CaseEvent, "attack" | "severity" | "suspicious" | "title"> {
  const risky = e.risk === "medium" || e.risk === "high";
  if (e.errorCode === 50126) return { attack: "T1110", severity: "warn", suspicious: true, title: "Wrong password" };
  if (e.errorCode === 500121) return { attack: "T1621", severity: "warn", suspicious: true, title: "MFA prompt not completed" };
  if (e.errorCode === 0 && risky) return { attack: "T1078.004", severity: e.risk === "high" ? "critical" : "warn", suspicious: true, title: `Signed in, ${e.risk} risk` };
  if (e.errorCode === 0 && LEGACY.test(e.client)) return { attack: "T1078.004", severity: "warn", suspicious: true, title: `Signed in with legacy authentication (${e.client})` };
  if (e.errorCode === 0) return { severity: "info", suspicious: false, title: "Signed in" };
  return { severity: "info", suspicious: e.errorCode !== -1, title: e.errorCode === -1 ? "Sign-in failed (reason not in the file)" : `Sign-in failed (${e.errorCode})` };
}

export function tagAudit(a: AuditEvent): Pick<CaseEvent, "attack" | "severity" | "suspicious"> {
  const t = a.activity.toLowerCase();
  if (/security info/.test(t)) return { attack: "T1098.005", severity: "warn", suspicious: true };
  if (/member to role|eligible member to role/.test(t)) return { attack: "T1098.003", severity: "critical", suspicious: true };
  if (/consent to application|delegated permission grant/.test(t)) return { attack: "T1528", severity: "warn", suspicious: true };
  if (/service principal credentials|certificates and secrets/.test(t)) return { attack: "T1098.001", severity: "critical", suspicious: true };
  if (SENSITIVE_CHANGE.test(a.activity)) return { attack: "T1098", severity: "warn", suspicious: true };
  return { severity: "info", suspicious: false };
}

export function tagRule(r: InboxRule): Pick<CaseEvent, "attack" | "severity" | "suspicious" | "title"> {
  if (r.forwardTo.length) return { attack: "T1114.003", severity: "critical", suspicious: true, title: `Inbox rule "${r.name}" forwards mail to ${r.forwardTo.join(", ")}` };
  if (r.deletes || /rss|archive|conversation history|junk/i.test(r.moveTo)) return { attack: "T1564.008", severity: "critical", suspicious: true, title: `Inbox rule "${r.name}" ${r.deletes ? "deletes" : `moves mail to ${r.moveTo}`}` };
  return { severity: "info", suspicious: false, title: `Inbox rule "${r.name}"` };
}

const matches = (key: string, ...vals: string[]) => vals.some((v) => v && (v === key || v.split(", ").includes(key)));

/** Every step for one person, oldest first. Inbox rules have no time in Get-InboxRule; they are placed at `ruleTime`. */
export function buildTimeline(c: CaseData, user: string, ruleTime = Date.now()): CaseEvent[] {
  const u = lower(user);
  const out: CaseEvent[] = [];
  for (const e of c.logs.signIns.filter((x) => x.user === u)) {
    const t = tagSignIn(e);
    out.push({ time: e.time, kind: "signin", user: u, ...t, detail: [where(e), e.app, e.client, e.device && `device ${e.device}`, e.details].filter(Boolean).join(" · "), source: e.from ?? "Sign-in log", ip: e.ip, country: e.country, device: e.device, app: e.app });
  }
  for (const a of c.logs.audits.filter((x) => x.actor === u || x.targetUser === u)) {
    out.push({ time: a.time, kind: "audit", user: u, ...tagAudit(a), title: a.activity, detail: [a.target, a.actor !== u && a.actor ? `by ${a.actor}` : "", a.targetUser && a.targetUser !== u ? `to ${a.targetUser}` : ""].filter(Boolean).join(" · "), source: "Audit log" });
  }
  const seen = new Set<string>();
  for (const h of c.hits.filter((x) => matches(u, x.user))) {
    const key = `${h.rule}|${h.time}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const rule = RULES.find((r) => r.id === h.rule);
    out.push({ time: h.time, kind: "detection", user: u, title: h.title, detail: [rule?.title, ...h.evidence.slice(0, 3), h.evidence.length > 3 ? `and ${h.evidence.length - 3} more` : ""].filter(Boolean).join(" · "), source: "Detections", severity: h.severity === "critical" ? "critical" : "warn", attack: rule?.attack.id, suspicious: true });
  }
  for (const r of c.rules.filter((x) => x.mailbox === u || x.mailbox === u.split("@")[0])) {
    out.push({ time: ruleTime, kind: "inbox-rule", user: u, ...tagRule(r), detail: [r.enabled ? "Enabled" : "Disabled", r.conditions, "Get-InboxRule has no creation time; check the Exchange audit log (New-InboxRule) for when it was made"].filter(Boolean).join(" · "), source: "Exchange" });
  }
  for (const m of c.messages.filter((x) => x.recipient === u || x.sender === u)) {
    out.push({ time: m.time, kind: "message", user: u, title: m.recipient === u ? `Mail from ${m.sender}` : `Mail to ${m.recipient}`, detail: [m.subject && `"${m.subject}"`, m.status, m.fromIp && `from ${m.fromIp}`].filter(Boolean).join(" · "), source: "Exchange message trace", severity: "info", suspicious: false });
  }
  // Mail from outside the person's domain, delivered in the 24 hours before the first suspicious sign-in, may be the lure.
  const firstSignIn = out.filter((e) => e.kind === "signin" && e.suspicious).sort((a, b) => a.time - b.time)[0]?.time;
  const domain = u.split("@")[1] ?? "";
  if (firstSignIn)
    for (const e of out.filter((x) => x.kind === "message" && x.title.startsWith("Mail from"))) {
      const sender = e.title.slice("Mail from ".length);
      if (domain && !sender.endsWith(`@${domain}`) && e.time <= firstSignIn && firstSignIn - e.time <= 24 * 3_600_000 && /deliver/i.test(e.detail)) {
        Object.assign(e, { suspicious: true, severity: "warn", attack: "T1566", title: `Possible phishing lure: ${e.title}` });
      }
    }
  return out.sort((a, b) => a.time - b.time || a.kind.localeCompare(b.kind));
}

/** People in the case, most suspicious first, for the picker. */
export function casePeople(c: CaseData): { user: string; suspicious: number; events: number }[] {
  const users = new Set<string>([...c.logs.signIns.map((s) => s.user), ...c.logs.audits.flatMap((a) => [a.actor, a.targetUser]).filter((x) => x.includes("@")), ...c.hits.flatMap((h) => h.user.split(", ")), ...c.rules.map((r) => r.mailbox)].filter(Boolean));
  return [...users]
    .map((user) => {
      const t = buildTimeline(c, user);
      return { user, suspicious: t.filter((e) => e.suspicious).length, events: t.length };
    })
    .filter((p) => p.events)
    .sort((a, b) => b.suspicious - a.suspicious || b.events - a.events || a.user.localeCompare(b.user));
}

// ---------------------------------------------------------------- scope, severity, report

export type CaseSeverity = "Critical" | "High" | "Medium" | "Low";
export type Verdict = "Undetermined" | "True positive" | "Benign true positive" | "False positive";
export const VERDICTS: Verdict[] = ["Undetermined", "True positive", "Benign true positive", "False positive"];

export interface Scope {
  first?: number;
  last?: number;
  suspiciousIps: { ip: string; country: string; count: number; succeeded: boolean }[];
  countries: string[];
  apps: string[];
  devices: string[];
  techniques: Technique[];
  successAfterSuspicious: boolean;
}

export function scopeOf(t: CaseEvent[]): Scope {
  const sus = t.filter((e) => e.suspicious);
  const ips = new Map<string, { ip: string; country: string; count: number; succeeded: boolean }>();
  for (const e of sus.filter((x) => x.kind === "signin" && x.ip)) {
    const cur = ips.get(e.ip!) ?? { ip: e.ip!, country: e.country ?? "", count: 0, succeeded: false };
    cur.count++;
    if (/^Signed in/.test(e.title)) cur.succeeded = true;
    ips.set(e.ip!, cur);
  }
  // A clean sign-in from an address that also failed or was flagged counts as the attacker getting in.
  for (const e of t.filter((x) => x.kind === "signin" && x.title === "Signed in" && x.ip && ips.has(x.ip))) ips.get(e.ip!)!.succeeded = true;
  const ids = [...new Set(sus.map((e) => e.attack).filter(Boolean) as string[])];
  const signins = t.filter((e) => e.kind === "signin");
  return {
    first: sus[0]?.time,
    last: sus[sus.length - 1]?.time,
    suspiciousIps: [...ips.values()].sort((a, b) => Number(b.succeeded) - Number(a.succeeded) || b.count - a.count),
    countries: [...new Set(signins.map((e) => e.country).filter(Boolean) as string[])],
    apps: [...new Set(signins.filter((e) => /^Signed in/.test(e.title)).map((e) => e.app).filter(Boolean) as string[])],
    devices: [...new Set(signins.map((e) => e.device).filter(Boolean) as string[])],
    techniques: ids.map((id) => TECHNIQUES[id] ?? { id, name: id, tactic: "Initial Access" as Tactic }).sort((a, b) => TACTIC_ORDER.indexOf(a.tactic) - TACTIC_ORDER.indexOf(b.tactic)),
    successAfterSuspicious: [...ips.values()].some((x) => x.succeeded) || sus.some((e) => /^Signed in/.test(e.title)),
  };
}

/** A starting point for the person's judgement, with the reason. */
export function suggestSeverity(t: CaseEvent[], s: Scope): { severity: CaseSeverity; why: string } {
  const crit = t.filter((e) => e.suspicious && e.severity === "critical");
  const persistence = s.techniques.filter((x) => x.tactic === "Persistence" || x.tactic === "Privilege Escalation" || x.tactic === "Collection" || x.tactic === "Defense Evasion");
  if (crit.length && persistence.length) return { severity: "Critical", why: `The attacker got in and changed something to stay in or take data (${persistence.map((x) => x.id).join(", ")}).` };
  if (crit.length) return { severity: "High", why: `${crit.length} critical step${crit.length === 1 ? "" : "s"}, e.g. ${crit[0].title}.` };
  if (s.successAfterSuspicious) return { severity: "Medium", why: "A suspicious step was followed by a successful sign-in, but nothing shows the attacker changing anything yet." };
  if (t.some((e) => e.suspicious)) return { severity: "Low", why: "Attempts only: nothing shows a successful sign-in by the attacker." };
  return { severity: "Low", why: "Nothing suspicious in the loaded evidence." };
}

/** NIST SP 800-61 phases, with the identity steps for each. */
export const NIST_STEPS: { phase: string; steps: { id: string; text: string }[] }[] = [
  { phase: "Detection and analysis", steps: [
    { id: "scope", text: "Timeline and scope reviewed: first and last suspicious step, addresses, apps reached" },
    { id: "user", text: "Asked the person, on a channel the attacker can't see, whether the activity was theirs" },
    { id: "verdict", text: "Verdict and severity set, and escalated if High or Critical" },
  ] },
  { phase: "Containment", steps: [
    { id: "revoke", text: "Sessions revoked (refresh tokens stop working)" },
    { id: "disable", text: "Account disabled or password reset, depending on the verdict" },
    { id: "device", text: "Device isolated in Remediation 360, if a managed device was used by the attacker" },
  ] },
  { phase: "Eradication", steps: [
    { id: "methods", text: "Attacker's MFA methods removed" },
    { id: "grants", text: "Consent grants, app credentials and role changes made by the attacker removed" },
    { id: "rules", text: "Forwarding and hiding inbox rules removed" },
  ] },
  { phase: "Recovery", steps: [
    { id: "reenable", text: "Account re-enabled with a new password and a phishing-resistant method" },
    { id: "watch", text: "Watching the account for 14 days (Detections, one user only)" },
  ] },
  { phase: "Post-incident activity", steps: [
    { id: "lessons", text: "Root cause written down: how the attacker got in" },
    { id: "tune", text: "Detection rule or control gap fixed (e.g. MFA coverage, Conditional Access, consent policy)" },
  ] },
];

export interface CaseRecord {
  caseId: string;
  user: string;
  analyst: string;
  severity: CaseSeverity;
  verdict: Verdict;
  notes: string;
  done: Record<string, number>;
  containedAt?: number;
}

export function newCaseId(now = new Date()): string {
  const r = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `F360-${now.toISOString().slice(0, 10).replace(/-/g, "")}-${r}`;
}

/** The evidence pack's JSON: the case, the timeline, and the chain of custody with every file's SHA-256. */
export function evidencePack(rec: CaseRecord, c: CaseData, t: CaseEvent[], s: Scope, now = new Date()) {
  return {
    format: "f360-case",
    version: 1,
    caseId: rec.caseId,
    generatedAt: now.toISOString(),
    generatedBy: "Federation 360 Investigate (read-only)",
    analyst: rec.analyst,
    subject: rec.user,
    severity: rec.severity,
    verdict: rec.verdict,
    notes: rec.notes,
    containedAt: rec.containedAt ? new Date(rec.containedAt).toISOString() : null,
    scope: { ...s, first: s.first ? new Date(s.first).toISOString() : null, last: s.last ? new Date(s.last).toISOString() : null },
    nist: NIST_STEPS.map((p) => ({ phase: p.phase, steps: p.steps.map((x) => ({ step: x.text, doneAt: rec.done[x.id] ? new Date(rec.done[x.id]).toISOString() : null })) })),
    chainOfCustody: c.files.map((f) => ({ ...f, loadedBy: rec.analyst || "not given" })),
    timeline: t.map((e) => ({ ...e, time: new Date(e.time).toISOString() })),
  };
}

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);
const fmt = (t?: number) => (t ? new Date(t).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "none");

/** A one-page incident report for leadership, as a self-contained HTML file that prints cleanly. */
export function incidentReport(rec: CaseRecord, c: CaseData, t: CaseEvent[], s: Scope, packHash: string, now = new Date()): string {
  const sus = t.filter((e) => e.suspicious);
  const what = sus.length
    ? `Between ${fmt(s.first)} and ${fmt(s.last)}, ${sus.length} suspicious step${sus.length === 1 ? "" : "s"} were seen on ${rec.user}'s account${s.suspiciousIps.length ? ` from ${s.suspiciousIps.map((x) => `${x.ip}${x.country ? ` (${x.country})` : ""}`).slice(0, 4).join(", ")}` : ""}. ${s.successAfterSuspicious ? "The attacker appears to have signed in successfully." : "No successful sign-in by the attacker is shown."}`
    : `No suspicious activity was found for ${rec.user} in the evidence loaded.`;
  const rows = sus.slice(0, 40).map((e) => `<tr><td>${esc(fmt(e.time))}</td><td>${esc(e.title)}</td><td>${esc(e.attack ?? "")}</td><td>${esc(e.source)}</td></tr>`).join("");
  const steps = NIST_STEPS.map((p) => `<li><strong>${esc(p.phase)}</strong>: ${p.steps.map((x) => `${rec.done[x.id] ? "&#10003;" : "&#9744;"} ${esc(x.text)}${rec.done[x.id] ? ` (${esc(fmt(rec.done[x.id]))})` : ""}`).join("; ")}</li>`).join("");
  const files = c.files.map((f) => `<tr><td>${esc(f.name)}</td><td>${esc(f.kind)}</td><td class="mono">${esc(f.sha256)}</td></tr>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Incident ${esc(rec.caseId)}</title>
<style>body{font:14px/1.45 system-ui,Segoe UI,sans-serif;color:#111;max-width:900px;margin:24px auto;padding:0 16px}h1{font-size:20px;margin:0}h2{font-size:15px;margin:18px 0 6px;border-bottom:1px solid #ccc}table{border-collapse:collapse;width:100%;font-size:12px}td,th{border:1px solid #ccc;padding:3px 6px;text-align:left;vertical-align:top}.mono{font-family:Consolas,monospace;font-size:11px;word-break:break-all}.k{display:grid;grid-template-columns:140px 1fr;gap:2px 12px}.muted{color:#555}@media print{body{margin:0}}</style></head><body>
<h1>Security incident ${esc(rec.caseId)}: ${esc(rec.user)}</h1>
<p class="muted">Generated ${esc(fmt(now.getTime()))} by Federation 360 Investigate (read-only). Analyst: ${esc(rec.analyst || "not given")}.</p>
<div class="k"><strong>Severity</strong><span>${esc(rec.severity)}</span><strong>Verdict</strong><span>${esc(rec.verdict)}</span><strong>Contained</strong><span>${esc(rec.containedAt ? fmt(rec.containedAt) : "not yet")}</span><strong>ATT&amp;CK</strong><span>${esc(s.techniques.map((x) => `${x.id} ${x.name} (${x.tactic})`).join("; ") || "none")}</span><strong>Apps reached</strong><span>${esc(s.apps.join(", ") || "none")}</span><strong>Devices</strong><span>${esc(s.devices.join(", ") || "none recorded")}</span></div>
<h2>What happened</h2><p>${esc(what)}</p>${rec.notes ? `<p>${esc(rec.notes)}</p>` : ""}
<h2>Response (NIST SP 800-61 phases)</h2><ul>${steps}</ul>
<h2>Timeline of suspicious steps</h2>${rows ? `<table><tr><th>Time</th><th>Step</th><th>ATT&amp;CK</th><th>Source</th></tr>${rows}</table>${sus.length > 40 ? `<p class="muted">First 40 of ${sus.length}; the full timeline is in the evidence file.</p>` : ""}` : "<p>None.</p>"}
<h2>Evidence (chain of custody)</h2><table><tr><th>File</th><th>What it is</th><th>SHA-256</th></tr>${files}</table>
<p class="muted">Evidence file SHA-256: <span class="mono">${esc(packHash)}</span></p>
</body></html>`;
}

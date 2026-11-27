import { renderToStaticMarkup } from "react-dom/server";
import { Ctx, type AppCtx } from "../src/components/ui";
import Investigate from "../src/views/Investigate";
import { addFile, addLogs, buildTimeline, casePeople, EMPTY_CASE, evidencePack, incidentReport, readInboxRules, readMessageTrace, scopeOf, sha256, suggestSeverity, tagSignIn, type CaseData, type CaseRecord } from "../src/lib/investigate";
import { runDetections } from "../src/detections/rules";
import { cleanupRunbook, verifyContainment } from "../src/lib/incidentContain";
import { sampleIncidentFiles } from "../src/data/sampleIncident";

const BLAIR = "blair.ops@f360sample.onmicrosoft.com";
const GRAY = "gray.finance@f360sample.onmicrosoft.com";

async function sampleCase(): Promise<CaseData> {
  let d = EMPTY_CASE;
  for (const f of sampleIncidentFiles(new Date("2026-11-21T08:00:00Z"))) d = (await addFile(d, f.name, f.text, new Date("2026-11-21T08:05:00Z"))).data;
  return { ...d, hits: runDetections(d.logs).flatMap((r) => r.hits) };
}

describe("evidence files", () => {
  it("hashes every file with SHA-256, recognises each kind, and skips a file already in the case", async () => {
    expect(await sha256("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let d = await sampleCase();
    expect(d.files.map((f) => f.kind)).toEqual(["Sign-in and audit logs", "Exchange message trace", "Exchange inbox rules"]);
    expect(d.files.every((f) => /^[0-9a-f]{64}$/.test(f.sha256))).toBe(true);
    const again = await addFile(d, "copy.json", sampleIncidentFiles(new Date("2026-11-21T08:00:00Z"))[1].text);
    expect(again.note).toMatch(/already in this case/);
    d = (await addFile(d, "heatmap-scan-123.json.txt", "not json at all")).data;
    expect(d.files[d.files.length - 1].kind).toMatch(/^HeatMap 360 scan/);
  });
  it("reads Get-InboxRule and Get-MessageTraceV2 output", () => {
    expect(readInboxRules({ Name: "x", MailboxOwnerId: "A@b", ForwardTo: null, RedirectTo: ["c@d"], DeleteMessage: false })).toMatchObject([{ mailbox: "a@b", forwardTo: ["c@d"] }]);
    expect(readMessageTrace([{ Received: "2026-11-20T08:00:00Z", SenderAddress: "x@y", RecipientAddress: "A@b", Subject: "Hi", Status: "Delivered" }])).toMatchObject([{ recipient: "a@b", status: "Delivered" }]);
    expect(readInboxRules([{ hello: 1 }])).toEqual([]);
  });
  it("records Graph reads and Detections hand-offs in the chain of custody too", async () => {
    const d = await addLogs(EMPTY_CASE, "Graph read", { signIns: [], audits: [], sources: ["x"] }, []);
    expect(d.files).toMatchObject([{ name: "Graph read", kind: "Read through Graph" }]);
  });
});

describe("timeline, scope and severity", () => {
  it("builds Blair's incident: phishing mail, MFA fatigue, a sign-in that got in, consent, a forwarding rule", async () => {
    const d = await sampleCase();
    const t = buildTimeline(d, BLAIR, Date.parse("2026-11-21T08:05:00Z"));
    const sus = t.filter((e) => e.suspicious);
    expect(sus.map((e) => e.attack)).toEqual(expect.arrayContaining(["T1621", "T1528", "T1114.003"]));
    expect(t.find((e) => e.kind === "message" && /confirm your MFA device/.test(e.detail))).toMatchObject({ suspicious: true, attack: "T1566" });
    expect(t.find((e) => e.kind === "message" && /Team lunch/.test(e.detail))?.suspicious).toBe(false);
    const s = scopeOf(t);
    expect(s.suspiciousIps[0]).toMatchObject({ ip: "198.51.100.23", country: "NL", succeeded: true });
    expect(s.techniques.map((x) => x.tactic)).toEqual(expect.arrayContaining(["Initial Access", "Credential Access", "Collection"]));
    expect(suggestSeverity(t, s).severity).toBe("Critical");
  });
  it("puts Gray's role change after a high-risk sign-in as Privilege Escalation", async () => {
    const d = await sampleCase();
    const s = scopeOf(buildTimeline(d, GRAY));
    expect(s.techniques.map((x) => x.id)).toEqual(expect.arrayContaining(["T1078.004", "T1098.003"]));
  });
  it("lists people most suspicious first and rates attempts only as Low", async () => {
    const d = await sampleCase();
    const p = casePeople(d);
    expect(p[0].suspicious).toBeGreaterThan(0);
    expect(p.map((x) => x.user)).toContain(BLAIR);
    const quiet = buildTimeline(d, "harper.sales@f360sample.onmicrosoft.com").filter((e) => e.kind === "signin");
    expect(tagSignIn({ time: 0, user: "u", ip: "", country: "", city: "", interactive: true, app: "", client: "IMAP4", errorCode: 0, details: "", session: "" }).attack).toBe("T1078.004");
    expect(quiet.length).toBeGreaterThan(0);
  });
});

describe("evidence pack and report", () => {
  it("carries the case, NIST steps, chain of custody and timeline, and the report escapes what it shows", async () => {
    const d = await sampleCase();
    const t = buildTimeline(d, BLAIR);
    const s = scopeOf(t);
    const rec: CaseRecord = { caseId: "F360-20261121-TEST", user: BLAIR, analyst: "Sam <script>", severity: "Critical", verdict: "True positive", notes: "Push bombing", done: { revoke: Date.parse("2026-11-21T09:00:00Z") }, containedAt: Date.parse("2026-11-21T09:00:00Z") };
    const pack = evidencePack(rec, d, t, s, new Date("2026-11-21T10:00:00Z"));
    expect(pack).toMatchObject({ format: "f360-case", caseId: rec.caseId, verdict: "True positive", containedAt: "2026-11-21T09:00:00.000Z" });
    expect(pack.chainOfCustody).toHaveLength(3);
    expect(pack.chainOfCustody[0].loadedBy).toBe("Sam <script>");
    expect(pack.nist.find((p) => p.phase === "Containment")!.steps[0].doneAt).toBe("2026-11-21T09:00:00.000Z");
    const html = incidentReport(rec, d, t, s, "abc123");
    expect(html).toContain("Security incident F360-20261121-TEST");
    expect(html).toContain("Sam &lt;script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain("T1114.003");
  });
});

describe("contain and clean up", () => {
  it("writes a What-if-first clean-up runbook with the apps and rules from the case", () => {
    const ps = cleanupRunbook({ upn: "o'brien@x.example", tenantId: "11111111-2222-3333-4444-555555555555", since: Date.parse("2026-11-21T08:00:00Z"), apps: ["Northwind Meeting Notes"], inboxRules: [".."], caseId: "F360-X" });
    expect(ps).toContain("[string]$User = 'o''brien@x.example'");
    expect(ps).toContain("'Northwind Meeting Notes'");
    expect(ps).toContain("if (-not $Run) { $WhatIfPreference = $true");
    expect(ps).toContain("revokeSignInSessions");
    expect(ps).toContain("2026-11-21T08:00:00.000Z");
  });
  it("verifies: disabled, sessions revoked after containment, and no successful sign-ins since", async () => {
    const at = Date.parse("2026-11-21T09:00:00Z");
    const f = (async (u: string) =>
      new Response(JSON.stringify(u.includes("/users/") ? { accountEnabled: false, signInSessionsValidFromDateTime: "2026-11-21T09:01:00Z" } : { value: [] }))) as unknown as typeof fetch;
    expect((await verifyContainment("t", "a@b", at, f)).map((c) => c.good)).toEqual([true, true, true]);
    const g = (async (u: string) =>
      new Response(JSON.stringify(u.includes("/users/") ? { accountEnabled: true, signInSessionsValidFromDateTime: "2026-11-01T00:00:00Z" } : { value: [{ createdDateTime: "2026-11-21T09:30:00Z", ipAddress: "203.0.113.1", appDisplayName: "Outlook" }] }))) as unknown as typeof fetch;
    const bad = await verifyContainment("t", "a@b", at, g);
    expect(bad.map((c) => c.good)).toEqual([false, false, false]);
    expect(bad[2].result).toMatch(/203\.0\.113\.1/);
  });
});

test("the page opens empty with the ways to gather evidence and no case yet", () => {
  const ctx: AppCtx = { store: null, tenants: [], apps: [], loading: false, go: () => {}, params: {}, toast: () => {}, loadExamples: async () => {} } as AppCtx;
  const out = renderToStaticMarkup(<Ctx.Provider value={ctx}><Investigate /></Ctx.Provider>);
  expect(out).toContain("1. Gather evidence");
  expect(out).toContain("Load the sample incident");
  expect(out).toContain("Connect-F360SignInLogs.ps1");
  expect(out).not.toContain("3. Timeline");
});

import { readFileSync } from "node:fs";
import {
  cadenceRows, emptySummary, findUsers, foldActivity, median, percentile, readActivityFile, readEntity360Csv, toActivityProvisioning, toActivitySignIn,
} from "../src/lib/activity";
import { collectActivity } from "../src/lib/activityCollect";
import { sampleActivityFile } from "../src/data/sampleActivity";

const NOW = new Date("2026-11-24T12:00:00Z");
const sample = () => foldActivity(emptySummary(), readActivityFile("sample.json", JSON.stringify(sampleActivityFile(NOW))), NOW);

describe("reading sign-in rows", () => {
  it("tells the four tabs apart from Graph beta, v1.0, Log Analytics and the file name", () => {
    const base = { createdDateTime: "2026-11-24T10:00:00Z", appDisplayName: "App", appId: "A", userPrincipalName: "X@C.example", status: { errorCode: 0 } };
    expect(toActivitySignIn({ ...base, signInEventTypes: ["nonInteractiveUser"] })?.kind).toBe("nonInteractive");
    expect(toActivitySignIn({ ...base, isInteractive: false })?.kind).toBe("nonInteractive");
    expect(toActivitySignIn(base)?.kind).toBe("interactive");
    expect(toActivitySignIn(base, "nonInteractive")?.kind).toBe("nonInteractive");
    expect(toActivitySignIn({ ...base, userPrincipalName: "", servicePrincipalId: "sp", servicePrincipalName: "Daemon" })).toMatchObject({ kind: "servicePrincipal", user: "Daemon" });
    expect(toActivitySignIn({ TimeGenerated: "2026-11-24T10:00:00Z", Category: "AADNonInteractiveUserSignInLogs", AppDisplayName: "App", UserPrincipalName: "x@c.example", ResultType: "0", IncomingTokenType: "refreshToken" }))
      .toMatchObject({ kind: "nonInteractive", tokenType: "refreshToken", user: "x@c.example", success: true });
    const f = readActivityFile("NonInteractiveSignIns_2026-11-24.json", JSON.stringify([base]));
    expect(f.signIns[0].kind).toBe("nonInteractive");
    expect(f.sources[0]).toContain("1 silent refreshes");
  });

  it("reads provisioning rows from Graph and Log Analytics", () => {
    const g = toActivityProvisioning({ activityDateTime: "2026-11-24T10:00:00Z", provisioningAction: "disable", provisioningStatusInfo: { status: "failure", errorInformation: { reason: "401" } }, servicePrincipal: { id: "sp", displayName: "HR" }, sourceIdentity: { id: "u1", details: { UserPrincipalName: "A@b.example" } } });
    expect(g).toMatchObject({ action: "disable", status: "failure", app: "HR", user: "a@b.example", error: "401" });
    const la = toActivityProvisioning({ TimeGenerated: "2026-11-24T10:00:00Z", ProvisioningAction: "create", ProvisioningStatusInfo: '{"status":"success"}', ServicePrincipal: '{"displayName":"HR"}', SourceIdentity: '{"id":"u1","displayName":"a@b.example"}' });
    expect(la).toMatchObject({ action: "create", status: "success", user: "a@b.example" });
  });

  it("reads Entity 360's timeline CSV, keeping only sign-ins, with the user ID from the file name", () => {
    const id = "e1a2b3c4-0000-4000-8000-100000000002";
    const csv = '﻿"Time UTC","Activity","Category","Result","Source","Actor","Target","Direction","IP","Record ID"\r\n"2026-11-23T10:00:00Z","Partner Portal sign-in","Sign-ins","Success","signin","Sam Leaver","Partner Portal","Actor","203.0.113.1","r1"\r\n"2026-11-23T11:00:00Z","Update user","Changes","Success","audit","Alex","Sam","Target","","r2"';
    const rows = readEntity360Csv(`entity-360-timeline-${id}-2026-11-17.csv`, csv);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ app: "Partner Portal", userId: id, userName: "Sam Leaver", success: true });
    expect(readActivityFile(`entity-360-timeline-${id}-2026-11-17.csv`, csv).sources[0]).toContain("Entity 360");
  });

  it("refuses files it can't use, in plain words", () => {
    expect(() => readActivityFile("x.json", "nope")).toThrow(/isn't JSON or CSV/);
    expect(() => readActivityFile("x.json", '[{"a":1}]')).toThrow(/no sign-in, audit or provisioning/);
  });
});

describe("summary from the sample", () => {
  const sum = sample();

  it("counts each kind and keeps workloads apart from people", () => {
    expect(sum.counts.servicePrincipal).toBe(4);
    expect(sum.counts.managedIdentity).toBe(1);
    expect(Object.keys(sum.workloads)).toHaveLength(2);
    expect(Object.keys(sum.users)).toHaveLength(4);
  });

  it("per person and app: last interactive, last silent, protocol, PRT device, failures", () => {
    const gray = sum.users["gray.finance@contoso.example"];
    const partner = Object.values(gray.apps).find((a) => a.app === "Partner Portal")!;
    expect(partner.interactive).toBe(1);
    expect(partner.silent).toBeGreaterThan(50);
    expect(partner.protocols).toEqual(["oAuth2"]);
    expect(partner.prtDevices).toEqual(["GRAY-LAPTOP"]);
    const sam = sum.users["sam.leaver@contoso.example"];
    expect(Object.values(sam.apps).find((a) => a.app === "Expense Portal")?.lastFailure?.code).toBe(50057);
  });

  it("audit: disabled (Update user, AccountEnabled false), sessions revoked, removed from an app, consent", () => {
    const sam = sum.users["sam.leaver@contoso.example"];
    expect(sam.disabledAt).toBe(NOW.getTime() - 2 * 86400000);
    expect(sam.sessionsRevokedAt).toBeGreaterThan(sam.disabledAt!);
    expect(sam.removedFrom[0].app).toBe("Ticketing Desk");
    expect(sum.users["gray.finance@contoso.example"].consents[0].app).toBe("Northwind Meeting Notes");
  });

  it("provisioning lands on the person's app, latest wins", () => {
    const sam = sum.users["sam.leaver@contoso.example"];
    const hr = Object.values(sam.apps).find((a) => a.app === "HR Hub")!;
    expect(hr.provisioning).toMatchObject({ action: "disable", status: "failure" });
  });

  it("refresh cadence: Partner Portal about 75 minutes, Field Service about 8 hours", () => {
    const rows = cadenceRows(sum);
    const partner = rows.find((r) => r.app === "Partner Portal")!;
    expect(partner.medianMinutes).toBeGreaterThanOrEqual(72);
    expect(partner.medianMinutes).toBeLessThanOrEqual(78);
    expect(partner.users).toBe(3);
    expect(partner.reading).toMatch(/once per access token lifetime/);
    expect(rows.find((r) => r.app === "Field Service app")!.medianMinutes).toBe(480);
  });

  it("finds people by UPN, name or ID", () => {
    expect(findUsers(sum, "sam").map((u) => u.upn)).toEqual(["sam.leaver@contoso.example"]);
    expect(findUsers(sum, "Gray Fin")).toHaveLength(1);
    expect(findUsers(sum, "")).toEqual([]);
  });

  it("an Entity 360 file seen first by ID joins the UPN entry later", () => {
    const id = "e1a2b3c4-0000-4000-8000-100000000002";
    const csv = '"Time UTC","Activity","Category","Result","Source","Actor","Target","Direction","IP","Record ID"\n"2026-11-20T10:00:00Z","Wiki sign-in","Sign-ins","Success","signin","Sam Leaver","Wiki","Actor","",""';
    let s = foldActivity(emptySummary(), readActivityFile(`entity-360-timeline-${id}-2026-11-20.csv`, csv), NOW);
    expect(Object.keys(s.users)).toEqual([`id:${id}`]);
    s = foldActivity(s, readActivityFile("sample.json", JSON.stringify(sampleActivityFile(NOW))), NOW);
    expect(s.users[`id:${id}`]).toBeUndefined();
    expect(Object.values(s.users["sam.leaver@contoso.example"].apps).some((a) => a.app === "Wiki")).toBe(true);
  });

  it("stays small enough for browser storage", () => {
    expect(JSON.stringify(sum).length).toBeLessThan(60000);
  });
});

test("median and percentile", () => {
  expect(median([5, 1, 3])).toBe(3);
  expect(median([1, 2, 3, 4])).toBe(3);
  expect(median([])).toBeUndefined();
  expect(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 90)).toBe(9);
});

describe("browser collector", () => {
  it("reads all four tabs from beta, provisioning and audits from v1.0; stops sign-in reads after a 403", async () => {
    const calls: string[] = [];
    const get = async (p: string) => {
      calls.push(decodeURIComponent(p));
      if (p.includes("auditLogs/signIns")) throw Object.assign(new Error("403 Authentication_RequestFromNonPremiumTenantOrB2CTenant"), { status: 403 });
      if (p.startsWith("auditLogs/provisioning")) throw Object.assign(new Error("403 premium"), { status: 403 });
      if (p.startsWith("auditLogs/directoryAudits")) return { value: [{ activityDateTime: "2026-11-24T10:00:00Z", activityDisplayName: "Disable account", targetResources: [{ type: "User", userPrincipalName: "x@c.example" }] }] };
      return { value: [] };
    };
    const scan = await collectActivity(get, 7, () => {}, NOW);
    expect(calls.filter((c) => c.includes("signIns"))).toHaveLength(1);
    expect(calls[0]).toContain("https://graph.microsoft.com/beta/auditLogs/signIns");
    expect(calls[0]).toContain("createdDateTime ge 2026-11-17T12:00:00Z");
    expect(scan.warnings.some((w) => /P1/.test(w))).toBe(true);
    expect(scan.parsed.audits).toHaveLength(1);
  });
});

describe("Export-F360Activity.ps1", () => {
  const ps = readFileSync("activity/Export-F360Activity.ps1", "utf8");
  it("asks only for read-only scopes, uses only GET, and writes the export format", () => {
    expect(ps).toContain("@('AuditLog.Read.All', 'Directory.Read.All')");
    expect(ps).not.toMatch(/-Method (POST|PATCH|PUT|DELETE)/i);
    expect(ps).toContain("format = 'f360-activity-export'");
    for (const t of ["interactiveUser", "nonInteractiveUser", "servicePrincipal", "managedIdentity"]) expect(ps).toContain(`'${t}'`);
  });
});

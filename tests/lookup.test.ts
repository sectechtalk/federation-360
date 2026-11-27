import { readFileSync } from "node:fs";
import { exposureFor, exposureText, lookupUser, parseUserAccess } from "../src/lib/lookup";
import { collectUserAccess, LOOKUP_SCOPES } from "../src/lib/lookupCollect";
import { sampleUserAccess, SAMPLE_PEOPLE } from "../src/data/sampleUserAccess";
import { sampleAccess } from "../src/data/sampleAccess";
import { sampleActivityFile } from "../src/data/sampleActivity";
import { emptySummary, foldActivity, readActivityFile } from "../src/lib/activity";
import { accessRow } from "../src/lib/access";
import { exampleData } from "../src/data/seed";
const seedApps = () => exampleData().apps;

const now = new Date("2026-11-24T18:00:00Z");
const access = sampleAccess(now);
const activity = foldActivity(emptySummary(), readActivityFile("s.json", JSON.stringify(sampleActivityFile(now))), now);
const look = (who: string, withActivity = true) =>
  lookupUser({ query: who, snapshot: sampleUserAccess(who, now), access, activity: withActivity ? activity : null, inventory: seedApps(), now })!;

describe("User lookup", () => {
  it("returns null when nothing is known about the person", () => {
    expect(lookupUser({ query: "nobody@contoso.example", access, activity, now })).toBeNull();
  });

  it("lists every app Gray can reach, from assignments, groups, consents and activity", () => {
    const r = look(SAMPLE_PEOPLE[0]);
    const names = r.rows.map((x) => x.app);
    for (const n of ["Expense Portal", "AWS IAM Identity Center", "Partner Portal", "Ticketing Desk", "HR Hub", "Northwind Meeting Notes"]) expect(names).toContain(n);
    const aws = r.rows.find((x) => x.app === "AWS IAM Identity Center")!;
    expect(aws.access.join(" ")).toMatch(/Through group AWS Finance Readers \(app role\)/);
    const notes = r.rows.find((x) => x.app === "Northwind Meeting Notes")!;
    expect(notes.access.join(" ")).toMatch(/Consented for themselves/);
    expect(notes.tokens).toMatch(/refresh token likely live/);
    expect(r.user.enabled).toBe(true);
    expect(r.devices[0].name).toBe("GRAY-LAPTOP");
  });

  it("sorts unknown app sessions first, then the longest known exposure", () => {
    const r = look(SAMPLE_PEOPLE[0]);
    const kinds = r.rows.map((x) => x.exposure.kind);
    const firstKnown = kinds.findIndex((k) => k !== "unknown");
    expect(kinds.slice(firstKnown).includes("unknown")).toBe(false);
    const mins = r.rows.slice(firstKnown).map((x) => (x.exposure.kind === "minutes" ? x.exposure.minutes : 0));
    expect([...mins].sort((a, b) => b - a)).toEqual(mins);
    expect(r.unknownCount).toBe(kinds.filter((k) => k === "unknown").length);
    if (r.longest) expect(r.longest.exposure.kind).toBe("minutes");
  });

  it("shows Sam's sessions ended and the failed HR Hub SCIM disable", () => {
    const r = look(SAMPLE_PEOPLE[1]);
    expect(r.user.enabled).toBe(false);
    expect(r.user.disabledAt).toBeTruthy();
    for (const row of r.rows) {
      if (row.exposure.kind === "minutes") expect(row.exposure.minutes).toBeGreaterThan(0);
    }
    const hr = r.rows.find((x) => x.app === "HR Hub")!;
    expect(hr.scimSeverity).toBe("critical");
    expect(hr.scim).toMatch(/failure/);
    const partner = r.rows.find((x) => x.app === "Partner Portal")!;
    expect(partner.tokens).toMatch(/Sessions ended/);
  });

  it("works from activity alone when there is no Entra read", () => {
    const r = lookupUser({ query: "kai.eng@contoso.example", access, activity, now })!;
    expect(r.rows.some((x) => x.app === "Field Service app")).toBe(true);
    expect(r.rows.find((x) => x.app === "Field Service app")!.access).toContain("Signed in (no assignment found)");
  });
});

describe("exposureFor", () => {
  const app = access.apps.find((a) => a.name === "Partner Portal")!;
  const row = accessRow(access, app, seedApps(), now);
  const t = now.getTime();

  it("is unknown without a declared app session, and keeps the token time as a floor", () => {
    const e = exposureFor({ ...row, profile: undefined }, { lastInteractive: t - 10 * 60000 } as any, "oidc", t);
    expect(e.kind).toBe("unknown");
    if (e.kind === "unknown") expect(e.atLeast).toBeGreaterThan(0);
    expect(exposureText(e)).toMatch(/app session unknown/);
  });

  it("is none when SCIM disabled the user and the app ends sessions on it", () => {
    const cutoff = t - 60 * 60000;
    const e = exposureFor(
      { ...row, profile: { sessionMinutes: 480, endsSessionOnScimDisable: "yes", singleLogout: false, cae: "no", source: "test" } as any },
      { lastInteractive: t - 120 * 60000, provisioning: { action: "disable", status: "success", time: cutoff + 30 * 60000 } } as any,
      "saml",
      t,
      cutoff,
    );
    expect(e.kind).toBe("none");
  });

  it("counts the remaining app session when the app keeps it", () => {
    const e = exposureFor(
      { ...row, profile: { sessionMinutes: 480, endsSessionOnScimDisable: "no", singleLogout: false, cae: "no", source: "test" } as any },
      { lastInteractive: t - 60 * 60000 } as any,
      "saml",
      t,
    );
    expect(e).toMatchObject({ kind: "minutes", minutes: 420 });
  });
});

describe("parseUserAccess", () => {
  it("round-trips the sample and rejects other files", () => {
    const s = sampleUserAccess(SAMPLE_PEOPLE[0], now)!;
    expect(parseUserAccess(JSON.stringify(s)).user.upn).toBe(SAMPLE_PEOPLE[0]);
    expect(() => parseUserAccess(JSON.stringify({ format: "f360-access" }))).toThrow();
  });
});

describe("collectUserAccess", () => {
  it("reads the account, direct and group assignments, grants and devices with GET only", async () => {
    const calls: string[] = [];
    const data: Record<string, any> = {
      "users/x%40c.com?$select=id,displayName,userPrincipalName,accountEnabled,signInSessionsValidFromDateTime,lastPasswordChangeDateTime,signInActivity": { id: "u1", userPrincipalName: "x@c.com", displayName: "X", accountEnabled: true, signInActivity: { lastSignInDateTime: "2026-11-24T10:00:00Z" } },
      "users/u1/appRoleAssignments": { value: [{ resourceId: "sp1", resourceDisplayName: "App One", appRoleId: "00000000-0000-0000-0000-000000000000" }] },
      "users/u1/transitiveMemberOf/microsoft.graph.group?$select=id,displayName&$top=999": { value: [{ id: "g1", displayName: "Staff" }] },
      "groups/g1/appRoleAssignments": { value: [{ resourceId: "sp2", resourceDisplayName: "App Two", appRoleId: "00000000-0000-0000-0000-000000000000" }] },
      "users/u1/oauth2PermissionGrants": { value: [{ clientId: "sp3", scope: " Mail.Read ", consentType: "Principal" }] },
      "servicePrincipals/sp1?$select=id,appId,displayName": { appId: "a1", displayName: "App One" },
      "servicePrincipals/sp2?$select=id,appId,displayName": { appId: "a2", displayName: "App Two" },
      "servicePrincipals/sp3?$select=id,appId,displayName": { appId: "a3", displayName: "Notes" },
      "users/u1/registeredDevices?$select=id,displayName,operatingSystem,trustType,accountEnabled": { value: [{ id: "d1", displayName: "LAPTOP", operatingSystem: "Windows", trustType: "AzureAd", accountEnabled: true }] },
      "users/u1/ownedDevices?$select=id,displayName,operatingSystem,trustType,accountEnabled": { value: [{ id: "d1", displayName: "LAPTOP" }] },
    };
    const s = await collectUserAccess(async (p) => {
      calls.push(p);
      if (!(p in data)) throw Object.assign(new Error("404 " + p), { status: 404 });
      return data[p];
    }, "x@c.com");
    expect(s.user).toMatchObject({ id: "u1", upn: "x@c.com", enabled: true, lastSignIn: "2026-11-24T10:00:00Z" });
    expect(s.assignments.map((a) => `${a.app}:${a.via}`)).toEqual(["App One:direct", "App Two:group"]);
    expect(s.grants).toEqual([{ spId: "sp3", app: "Notes", scope: "Mail.Read", consentType: "Principal" }]);
    expect(s.appIds).toEqual({ sp1: "a1", sp2: "a2", sp3: "a3" });
    expect(s.devices).toHaveLength(1);
    expect(LOOKUP_SCOPES).toEqual(["Directory.Read.All", "AuditLog.Read.All"]);
  });

  it("falls back without signInActivity when P1 is missing", async () => {
    const s = await collectUserAccess(async (p) => {
      if (p.includes("signInActivity")) throw Object.assign(new Error("403"), { status: 403 });
      if (p.startsWith("users/x?")) return { id: "u1", userPrincipalName: "x", accountEnabled: false };
      return { value: [] };
    }, "x");
    expect(s.user.enabled).toBe(false);
    expect(s.warnings.join(" ")).toMatch(/P1/);
  });

  it("explains a missing user", async () => {
    await expect(collectUserAccess(async () => { throw Object.assign(new Error("nf"), { status: 404 }); }, "ghost")).rejects.toThrow(/No user ghost/);
  });
});

describe("Export-F360UserAccess.ps1", () => {
  const ps = readFileSync("lookup/Export-F360UserAccess.ps1", "utf8");
  it("asks only for read-only scopes, uses only GET, and writes the user access format", () => {
    expect(ps).toMatch(/Directory\.Read\.All/);
    expect(ps).toMatch(/AuditLog\.Read\.All/);
    expect(ps).not.toMatch(/-Method (POST|PATCH|PUT|DELETE)/i);
    expect(ps).not.toMatch(/ReadWrite/);
    expect(ps).toContain("format      = 'f360-user-access'");
    expect(ps).toMatch(/\[Parameter\(Mandatory\)\]\s*\[string\]\$User/);
  });
});

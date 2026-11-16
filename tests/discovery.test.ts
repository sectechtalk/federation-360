// The Entra mapper's own tests live in @sectechtalk/f360-collector. These cover f-360's side:
// that the package is wired in, the inventory merge and the health checks.
import { entraToSnapshot, makeSampleEntraExport } from "@sectechtalk/f360-collector";
import { planMerge, applyMerge } from "../src/lib/discovery/merge";
import { appHealth } from "../src/lib/health";
import { emptyOidc, emptySaml, type AppIntegration, type Tenant } from "../src/lib/types";

const now = new Date("2026-11-13T00:00:00Z");
const snap = () => entraToSnapshot(makeSampleEntraExport(now), now);
const byName = (n: string) => snap().apps.find((a) => a.name === n)!;

test("the shared collector package maps the sample tenant", () => {
  expect(snap().apps.map((a) => a.name)).toEqual([
    "Expense Mailbox Sync", "F360-LiveTest", "LAB-API", "LAB-Daemon", "LAB-OIDC-Playground", "LAB-SAML-App", "Northwind Chat", "Payroll Web",
  ]);
  expect(byName("LAB-SAML-App").saml.certExpires).toBe("2029-10-23");
});

const labTenant: Tenant = { id: "lab-tenant", name: "Federation 360 lab", platform: "entra", tenantRef: "5D3E9A72-6C41-4F0B-B2D8-7A19C4E6F031", domain: "", environment: "test", notes: "", updatedAt: "" };
const handApp = (over: Partial<AppIntegration>): AppIntegration => ({
  id: "lab-livetest", tenantId: "lab-tenant", name: "Live test (typed)", protocol: "oidc", environment: "test", owner: "Lab", status: "testing",
  provisioning: "none", saml: emptySaml(), oidc: emptyOidc(), notes: "my notes", updatedAt: "", ...over,
});

test("first scan into an empty inventory creates the tenant and every app", () => {
  const p = planMerge(snap(), [], [], now);
  expect(p.tenantIsNew).toBe(true);
  expect(p.tenant.id).toBe("entra-5d3e9a72-6c41-4f0b-b2d8-7a19c4e6f031");
  expect(p.creates).toHaveLength(8);
  expect(p.updates).toHaveLength(0);
});

test("adopts hand-entered apps by client ID and keeps the user's fields", () => {
  const s = snap();
  const live = s.apps.find((a) => a.name === "F360-LiveTest")!;
  const typed = handApp({ oidc: { ...emptyOidc(), clientId: live.discovery.appId!.toUpperCase() } });
  const p = planMerge(s, [labTenant], [typed], now);
  expect(p.tenantIsNew).toBe(false);
  const u = p.updates.find((x) => x.before.id === "lab-livetest")!;
  expect(u.adopted).toBe(true);
  expect(u.after).toMatchObject({ id: "lab-livetest", name: "F360-LiveTest", status: "testing", notes: "my notes", environment: "test" });
  expect(u.after.discovery?.externalId).toBe(`entra:${live.discovery.appId}`);
  expect(p.creates).toHaveLength(7);
});

test("adopts SAML apps by entity ID", () => {
  const typed = handApp({ id: "lab-saml", protocol: "saml", saml: { ...emptySaml(), entityId: "api://5d3e9a72-6c41-4f0b-b2d8-7a19c4e6f031/f360-lab-saml" } });
  const p = planMerge(snap(), [labTenant], [typed], now);
  expect(p.updates.find((x) => x.before.id === "lab-saml")?.after.saml.certThumbprint).toBe("3F2A9C1D7B6E5A4F3E2D1C0B9A8F7E6D5C4B3A29");
});

test("rescan: unchanged apps stay put, vanished apps are flagged missing, never deleted", async () => {
  const first = planMerge(snap(), [], [], now);
  const rows: Record<string, any> = {};
  await applyMerge({ put: async (_c, r) => void (rows[r.id] = r) }, first);
  const inv = Object.values(rows).filter((r) => r.protocol) as AppIntegration[];
  const tenants = Object.values(rows).filter((r) => r.platform) as Tenant[];
  const again = planMerge(snap(), tenants, inv, now);
  expect(again.creates).toHaveLength(0);
  expect(again.updates).toHaveLength(0);
  expect(again.unchanged).toHaveLength(8);

  const fewer = snap();
  fewer.apps = fewer.apps.filter((a) => a.name !== "Payroll Web");
  const third = planMerge(fewer, tenants, inv, now);
  expect(third.missing.map((m) => m.name)).toEqual(["Payroll Web"]);
  expect(third.missing[0].discovery?.missing).toBe(true);
});

test("health flags what discovery surfaces", () => {
  const p = planMerge(snap(), [], [], now);
  const get = (n: string) => appHealth(p.creates.find((a) => a.name === n)!, now).map((f) => f.title);
  expect(get("Payroll Web")).toEqual(expect.arrayContaining(["Wildcard redirect URI", "No owner recorded"]));
  expect(get("LAB-OIDC-Playground")).toContain("Implicit flow");
  expect(get("Payroll Web").some((t) => t.includes("expired"))).toBe(true);
});

test("a real scan never merges into fictional example entries", () => {
  const example: Tenant = { ...labTenant, id: "ex-t", example: true };
  const p = planMerge(snap(), [example], [], now);
  expect(p.tenantIsNew).toBe(true);
  const sample = planMerge(snap(), [example], [], now, { example: true });
  expect(sample.tenantIsNew).toBe(false);
  expect(sample.creates.every((a) => a.example)).toBe(true);
});

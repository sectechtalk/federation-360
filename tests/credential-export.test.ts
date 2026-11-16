import { readFileSync } from "node:fs";
import { entraToSnapshot, makeSampleEntraExport } from "@sectechtalk/f360-collector";
import { planMerge, applyMerge } from "../src/lib/discovery/merge";
import { exampleData } from "../src/data/seed";
import { assertNoSecretMaterial, buildCredentialsExport, CREDENTIALS_FORMAT } from "../src/lib/credentialExport";
import { emptyOidc, emptySaml, type AppIntegration, type Tenant } from "../src/lib/types";

const now = new Date("2026-11-13T00:00:00Z");

async function scannedInventory() {
  const raw = makeSampleEntraExport(now);
  // A real Graph export carries secret hints and certificate bodies; the export must never pass them on.
  raw.applications[0].passwordCredentials = [{ keyId: "k-hint", displayName: "has-hint", hint: "abc", secretText: "s3cr3t", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2027-01-01T00:00:00Z" }];
  const plan = planMerge(entraToSnapshot(raw, now), [], [], now);
  const rows: Record<string, any> = {};
  await applyMerge({ put: async (_c, r) => void (rows[r.id] = r) }, plan);
  return {
    apps: Object.values(rows).filter((r) => r.protocol) as AppIntegration[],
    tenants: Object.values(rows).filter((r) => r.platform) as Tenant[],
  };
}

test("one item per scanned credential, with type, app, tenant and dates", async () => {
  const { apps, tenants } = await scannedInventory();
  const x = buildCredentialsExport(tenants, apps, { now });
  expect(x.format).toBe(CREDENTIALS_FORMAT);
  expect(x.version).toBe(1);

  const payroll = x.items.filter((i) => i.app.name === "Payroll Web");
  expect(payroll.map((i) => [i.type, i.name, i.status])).toEqual([
    ["app-client-secret", "prod-2024", "expired"],
    ["app-client-secret", "never-rotated", "ok"],
  ]);
  expect(payroll[0]).toMatchObject({ daysLeft: -10, source: "tenant-scan", tenant: { id: "5d3e9a72-6c41-4f0b-b2d8-7a19c4e6f031", platform: "entra", domain: "f360sample.onmicrosoft.com" } });
  expect(payroll[0].createdAt).toBeTruthy();
  expect(payroll[0].manageUrl).toMatch(/^https:\/\/entra\.microsoft\.com\/#view\/Microsoft_AAD_RegisteredApps\/ApplicationMenuBlade\/~\/Credentials\/appId\/[0-9a-f-]{36}$/);

  const daemon = x.items.find((i) => i.app.name === "LAB-Daemon")!;
  expect(daemon).toMatchObject({ type: "app-certificate", status: "expiring", daysLeft: 21 });
  expect(daemon.thumbprint).toMatch(/^[0-9A-F]{40}$/);

  const saml = x.items.filter((i) => i.app.name === "LAB-SAML-App");
  expect(saml.every((i) => i.type === "saml-signing-certificate")).toBe(true);
  expect(saml).toHaveLength(2);
  expect(saml[0].manageUrl).toContain("ManagedAppMenuBlade/~/SignOn/objectId/");

  expect(x.counts.total).toBe(x.items.length);
  expect(x.items[0].status).toBe("expired");
});

test("IDs are stable across exports and contain no secret material", async () => {
  const a = await scannedInventory();
  const b = await scannedInventory();
  const ids = (s: typeof a) => buildCredentialsExport(s.tenants, s.apps, { now }).items.map((i) => i.id).sort();
  expect(ids(a)).toEqual(ids(b));
  expect(new Set(ids(a)).size).toBe(ids(a).length);

  const x = buildCredentialsExport(a.tenants, a.apps, { now });
  expect(() => assertNoSecretMaterial(x)).not.toThrow();
  const text = JSON.stringify(x);
  expect(text).not.toContain("s3cr3t");
  expect(text).not.toContain('"abc"');
  expect(x.items.some((i) => i.name === "has-hint")).toBe(true);
});

test("recorded dates fill in where there is no scan, and SCIM tokens always come from the record", () => {
  const tenant: Tenant = { id: "t1", name: "Lab", platform: "entra", tenantRef: "8f2b6c1e-0d4a-4a7e-9a51-3c0d2e7b9f10", domain: "contoso.onmicrosoft.com", environment: "test", notes: "", updatedAt: "2026-11-01T00:00:00Z" };
  const base = { tenantId: "t1", environment: "test" as const, owner: "", status: "live" as const, notes: "", updatedAt: "2026-11-01T00:00:00Z" };
  const apps: AppIntegration[] = [
    { ...base, id: "a1", name: "Hand SAML", protocol: "saml", provisioning: "scim", saml: { ...emptySaml(), certExpires: "2026-12-01", certThumbprint: "AB" }, oidc: emptyOidc(), scim: { endpoint: "https://x/scim", tokenExpires: "2026-11-01", matchAttribute: "userName", userNameSource: "upn" } },
    { ...base, id: "a2", name: "Hand OIDC", protocol: "oidc", provisioning: "none", saml: emptySaml(), oidc: { ...emptyOidc(), clientType: "confidential", clientId: "11111111-2222-3333-4444-555555555555", secretExpires: "2028-01-01" } },
    { ...base, id: "a3", name: "Public SPA", protocol: "oidc", provisioning: "none", saml: emptySaml(), oidc: { ...emptyOidc(), clientType: "public", secretExpires: "2028-01-01" } },
    { ...base, id: "a4", name: "SCIM no date", protocol: "saml", provisioning: "scim", saml: emptySaml(), oidc: emptyOidc(), scim: { endpoint: "", tokenExpires: "", matchAttribute: "", userNameSource: "" } },
  ];
  const x = buildCredentialsExport([tenant], apps, { now });
  const by = (id: string) => x.items.find((i) => i.id === id)!;
  expect(by("f360:recorded:a1:scim-token")).toMatchObject({ status: "expired", source: "recorded", daysLeft: -12 });
  expect(by("f360:recorded:a1:saml-signing-certificate")).toMatchObject({ status: "expiring", daysLeft: 18, thumbprint: "AB", expiresAt: "2026-12-01" });
  expect(by("f360:recorded:a2:app-credential")).toMatchObject({ status: "ok", app: { appId: "11111111-2222-3333-4444-555555555555" } });
  expect(by("f360:recorded:a2:app-credential").manageUrl).toContain("/Credentials/appId/11111111-2222-3333-4444-555555555555");
  expect(x.items.some((i) => i.app.f360Id === "a3")).toBe(false);
  expect(by("f360:recorded:a4:scim-token")).toMatchObject({ status: "unknown", daysLeft: null, expiresAt: null });
});

test("example data is left out unless asked for, and flagged when included", () => {
  const { tenants, apps } = exampleData();
  expect(buildCredentialsExport(tenants, apps, { now }).items).toHaveLength(0);
  const x = buildCredentialsExport(tenants, apps, { now, includeExamples: true });
  expect(x.items.length).toBeGreaterThan(0);
  expect(x.items.every((i) => i.example === true)).toBe(true);
});

test("the documented JSON Schema lists every field the builder writes", async () => {
  const schema = JSON.parse(readFileSync("node_modules/@sectechtalk/f360-collector/schema/f360-federation-credentials.v1.schema.json", "utf8"));
  const { apps, tenants } = await scannedInventory();
  const x = buildCredentialsExport(tenants, apps, { now, includeExamples: true });
  for (const k of Object.keys(x)) expect(schema.properties).toHaveProperty(k);
  const item = schema.$defs.item;
  for (const i of x.items) {
    for (const k of Object.keys(i)) expect(item.properties).toHaveProperty(k);
    for (const k of item.required) expect(i).toHaveProperty(k);
    expect(item.properties.type.enum).toContain(i.type);
    for (const k of Object.keys(i.app)) expect(item.properties.app.properties).toHaveProperty(k);
    for (const k of Object.keys(i.tenant)) expect(item.properties.tenant.properties).toHaveProperty(k);
  }
});

test("the Download credentials file and Copy JSON buttons are never disabled", () => {
  const src = readFileSync("src/views/Inventory.tsx", "utf8");
  for (const label of ["Download credentials file", "Copy JSON"]) {
    const line = src.split("\n").find((l) => l.includes(`>${label}</button>`))!;
    expect(line).toBeTruthy();
    expect(line).not.toMatch(/disabled=/);
  }
});

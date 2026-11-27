// A made-up access snapshot so the "How access ends" page shows every state before a real scan. The app IDs match the
// example inventory (data/seed.ts), so the example apps pick up their declared profiles.
import { ACCESS_FORMAT, type AccessSnapshot, type SyncJob } from "../lib/access";
import { EXAMPLE_TENANT_ID } from "./seed";

const sp = (n: number) => `e1a2b3c4-0000-4000-8000-${String(n).padStart(12, "0")}`;

export const SAMPLE_APP_IDS = {
  expenses: "7a1b2c3d-1111-4a2b-8c3d-000000000001",
  aws: "7a1b2c3d-1111-4a2b-8c3d-000000000002",
  partner: "5d1e2f3a-4b5c-4d6e-8f70-819203a4b5c6",
  field: "c3d4e5f6-0718-4293-a4b5-c6d7e8f90a1b",
  notes: "0b7e6c51-9a3d-4f2e-8c1b-5d4a3e2f1a09",
  ticketing: "7a1b2c3d-1111-4a2b-8c3d-000000000006",
  hr: "7a1b2c3d-1111-4a2b-8c3d-000000000007",
};

export function sampleAccess(now = new Date()): AccessSnapshot {
  const at = (minutesAgo: number) => new Date(now.getTime() - minutesAgo * 60000).toISOString();
  const healthy = (id: string, lastMinutesAgo: number, inScope: number): SyncJob => ({
    id,
    templateId: "scim",
    intervalMinutes: 40,
    scheduleState: "Active",
    status: "Active",
    lastRun: { began: at(lastMinutesAgo + 2), ended: at(lastMinutesAgo), state: "Succeeded" },
    lastSuccess: at(lastMinutesAgo),
    failures: 0,
    inScope,
  });
  return {
    format: ACCESS_FORMAT,
    version: 1,
    collectedAt: now.toISOString(),
    collector: "sample",
    tenant: { id: EXAMPLE_TENANT_ID, name: "Contoso (corporate)", domain: "contoso.example" },
    example: true,
    tokenPolicies: [
      {
        id: "tlp-1",
        name: "Field Service: 8-hour tokens",
        isOrganizationDefault: false,
        accessTokenMinutes: 480,
        idTokenMinutes: 480,
        samlTokenMinutes: 480,
        appliesTo: [sp(4)],
      },
    ],
    caPolicies: [
      { id: "ca-1", name: "Require MFA for all users", state: "enabled", includeApps: ["All"], excludeApps: [], users: "All users (1 excluded)" },
      {
        id: "ca-2",
        name: "Finance apps: sign in every 12 hours, no persistent browser",
        state: "enabled",
        includeApps: [SAMPLE_APP_IDS.expenses, SAMPLE_APP_IDS.hr],
        excludeApps: [],
        users: "All users",
        signInFrequency: 720,
        persistentBrowser: "never",
      },
      { id: "ca-3", name: "Strict CAE for Microsoft 365 (report-only)", state: "enabledForReportingButNotEnforced", includeApps: ["Office365"], excludeApps: [], users: "All users", cae: "strictEnforcement" },
      { id: "ca-4", name: "Admins: sign in every time", state: "enabled", includeApps: ["All"], excludeApps: [], users: "4 roles", signInFrequency: "everyTime" },
    ],
    apps: [
      { spId: sp(1), appId: SAMPLE_APP_IDS.expenses, name: "Expense Portal", ssoMode: "saml", syncJobs: [] },
      { spId: sp(2), appId: SAMPLE_APP_IDS.aws, name: "AWS IAM Identity Center", ssoMode: "saml", syncJobs: [healthy("aws.scim", 14, 212)] },
      { spId: sp(3), appId: SAMPLE_APP_IDS.partner, name: "Partner Portal", ssoMode: "oidc", syncJobs: [] },
      { spId: sp(4), appId: SAMPLE_APP_IDS.field, name: "Field Service app", ssoMode: "oidc", syncJobs: [] },
      { spId: sp(5), appId: SAMPLE_APP_IDS.notes, name: "Northwind Meeting Notes", ssoMode: "", syncJobs: [] },
      {
        spId: sp(6),
        appId: SAMPLE_APP_IDS.ticketing,
        name: "Ticketing Desk",
        ssoMode: "saml",
        syncJobs: [
          {
            ...healthy("ticketing.scim", 31, 88),
            lastRun: { began: at(33), ended: at(31), state: "EntryLevelErrors", error: "2 users couldn't be updated: email already in use" },
          },
        ],
      },
      {
        spId: sp(7),
        appId: SAMPLE_APP_IDS.hr,
        name: "HR Hub",
        ssoMode: "saml",
        syncJobs: [
          {
            id: "hr.scim",
            templateId: "scim",
            intervalMinutes: 40,
            scheduleState: "Active",
            status: "Quarantine",
            lastRun: { began: at(60 * 26 + 2), ended: at(60 * 26), state: "Failed", error: "401 Unauthorized from the SCIM endpoint: the secret token expired" },
            lastSuccess: at(60 * 30),
            quarantine: { reason: "EncounteredQuarantineException", since: at(60 * 26), nextAttempt: at(-60 * 4) },
            failures: 6,
            inScope: 140,
          },
        ],
      },
    ],
    warnings: [],
  };
}

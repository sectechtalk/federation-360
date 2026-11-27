// Made-up per-person reads for the fictional Contoso tenant, matching the sample activity (data/sampleActivity.ts) and
// the sample access scan (data/sampleAccess.ts). Gray Finance is active; Sam Leaver was disabled two days ago.
import { USER_ACCESS_FORMAT, type UserAccessSnapshot } from "../lib/lookup";
import { SAMPLE_APP_IDS } from "./sampleAccess";

const sp = (n: number) => `e1a2b3c4-0000-4000-8000-${String(n).padStart(12, "0")}`;
const uid = (n: number) => `e1a2b3c4-0000-4000-8000-1000000000${String(n).padStart(2, "0")}`;
const appIds: Record<string, string> = {
  [sp(1)]: SAMPLE_APP_IDS.expenses,
  [sp(2)]: SAMPLE_APP_IDS.aws,
  [sp(3)]: SAMPLE_APP_IDS.partner,
  [sp(5)]: SAMPLE_APP_IDS.notes,
  [sp(6)]: SAMPLE_APP_IDS.ticketing,
  [sp(7)]: SAMPLE_APP_IDS.hr,
};
const DEFAULT = "00000000-0000-0000-0000-000000000000";

export const SAMPLE_PEOPLE = ["gray.finance@contoso.example", "sam.leaver@contoso.example"];

export function sampleUserAccess(who: string, now = new Date()): UserAccessSnapshot | null {
  const ago = (min: number) => new Date(now.getTime() - min * 60000).toISOString();
  const base = { format: USER_ACCESS_FORMAT as typeof USER_ACCESS_FORMAT, version: 1 as const, collectedAt: now.toISOString(), collector: "sample" as const, appIds, warnings: [], example: true };
  const w = who.trim().toLowerCase();
  if (w.startsWith("gray")) {
    return {
      ...base,
      user: { id: uid(1), upn: "gray.finance@contoso.example", name: "Gray Finance", enabled: true, sessionsValidFrom: ago(200 * 1440), lastSignIn: ago(50), lastNonInteractive: ago(10) },
      assignments: [
        { spId: sp(1), app: "Expense Portal", via: "direct", roleId: DEFAULT },
        { spId: sp(2), app: "AWS IAM Identity Center", via: "group", group: "AWS Finance Readers", roleId: "e1a2b3c4-0000-4000-8000-0000000000aa" },
        { spId: sp(3), app: "Partner Portal", via: "direct", roleId: DEFAULT },
        { spId: sp(6), app: "Ticketing Desk", via: "group", group: "All Staff", roleId: DEFAULT },
        { spId: sp(7), app: "HR Hub", via: "group", group: "All Staff", roleId: DEFAULT },
      ],
      grants: [{ spId: sp(5), app: "Northwind Meeting Notes", scope: "openid profile offline_access Mail.Read Files.Read.All Calendars.Read", consentType: "Principal" }],
      devices: [{ id: "dev-GRAY-LAPTOP", name: "GRAY-LAPTOP", os: "Windows", trustType: "AzureAd", enabled: true }],
    };
  }
  if (w.startsWith("sam")) {
    return {
      ...base,
      user: { id: uid(2), upn: "sam.leaver@contoso.example", name: "Sam Leaver", enabled: false, sessionsValidFrom: ago(2 * 1440 - 5), lastSignIn: ago(2 * 1440 - 90), lastNonInteractive: ago(2 * 1440 + 10) },
      assignments: [
        { spId: sp(1), app: "Expense Portal", via: "direct", roleId: DEFAULT },
        { spId: sp(2), app: "AWS IAM Identity Center", via: "group", group: "AWS Finance Readers", roleId: "e1a2b3c4-0000-4000-8000-0000000000aa" },
        { spId: sp(3), app: "Partner Portal", via: "direct", roleId: DEFAULT },
        { spId: sp(7), app: "HR Hub", via: "group", group: "All Staff", roleId: DEFAULT },
      ],
      grants: [],
      devices: [{ id: "dev-SAM-MACBOOK", name: "SAM-MACBOOK", os: "MacMDM", trustType: "AzureAd", enabled: true }],
    };
  }
  return null;
}

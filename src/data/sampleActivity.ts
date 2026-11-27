// Made-up activity for the fictional Contoso tenant, shaped like Graph's own log rows so it goes through the same
// readers as a real download. Sam Leaver was disabled two days ago; Gray Finance is still active everywhere.
import { ACTIVITY_EXPORT_FORMAT } from "../lib/activity";
import { SAMPLE_APP_IDS } from "./sampleAccess";

const GRAPH = "00000003-0000-0000-c000-000000000000";
const sp = (n: number) => `e1a2b3c4-0000-4000-8000-${String(n).padStart(12, "0")}`;
const uid = (n: number) => `e1a2b3c4-0000-4000-8000-1000000000${String(n).padStart(2, "0")}`;

interface Person {
  upn: string;
  name: string;
  id: string;
  device: string;
  prt: boolean;
}

const PEOPLE: Person[] = [
  { upn: "gray.finance@contoso.example", name: "Gray Finance", id: uid(1), device: "GRAY-LAPTOP", prt: true },
  { upn: "sam.leaver@contoso.example", name: "Sam Leaver", id: uid(2), device: "SAM-MACBOOK", prt: true },
  { upn: "kai.eng@contoso.example", name: "Kai Engineer", id: uid(3), device: "KAI-DESKTOP", prt: true },
  { upn: "harper.sales@contoso.example", name: "Harper Sales", id: uid(4), device: "", prt: false },
];

export function sampleActivityFile(now = new Date()): Record<string, unknown> {
  const t = (minutesAgo: number) => new Date(now.getTime() - minutesAgo * 60000).toISOString();
  const signIn = (p: Person, app: string, appId: string, minutesAgo: number, type: "interactiveUser" | "nonInteractiveUser" = "interactiveUser", extra: Record<string, unknown> = {}) => ({
    id: `s-${p.id.slice(-4)}-${appId.slice(-4)}-${minutesAgo}`,
    createdDateTime: t(minutesAgo),
    userPrincipalName: p.upn,
    userDisplayName: p.name,
    userId: p.id,
    appDisplayName: app,
    appId,
    resourceDisplayName: app === "Northwind Meeting Notes" ? "Microsoft Graph" : app,
    resourceId: app === "Northwind Meeting Notes" ? GRAPH : appId,
    ipAddress: "203.0.113.10",
    isInteractive: type === "interactiveUser",
    signInEventTypes: [type],
    authenticationProtocol: app === "AWS IAM Identity Center" || app === "Expense Portal" || app === "Ticketing Desk" ? "saml20" : "oAuth2",
    incomingTokenType: type === "interactiveUser" && p.prt ? "primaryRefreshToken" : type === "nonInteractiveUser" ? "refreshToken" : "none",
    deviceDetail: { displayName: p.device, deviceId: p.device ? `dev-${p.device}` : "" },
    status: { errorCode: 0 },
    ...extra,
  });
  const silentEvery = (p: Person, app: string, appId: string, everyMin: number, fromMinutesAgo: number, toMinutesAgo = 0) => {
    const out = [];
    for (let m = fromMinutesAgo; m >= toMinutesAgo; m -= everyMin) out.push(signIn(p, app, appId, m, "nonInteractiveUser"));
    return out;
  };
  const [gray, sam, kai, harper] = PEOPLE;
  const DAY = 1440;
  const samGone = 2 * DAY;

  const signIns = [
    signIn(gray, "Expense Portal", SAMPLE_APP_IDS.expenses, 3 * 60),
    signIn(gray, "Partner Portal", SAMPLE_APP_IDS.partner, 5 * DAY),
    signIn(gray, "AWS IAM Identity Center", SAMPLE_APP_IDS.aws, 50),
    signIn(gray, "HR Hub", SAMPLE_APP_IDS.hr, 2 * DAY),
    signIn(gray, "Northwind Meeting Notes", SAMPLE_APP_IDS.notes, 6 * DAY),
    signIn(kai, "Field Service app", SAMPLE_APP_IDS.field, 4 * DAY),
    signIn(kai, "Ticketing Desk", SAMPLE_APP_IDS.ticketing, 20),
    signIn(harper, "Partner Portal", SAMPLE_APP_IDS.partner, 30),
    signIn(sam, "AWS IAM Identity Center", SAMPLE_APP_IDS.aws, samGone + 120),
    signIn(sam, "Partner Portal", SAMPLE_APP_IDS.partner, samGone + 300),
    signIn(sam, "Expense Portal", SAMPLE_APP_IDS.expenses, samGone + 200),
    // Sam tries again after being disabled.
    signIn(sam, "Expense Portal", SAMPLE_APP_IDS.expenses, samGone - 90, "interactiveUser", { status: { errorCode: 50057, failureReason: "User account is disabled." } }),
  ];
  const nonInteractive = [
    ...silentEvery(gray, "Partner Portal", SAMPLE_APP_IDS.partner, 75, 5 * DAY, 10),
    ...silentEvery(harper, "Partner Portal", SAMPLE_APP_IDS.partner, 72, 2 * DAY, 5),
    ...silentEvery(kai, "Field Service app", SAMPLE_APP_IDS.field, 480, 4 * DAY, 60),
    ...silentEvery(gray, "Northwind Meeting Notes", SAMPLE_APP_IDS.notes, 65, 6 * DAY, 15),
    // Sam's refreshes stop when the account is disabled.
    ...silentEvery(sam, "Partner Portal", SAMPLE_APP_IDS.partner, 78, samGone + 300, samGone + 10),
  ];
  const servicePrincipal = [0, 60, 120, 180].map((m) => ({
    id: `sp-${m}`,
    createdDateTime: t(m + 5),
    appDisplayName: "Payroll sync job",
    appId: "a7b8c9d0-1e2f-4a3b-9c4d-5e6f7a8b9c0d",
    servicePrincipalId: sp(8),
    servicePrincipalName: "Payroll sync job",
    resourceDisplayName: "Microsoft Graph",
    signInEventTypes: ["servicePrincipal"],
    status: { errorCode: 0 },
  }));
  const managedIdentity = [{
    id: "mi-1",
    createdDateTime: t(12),
    appDisplayName: "func-helpdesk-runner",
    appId: "",
    servicePrincipalId: sp(9),
    servicePrincipalName: "func-helpdesk-runner",
    resourceDisplayName: "Azure Key Vault",
    signInEventTypes: ["managedIdentity"],
    managedIdentityType: "systemAssigned",
    status: { errorCode: 0 },
  }];
  const prov = (p: Person, app: string, spIdN: number, minutesAgo: number, action: string, status: string, reason = "") => ({
    id: `p-${p.id.slice(-4)}-${spIdN}-${minutesAgo}`,
    activityDateTime: t(minutesAgo),
    provisioningAction: action,
    provisioningStatusInfo: { status, ...(reason ? { errorInformation: { reason } } : {}) },
    servicePrincipal: { id: sp(spIdN), displayName: app },
    sourceIdentity: { id: p.id, displayName: p.name, details: { UserPrincipalName: p.upn } },
    targetIdentity: { id: `ext-${p.id.slice(-4)}`, displayName: p.upn },
  });
  const provisioning = [
    prov(gray, "AWS IAM Identity Center", 2, 3 * DAY, "update", "success"),
    prov(sam, "AWS IAM Identity Center", 2, samGone - 35, "disable", "success"),
    prov(sam, "Ticketing Desk", 6, samGone - 30, "disable", "success"),
    prov(sam, "HR Hub", 7, samGone - 40, "disable", "failure", "401 Unauthorized from the SCIM endpoint: the secret token expired"),
    prov(kai, "Ticketing Desk", 6, 31, "update", "failure", "email already in use"),
  ];
  const audit = (activity: string, p: Person, minutesAgo: number, target = "", props: { displayName: string; newValue: string }[] = []) => ({
    id: `a-${activity}-${minutesAgo}`,
    activityDateTime: t(minutesAgo),
    activityDisplayName: activity,
    initiatedBy: { user: { userPrincipalName: "alex.admin@contoso.example" } },
    targetResources: [
      { id: p.id, type: "User", userPrincipalName: p.upn, displayName: p.name, modifiedProperties: props },
      ...(target ? [{ id: "x", type: "ServicePrincipal", displayName: target }] : []),
    ],
  });
  const audits = [
    audit("Update user", sam, samGone, "", [{ displayName: "AccountEnabled", newValue: "[false]" }]),
    audit("Revoke sign-in sessions", sam, samGone - 5),
    audit("Remove app role assignment from user", sam, samGone - 20, "Ticketing Desk"),
    audit("Consent to application", gray, 6 * DAY + 30, "Northwind Meeting Notes"),
  ];
  return { format: ACTIVITY_EXPORT_FORMAT, version: 1, collector: "sample", collectedAt: now.toISOString(), days: 7, signIns, nonInteractive, servicePrincipal, managedIdentity, provisioning, audits };
}

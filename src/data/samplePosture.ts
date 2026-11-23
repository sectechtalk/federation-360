// A made-up posture scan so the MFA and SSO coverage page shows every state before a real scan.
import { POSTURE_FORMAT, type PostureSnapshot, type PostureUser } from "../lib/posture";

const id = (prefix: string, n: number) => `${prefix}-0000-4000-8000-${String(n).padStart(12, "0")}`;

export function samplePosture(now = new Date()): PostureSnapshot {
  const people: [string, string, string[], string[], boolean?, boolean?][] = [
    // [upn local part, name, roles, methods, enabled = true, guest = false]
    ["alex.admin", "Alex Admin", ["Global Administrator"], ["password", "fido2", "microsoftAuthenticator"]],
    ["blair.ops", "Blair Ops", ["Global Administrator"], ["password", "microsoftAuthenticator"]],
    ["casey.helpdesk", "Casey Helpdesk", ["Helpdesk Administrator"], ["password", "phone"]],
    ["dana.apps", "Dana Apps", ["Application Administrator"], ["password"]],
    ["eli.sec", "Eli Security", ["Security Administrator"], ["password", "windowsHelloForBusiness", "microsoftAuthenticator"]],
    ["frankie.mac", "Frankie Mac", [], ["password", "platformCredential", "microsoftAuthenticator"]],
    ["gray.finance", "Gray Finance", [], ["password", "microsoftAuthenticator"]],
    ["harper.sales", "Harper Sales", [], ["password", "microsoftAuthenticator", "phone"]],
    ["indy.sales", "Indy Sales", [], ["password", "phone"]],
    ["jo.people", "Jo People", [], ["password", "microsoftAuthenticator"]],
    ["kai.eng", "Kai Engineer", [], ["password", "fido2"]],
    ["lee.eng", "Lee Engineer", [], ["password", "softwareOath"]],
    ["morgan.ops", "Morgan Ops", [], ["password", "microsoftAuthenticator"]],
    ["noor.legal", "Noor Legal", [], ["password"]],
    ["oak.warehouse", "Oak Warehouse", [], ["password", "phone"]],
    ["pat.warehouse", "Pat Warehouse", [], ["password"]],
    ["quinn.design", "Quinn Design", [], ["password", "microsoftAuthenticator"]],
    ["river.support", "River Support", [], ["password", "microsoftAuthenticator", "email"]],
    ["sam.leaver", "Sam Leaver", [], ["password", "microsoftAuthenticator"], false],
    ["tara_partner.example#EXT#", "Tara (partner)", [], ["password"], true, true],
  ];
  const users: PostureUser[] = people.map(([upn, name, roles, methods, enabled = true, guest = false], i) => ({
    id: id("5a3e0001", i + 1),
    upn: `${upn}@f360sample.onmicrosoft.com`,
    name,
    enabled,
    guest,
    roles,
    methods,
  }));
  return {
    format: POSTURE_FORMAT,
    version: 1,
    collectedAt: now.toISOString(),
    collector: "sample",
    tenant: { id: id("5a3e0000", 1), name: "F360 Sample tenant", domain: "f360sample.onmicrosoft.com" },
    securityDefaults: true,
    methodsPolicy: [
      { id: "Fido2", state: "enabled", targets: ["Passkey pilot"] },
      { id: "MicrosoftAuthenticator", state: "enabled", targets: ["all_users"] },
      { id: "Sms", state: "enabled", targets: ["all_users"] },
      { id: "Voice", state: "disabled", targets: [] },
      { id: "SoftwareOath", state: "enabled", targets: ["all_users"] },
      { id: "TemporaryAccessPass", state: "enabled", targets: ["all_users"] },
      { id: "Email", state: "enabled", targets: ["all_users"] },
    ],
    users,
    apps: [
      { appId: id("5a3e0002", 1), spId: id("5a3e0003", 1), name: "Expense Portal", ssoMode: "saml", assignmentRequired: true, thirdParty: true, enabled: true },
      { appId: id("5a3e0002", 2), spId: id("5a3e0003", 2), name: "Payroll Cloud", ssoMode: "saml", assignmentRequired: false, thirdParty: true, enabled: true },
      { appId: id("5a3e0002", 3), spId: id("5a3e0003", 3), name: "Partner Portal", ssoMode: "", assignmentRequired: false, thirdParty: false, enabled: true },
      { appId: id("5a3e0002", 4), spId: id("5a3e0003", 4), name: "Shipping Tracker", ssoMode: "password", assignmentRequired: false, thirdParty: true, enabled: true },
      { appId: id("5a3e0002", 5), spId: id("5a3e0003", 5), name: "Vendor Wiki", ssoMode: "notSupported", assignmentRequired: false, thirdParty: true, enabled: true },
      { appId: id("5a3e0002", 6), spId: id("5a3e0003", 6), name: "Field Service app", ssoMode: "oidc", assignmentRequired: true, thirdParty: false, enabled: true },
    ],
    warnings: [],
    example: true,
  };
}

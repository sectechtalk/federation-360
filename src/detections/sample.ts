// Made-up sign-in and audit logs (Graph shape) with one example of every attack the rules look for, plus ordinary
// noise that must not fire. Addresses are from the documentation ranges (RFC 5737), the domain is fictional.
import { SIGNINS_FORMAT } from "./events";

const D = "f360sample.onmicrosoft.com";
const MIN = 60_000;

export function sampleSignInLog(now = new Date()) {
  const base = now.getTime() - 20 * 60 * MIN; // 20 hours ago
  const t = (m: number) => new Date(base + m * MIN).toISOString();
  let n = 0;
  const si = (m: number, user: string, ip: string, country: string, city: string, errorCode = 0, more: Record<string, unknown> = {}) => ({
    id: `sample-${++n}`,
    createdDateTime: t(m),
    userPrincipalName: `${user}@${D}`,
    appDisplayName: "Office 365 Exchange Online",
    ipAddress: ip,
    clientAppUsed: "Browser",
    isInteractive: true,
    location: { city, countryOrRegion: country },
    status: { errorCode, failureReason: errorCode === 50126 ? "Invalid username or password." : errorCode === 500121 ? "Authentication failed during strong authentication request." : null, additionalDetails: null as string | null },
    sessionId: `sess-${user}-1`,
    riskLevelDuringSignIn: "none",
    deviceDetail: { displayName: errorCode === 0 && country === "US" ? `${user.split(".")[0].toUpperCase()}-PC` : "" },
    ...more,
  });
  const office = ["192.0.2.10", "US", "Seattle"] as const;
  const signIns: any[] = [];

  // Ordinary day: everyone signs in from the office, a few mistype once.
  const people = ["alex.admin", "blair.ops", "casey.helpdesk", "gray.finance", "harper.sales", "indy.sales", "jo.people", "kai.eng", "lee.eng", "morgan.ops", "noor.legal", "oak.warehouse", "pat.warehouse", "quinn.design", "frankie.mac"];
  people.forEach((p, i) => signIns.push(si(i * 3, p, ...office)));
  signIns.push(si(50, "jo.people", ...office, 50126), si(51, "jo.people", ...office));
  // Two missed MFA prompts is not fatigue.
  signIns.push(si(70, "kai.eng", ...office, 500121), si(72, "kai.eng", ...office, 500121), si(73, "kai.eng", ...office));

  // 1. MFA fatigue: Blair gets 5 prompts in 6 minutes from abroad, then a sign-in succeeds.
  for (const [k, m] of [300, 301, 303, 304, 306].entries())
    signIns.push(si(m, "blair.ops", "198.51.100.23", "NL", "Amsterdam", 500121, { status: { errorCode: 500121, failureReason: "Authentication failed during strong authentication request.", additionalDetails: k === 4 ? "MFA denied; user did not respond to mobile app notification" : "MFA denied; user declined the authentication" } }));
  signIns.push(si(309, "blair.ops", "198.51.100.23", "NL", "Amsterdam", 0, { sessionId: "sess-blair-2" }));

  // 2. Password spray from one address across 12 accounts; Noor's password was "Winter2026!".
  people.slice(0, 12).forEach((p, i) => signIns.push(si(400 + i, p, "203.0.113.50", "RU", "Moscow", p === "noor.legal" ? 0 : 50126, { sessionId: `sess-spray-${p}` })));

  // 3. Password guessing: 11 failures for Oak, then success.
  for (let i = 0; i < 11; i++) signIns.push(si(500 + i * 2, "oak.warehouse", "203.0.113.77", "BR", "Sao Paulo", 50126));
  signIns.push(si(525, "oak.warehouse", "203.0.113.77", "BR", "Sao Paulo", 0, { sessionId: "sess-oak-2" }));

  // 4. Legacy authentication: Pat's mailbox read over IMAP.
  signIns.push(si(600, "pat.warehouse", "203.0.113.90", "US", "Ashburn", 0, { clientAppUsed: "IMAP4", isInteractive: false, sessionId: "" }));

  // 5. Token replay: Frankie's session from the office, then reused from another country an hour later.
  signIns.push(si(700, "frankie.mac", "192.0.2.10", "US", "Seattle", 0, { sessionId: "sess-frankie-9" }));
  signIns.push(si(760, "frankie.mac", "198.51.100.200", "SG", "Singapore", 0, { sessionId: "sess-frankie-9", isInteractive: false, appDisplayName: "Microsoft Graph" }));

  // 6. New country then new security info: Casey from the office earlier, then from Nigeria, then a new phone.
  signIns.push(si(800, "casey.helpdesk", "198.51.100.140", "NG", "Lagos", 0, { sessionId: "sess-casey-2", riskLevelDuringSignIn: "medium" }));

  // 8. Risky sign-in, then a sensitive change: Entra ID Protection rates Gray's sign-in high (anonymous IP address),
  //    and 25 minutes later Gray's account adds Harper to the Global Administrator role.
  signIns.push(si(900, "gray.finance", "203.0.113.120", "DE", "Frankfurt", 0, { sessionId: "sess-gray-2", riskLevelDuringSignIn: "high", appDisplayName: "Microsoft Entra admin center" }));

  const audit = (m: number, activity: string, actor: string, target: { userPrincipalName?: string; displayName?: string; type: string }) => ({
    id: `audit-${++n}`,
    activityDateTime: t(m),
    activityDisplayName: activity,
    category: "UserManagement",
    result: "success",
    initiatedBy: { user: { userPrincipalName: `${actor}@${D}` } },
    targetResources: [target],
  });
  const audits = [
    audit(820, "User registered security info", "casey.helpdesk", { userPrincipalName: `casey.helpdesk@${D}`, type: "User" }),
    // 7. Blair consents to a mail-reading app 40 minutes after the MFA fatigue attack.
    audit(350, "Consent to application", "blair.ops", { displayName: "Northwind Meeting Notes", type: "ServicePrincipal" }),
    audit(925, "Add member to role", "gray.finance", { userPrincipalName: `harper.sales@${D}`, displayName: "Global Administrator", type: "User" }),
    // Ordinary: a new starter registers security info with no new-country sign-in before it.
    audit(100, "User registered security info", "quinn.design", { userPrincipalName: `quinn.design@${D}`, type: "User" }),
  ];
  return { format: SIGNINS_FORMAT, version: 1, collectedAt: now.toISOString(), collector: "sample", signIns, audits };
}

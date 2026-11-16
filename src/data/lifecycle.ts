import type { ProtocolId } from "../lib/types";
import { WORKDIR } from "./workdir";

// The life of an integration, from the day it's asked for to the day it's switched off, walked through as one
// real-world scenario in the free lab tenant. {tenant} and {domain} are replaced on the Learn page with the
// values typed into its "Your lab" boxes.

export interface LifeStep {
  title: string;
  /** Why this step exists, in plain English. */
  why: string;
  /** Click by click. Each line is one action. */
  clicks?: string[];
  /** PowerShell 7 to paste. */
  code?: { title: string; body: string };
  /** What you should see when it worked. */
  success: string;
  /** How this differs at work, outside the lab. */
  realWorld?: string;
  /** The Federation 360 page that helps with this step. */
  open?: { route: string; params?: Record<string, string>; label: string };
}

export interface LifeStage {
  id: "create" | "maintain" | "remove";
  title: string;
  summary: string;
  steps: LifeStep[];
}

export interface Lifecycle {
  id: string;
  title: string;
  protocols: ProtocolId[];
  /** The part of the scenario this lifecycle plays. */
  story: string;
  stages: LifeStage[];
}

export const ENTRA = "https://entra.microsoft.com";
export const ENTERPRISE_APPS = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview";
export const APP_REGISTRATIONS = "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade";
export const ALL_USERS = "https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers";
export const MY_APPS = "https://myapps.microsoft.com";

export const SCENARIO = {
  title: "The scenario: your company buys an expenses app",
  body: "Finance has bought a cloud app called Expenses. Staff must sign in with their work account (SAML). The app's mobile version signs people in with OpenID Connect, and a nightly export job calls it with OAuth client credentials. Accounts must appear when someone joins and disappear when they leave (SCIM). You are the identity engineer. In the lab, the Federation 360 test app on http://localhost:5174 plays the Expenses web app, jwt.ms plays the mobile app, and the lab SCIM app plays Expenses' user directory. Everything you build is prefixed PRAC- so it's easy to find and remove.",
  before: [
    "Docker Desktop is running and Federation 360 opens at http://localhost:5173.",
    "Your lab is built (Learn > Build your lab), including the lab workflow's apply run, and the Live test page's SAML test has passed at least once.",
    "PowerShell 7 with the Microsoft.Graph.Authentication module, the same setup the lab scripts already use.",
    "You can sign in as admin@{domain} (to change things) and as lab.user1@{domain} and lab.user2@{domain} (to test). Use an InPrivate window for every test sign-in so your admin session doesn't get in the way.",
    "Federation 360's Inventory has a tenant for the lab. If not: Inventory > Add tenant, Name F360 Lab, Platform Microsoft Entra ID, Tenant ID {tenant}, Domain {domain}, then Save tenant.",
  ],
};

export const STAGE_INTRO: Record<LifeStage["id"], string> = {
  create: "Gather the app's details, build it in Entra, give the right people access, prove it works, and write it down.",
  maintain: "Keep it working for years: rotate certificates, secrets and tokens before they expire, change what the app receives, watch for failures, and check who still needs access.",
  remove: "Switch it off on purpose: confirm nobody uses it, disable it, remove access and credentials, delete it, and clean up the records.",
};

export const LIFECYCLES: Lifecycle[] = [
  // ------------------------------------------------------------------ SAML
  {
    id: "saml",
    title: "SAML",
    protocols: ["saml"],
    story: "Staff sign in to the Expenses web app with their work account. You build the enterprise app by hand, the way you would for a real vendor, and point the lab test app at it.",
    stages: [
      {
        id: "create",
        title: "Create",
        summary: STAGE_INTRO.create,
        steps: [
          {
            title: "Get the app's SAML details from the vendor",
            why: "Entra and the app must agree on three values before anything works: the app's name for itself (Identifier, also called Entity ID), where Entra sends the user back (Reply URL, also called ACS URL), and which user value identifies the person (NameID). At work, the vendor's setup guide or metadata file gives you these.",
            clicks: [
              "Paste http://localhost:5173/#wizards into the address bar.",
              "Click the card SAML single sign-on for an app in Entra ID.",
              "On step 1, type the vendor's values: SP Entity ID api://{tenant}/prac-expenses and ACS URL http://localhost:5174/saml/acs. Leave the sign-on URL empty.",
              "Click Next step through the wizard as you do each part in Entra below. It explains every field and what breaks when it's wrong.",
            ],
            success: "The wizard's step 1 shows no red errors under the two fields.",
            realWorld: "Ask the vendor which user value they match accounts on (usually email or UPN) before you start. Changing it after go-live breaks every existing account.",
            open: { route: "wizards", params: { id: "entra-saml" }, label: "Open the SAML wizard" },
          },
          {
            title: "Create the enterprise application",
            why: "An enterprise application is Entra's record of one app in your tenant. Assignment, single sign-on and the signing certificate all live on it.",
            clicks: [
              `Open an InPrivate window, paste ${ENTERPRISE_APPS} and sign in as admin@{domain}.`,
              "Click New application, then Create your own application.",
              "Name it PRAC-Expenses-SAML.",
              "Choose Integrate any other application you don't find in the gallery (Non-gallery), then click Create.",
            ],
            success: "After about 30 seconds the PRAC-Expenses-SAML Overview page opens.",
          },
          {
            title: "Fill in Basic SAML Configuration",
            why: "This is where you type the vendor's Identifier and Reply URL. Entra refuses any sign-in whose request doesn't match them exactly.",
            clicks: [
              "In PRAC-Expenses-SAML, click Single sign-on in the left menu, then the SAML tile.",
              "On the Basic SAML Configuration card, click Edit.",
              "Under Identifier (Entity ID), click Add identifier and type api://{tenant}/prac-expenses",
              "Under Reply URL (Assertion Consumer Service URL), click Add reply URL and type http://localhost:5174/saml/acs",
              "Click Save at the top of the panel, then close it with the X.",
            ],
            success: "The Basic SAML Configuration card now shows both values. The SAML Certificates card shows a certificate with Status Active and an expiry date three years away.",
            realWorld: "Most apps need a Sign on URL too, so a click on the My Apps tile starts at the app. The lab test app works without one.",
          },
          {
            title: "Check the claims the app will receive",
            why: "Claims (SAML calls them attributes) are the facts about the user that Entra puts in the response. The Unique User Identifier becomes the NameID, which the app uses to find the account.",
            clicks: [
              "On the Attributes & Claims card, click Edit.",
              "Confirm Unique User Identifier (Name ID) is user.userprincipalname. Leave the rest as they are.",
              "Close the panel with the X.",
            ],
            success: "Unique User Identifier shows user.userprincipalname.",
          },
          {
            title: "Give one test user access",
            why: "New enterprise apps require assignment, so only people you add can sign in. Start with one user, prove it works, then add more.",
            clicks: [
              "Click Users and groups in the left menu, then Add user/group.",
              "Under Users, click None Selected, tick lab.user1, click Select, then click Assign.",
            ],
            success: "lab.user1 appears in the list. lab.user2 is not in the list, on purpose.",
            realWorld: "At work you assign a group, not people one by one. Group assignment needs Entra ID P1, which the free lab doesn't have.",
          },
          {
            title: "Point the stand-in app at your new enterprise app",
            why: "The lab test app plays the Expenses web app. This tells it to sign in to PRAC-Expenses-SAML instead of the lab's ready-made app. Sign in as admin@{domain} when the browser opens.",
            code: {
              title: "PowerShell 7",
              body: `cd ${WORKDIR}\ngit pull\n./lab/testapp/Start-F360TestApp.ps1 -TenantId {tenant} -SamlApp PRAC-Expenses-SAML`,
            },
            success: "The script ends with Test app is running. and SAML test: ready (PRAC-Expenses-SAML).",
          },
          {
            title: "Test the sign-in both ways",
            why: "Users reach an app two ways: by opening the app (SP-initiated) or by clicking its tile in My Apps (IdP-initiated). Test both, and test that someone without access is refused.",
            clicks: [
              "Paste http://localhost:5173/#livetest and click Check again in the Start the test app panel.",
              "In the SAML panel, click Run SAML sign-in. Sign in as lab.user1@{domain}.",
              `Then, in a new InPrivate window, paste ${MY_APPS}, sign in as lab.user1@{domain} and click the PRAC-Expenses-SAML tile.`,
              "Finally, click Run SAML sign-in again, but sign in as lab.user2@{domain}.",
            ],
            success: "Both lab.user1 sign-ins land back on Live test with The flow completed, and the Recent runs list shows SAML sign-in (started by the app) and SAML sign-in (started from My Apps). lab.user2 gets AADSTS50105 from Microsoft, because they aren't assigned.",
            open: { route: "playbooks", params: { id: "AADSTS50105" }, label: "AADSTS50105 playbook" },
          },
          {
            title: "Write it down in the inventory",
            why: "The inventory is how you know, months later, what this app is, who owns it and when its certificate expires. Overview warns you before expiry dates arrive.",
            clicks: [
              "Back in Entra, on the SAML Certificates card, note the Thumbprint and Expiration date.",
              "Paste http://localhost:5173/#inventory and click Add integration.",
              "Name PRAC-Expenses-SAML, Tenant F360 Lab, Protocol SAML, Environment test, Status live, Owner your name.",
              "SP Entity ID api://{tenant}/prac-expenses, ACS URL http://localhost:5174/saml/acs, IdP Entity ID https://sts.windows.net/{tenant}/",
              "Signing cert thumbprint and Signing cert expires from the card, then click Save integration.",
            ],
            success: "PRAC-Expenses-SAML is in the Integrations list with no warnings.",
            open: { route: "inventory", label: "Open Inventory" },
          },
        ],
      },
      {
        id: "maintain",
        title: "Maintain",
        summary: STAGE_INTRO.maintain,
        steps: [
          {
            title: "Change what the app receives (a new claim)",
            why: "Six months in, Finance wants the app to know each person's department so it can route approvals. This is the most common SAML change request.",
            clicks: [
              `Paste ${ALL_USERS}, click lab.user1, click Edit properties, open the Job information tab, set Department to Finance, then click Save.`,
              "Open PRAC-Expenses-SAML > Single sign-on. On the Attributes & Claims card click Edit, then Add new claim.",
              "Name department, Source attribute user.department, then click Save.",
              "Paste http://localhost:5173/#livetest and click Run SAML sign-in as lab.user1@{domain}. Open the run and expand the SAML response hop.",
            ],
            success: "The response's attributes now include department with the value Finance.",
            realWorld: "Agree the claim name with the vendor first. The app ignores claims it doesn't expect, and renaming one later breaks whatever reads it.",
          },
          {
            title: "Rotate the signing certificate",
            why: "Entra signs every SAML response with a certificate that expires (three years by default). When it expires, nobody can sign in. You swap it before then, in a planned window.",
            clicks: [
              "Open PRAC-Expenses-SAML > Single sign-on. On the SAML Certificates card click Edit.",
              "Click New Certificate, then Save. The new one is added as Inactive.",
              "On the new certificate's row, click the … menu, choose Make certificate active, and confirm with Yes. Click Save, then close the panel.",
              "Paste http://localhost:5173/#livetest and click Run SAML sign-in as lab.user1@{domain}.",
              "Update Signing cert thumbprint and Signing cert expires on PRAC-Expenses-SAML in Inventory, then click Save integration.",
            ],
            success: "The sign-in still says The flow completed, and the SAML Certificates card shows the new thumbprint as Active.",
            realWorld: "The lab test app re-reads Entra's metadata on every sign-in, so it never breaks. A real app keeps the old certificate until someone uploads the new one. Send the vendor the new certificate first, and activate it in Entra at the moment they switch.",
            open: { route: "playbooks", params: { id: "cert-rollover" }, label: "Certificate rollover playbook" },
          },
          {
            title: "Watch for failures",
            why: "You want to hear about a problem before users do.",
            clicks: [
              "Open PRAC-Expenses-SAML > Single sign-on. On the SAML Certificates card, click Edit and check Notification Email is an address someone reads. Entra emails it before the certificate expires.",
              "Click Sign-in logs in the left menu (under Activity). Each test sign-in is listed with Success or Failure and the reason.",
              "Paste http://localhost:5173/#overview and look at Upcoming expirations.",
            ],
            success: "Your test sign-ins appear in Sign-in logs, and the certificate expiry appears under Upcoming expirations.",
            realWorld: "The free tenant keeps sign-in logs for 7 days. At work they are usually sent to a SIEM so you can search months back.",
          },
          {
            title: "Check who still needs access",
            why: "People change jobs. An access review asks: does everyone assigned still need this app? Removing people who don't is part of keeping the app safe.",
            clicks: [
              "Open PRAC-Expenses-SAML > Users and groups and read the list.",
              "For anyone who no longer needs it, tick them, click Remove assignment, then Yes.",
            ],
            success: "Only people who need Expenses are in the list.",
            realWorld: "Entra's automated Access reviews need an ID Governance licence, so in the free lab you do this by hand. At work it runs every quarter and managers approve or remove each person.",
          },
          {
            title: "Break it on purpose and fix it",
            why: "Most SAML tickets are a mismatch between what the app sends and what Entra expects. Seeing the error once makes it easy to recognise.",
            clicks: [
              "Paste http://localhost:5173/#livetest. In the SAML panel click Break it: wrong Issuer, and sign in as lab.user1@{domain}.",
              "Click Break it: wrong reply URL and sign in again.",
              "Open each run from Recent runs and click its playbook link.",
            ],
            success: "Microsoft shows AADSTS700016 for the wrong Issuer and AADSTS50011 for the wrong reply URL, and each run links to its playbook.",
            open: { route: "flowtracer", label: "Open Flow tracer" },
          },
        ],
      },
      {
        id: "remove",
        title: "Remove",
        summary: STAGE_INTRO.remove,
        steps: [
          {
            title: "Confirm nobody still uses it",
            why: "Finance has moved to a new expenses product. Before you switch the old one off, check that people really have stopped using it.",
            clicks: [
              "Open PRAC-Expenses-SAML > Sign-in logs and set Date to Last 7 days.",
            ],
            success: "Only your own test sign-ins are listed.",
            realWorld: "At work, get the app owner's written go-ahead and a date. Announce it to the assigned users a week before.",
          },
          {
            title: "Disable sign-in first",
            why: "Disabling is reversible. If someone shouts, you switch it back on in seconds. Deleting is not.",
            clicks: [
              "Open PRAC-Expenses-SAML > Properties.",
              "Set Enabled for users to sign-in? to No, then click Save.",
              "Paste http://localhost:5173/#livetest and click Run SAML sign-in as lab.user1@{domain}.",
            ],
            success: "Microsoft refuses the sign-in with an error saying the application is disabled (AADSTS7000112).",
          },
          {
            title: "Point the test app back at the lab app",
            why: "So the Live test page's SAML test keeps working after PRAC-Expenses-SAML is gone.",
            code: {
              title: "PowerShell 7",
              body: `cd ${WORKDIR}\n./lab/testapp/Start-F360TestApp.ps1 -TenantId {tenant}`,
            },
            success: "The script ends with SAML test: ready (LAB-TestApp-SAML).",
          },
          {
            title: "Delete the app",
            why: "A non-gallery app has two parts: the enterprise application (in your tenant) and the app registration (its definition). Deleting the app registration removes both.",
            clicks: [
              `Paste ${APP_REGISTRATIONS} and click the All applications tab.`,
              "Click PRAC-Expenses-SAML, then Delete in the bar at the top, and confirm.",
            ],
            success: "PRAC-Expenses-SAML is gone from All applications and from Enterprise applications. It's listed under the Deleted applications tab, where you can restore it for 30 days.",
            realWorld: "Ask the vendor to delete the users' data under your contract, and remove any firewall or DNS entries that only existed for this app.",
          },
          {
            title: "Close the record",
            why: "An inventory that still lists dead apps sends the next person chasing certificates that don't matter.",
            clicks: [
              "Paste http://localhost:5173/#inventory and click PRAC-Expenses-SAML.",
              "Click Delete, then Yes, delete.",
            ],
            success: "PRAC-Expenses-SAML is no longer in Integrations, and Overview no longer shows its certificate expiry.",
          },
        ],
      },
    ],
  },

  // ------------------------------------------------------------------ OIDC and OAuth
  {
    id: "oidc-oauth",
    title: "OpenID Connect and OAuth",
    protocols: ["oidc", "oauth"],
    story: "The Expenses mobile app signs people in with OpenID Connect, and a nightly export job calls in with OAuth client credentials (a client secret). You register one app for both and use jwt.ms, Microsoft's token viewer, as the stand-in mobile app.",
    stages: [
      {
        id: "create",
        title: "Create",
        summary: STAGE_INTRO.create,
        steps: [
          {
            title: "Plan the registration",
            why: "For OpenID Connect, Entra and the app agree on a client ID (Entra makes it), a redirect URI (where Entra sends the user back) and scopes (what the app asks for). The wizard explains each one.",
            clicks: [
              "Paste http://localhost:5173/#wizards and click OpenID Connect sign-in for a web app (auth code + PKCE).",
              "Read steps 1 to 3. Use redirect URI https://jwt.ms and scopes openid profile email.",
            ],
            success: "You know the three values before you open Entra.",
            open: { route: "wizards", params: { id: "entra-oidc" }, label: "Open the OIDC wizard" },
          },
          {
            title: "Register the app",
            why: "An app registration is the app's definition: its client ID, redirect URIs, secrets and the permissions it asks for.",
            clicks: [
              `Open an InPrivate window, paste ${APP_REGISTRATIONS} and sign in as admin@{domain}.`,
              "Click New registration. Name PRAC-Expenses-OIDC.",
              "Under Supported account types, choose the single tenant option (Accounts in this organizational directory only).",
              "Under Redirect URI, choose Web and type https://jwt.ms",
              "Click Register. On the Overview page, copy the Application (client) ID.",
            ],
            success: "The Overview page shows PRAC-Expenses-OIDC with its Application (client) ID and Directory (tenant) ID {tenant}.",
          },
          {
            title: "Allow an ID token straight to jwt.ms",
            why: "jwt.ms can't redeem a code, so for this test you let Entra hand it the ID token directly. Real apps use the authorization code flow with PKCE, which is what the Live test page's OIDC test does.",
            clicks: [
              "In PRAC-Expenses-OIDC, click Authentication in the left menu.",
              "Under Implicit grant and hybrid flows, tick ID tokens (used for implicit and hybrid flows), then click Save.",
            ],
            success: "The ID tokens box stays ticked after you reload the page.",
            realWorld: "Never leave this ticked on a production app. Federation 360's inventory flags it as a warning.",
          },
          {
            title: "Require assignment and give one user access",
            why: "By default, anyone in the tenant can sign in to a new app registration. Turning on assignment means only people you add can.",
            clicks: [
              `Paste ${ENTERPRISE_APPS} and click PRAC-Expenses-OIDC.`,
              "Click Properties, set Assignment required? to Yes, and click Save.",
              "Click Users and groups > Add user/group > None Selected, tick lab.user1, click Select, then Assign.",
            ],
            success: "lab.user1 is the only user listed.",
          },
          {
            title: "Sign in and read the token",
            why: "This proves the registration works and shows you exactly what the app receives about the user.",
            code: {
              title: "PowerShell 7 (opens an InPrivate Edge window)",
              body: "$TenantId = '{tenant}'\n$ClientId = Read-Host 'Paste the Application (client) ID of PRAC-Expenses-OIDC'\n$url = \"https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?client_id=$ClientId&response_type=id_token&redirect_uri=https%3A%2F%2Fjwt.ms&scope=openid%20profile%20email&response_mode=fragment&nonce=lab123\"\nStart-Process msedge -ArgumentList '--inprivate', $url",
            },
            clicks: [
              "Sign in as lab.user1@{domain}. If asked to consent, click Accept.",
              "On jwt.ms, copy the whole encoded token from the top box.",
              "Paste http://localhost:5173/#jwt and paste the token into the decoder.",
              "Run the PowerShell again and sign in as lab.user2@{domain}.",
            ],
            success: "jwt.ms shows the decoded token, aud equals your client ID, and the JWT decoder shows no red findings. lab.user2 gets AADSTS50105.",
            open: { route: "jwt", label: "Open JWT decoder" },
          },
          {
            title: "Add a client secret for the export job",
            why: "The nightly export job has no user. It proves who it is with a client secret (a password for the app) and gets an access token. This is OAuth client credentials.",
            clicks: [
              "In App registrations > PRAC-Expenses-OIDC, click Certificates & secrets, then the Client secrets tab, then New client secret.",
              "Description export-1, Expires 90 days (3 months), then click Add.",
              "Copy the Value now. Entra never shows it again.",
            ],
            code: {
              title: "PowerShell 7 (asks for the client ID and secret, prints the result)",
              body: "$TenantId = '{tenant}'\n$ClientId = Read-Host 'Application (client) ID of PRAC-Expenses-OIDC'\n$Secret = Read-Host 'Client secret Value' -MaskInput\n$t = Invoke-RestMethod -Method Post \"https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token\" -Body @{\n  grant_type = 'client_credentials'; client_id = $ClientId; client_secret = $Secret\n  scope = 'https://graph.microsoft.com/.default'\n}\n\"Token issued. It expires in $($t.expires_in) seconds.\"\n$t.access_token | Set-Clipboard",
            },
            success: "PowerShell prints Token issued. The token is on your clipboard; paste it into the JWT decoder and appid equals your client ID.",
            realWorld: "Prefer a certificate or workload identity federation over a secret. The lab's LAB-Daemon uses a certificate, and the Live test page's client credentials test uses it.",
            open: { route: "wizards", params: { id: "entra-client-credentials" }, label: "Client credentials wizard" },
          },
          {
            title: "Write it down in the inventory",
            why: "The secret expires in 90 days. The inventory is what reminds you.",
            clicks: [
              "Paste http://localhost:5173/#inventory and click Add integration.",
              "Name PRAC-Expenses-OIDC, Tenant F360 Lab, Protocol OpenID Connect, Environment test, Status live.",
              "Client (application) ID from Entra, Redirect URIs https://jwt.ms, Expected issuer https://login.microsoftonline.com/{tenant}/v2.0",
              "Secret / certificate expires: the Expires date from Certificates & secrets. Click Save integration.",
            ],
            success: "PRAC-Expenses-OIDC is listed, and Overview shows its secret under Upcoming expirations.",
            open: { route: "inventory", label: "Open Inventory" },
          },
        ],
      },
      {
        id: "maintain",
        title: "Maintain",
        summary: STAGE_INTRO.maintain,
        steps: [
          {
            title: "Add a claim to the ID token",
            why: "The mobile app team wants the user's UPN in the token. Optional claims add facts that aren't there by default.",
            clicks: [
              "In App registrations > PRAC-Expenses-OIDC, click Token configuration, then Add optional claim.",
              "Token type ID, tick upn, click Add. If asked to turn on the Microsoft Graph profile permission, tick it and click Add.",
              "Run the sign-in PowerShell from Create again as lab.user1@{domain}.",
            ],
            success: "jwt.ms now shows a upn claim with lab.user1@{domain}.",
          },
          {
            title: "Rotate the client secret with no downtime",
            why: "Secrets expire. The safe pattern is: add the new one, move the app to it, test, then delete the old one. Two secrets can be valid at once, which is what makes this safe.",
            clicks: [
              "In Certificates & secrets > Client secrets, click New client secret, Description export-2, Expires 90 days (3 months), Add. Copy the Value.",
              "Run the client secret PowerShell from Create with the new Value. It should print Token issued.",
              "On the export-1 row, click the Delete (bin) icon and confirm with Yes.",
              "Run the PowerShell with the old Value.",
              "Update Secret / certificate expires on PRAC-Expenses-OIDC in Inventory and click Save integration.",
            ],
            success: "The new secret prints Token issued. The old one fails with AADSTS7000215 (invalid client secret).",
            realWorld: "At work, step 2 is updating the secret in the job's key vault or settings and watching its next run succeed. Only then delete the old secret.",
            open: { route: "playbooks", params: { id: "AADSTS7000215" }, label: "AADSTS7000215 playbook" },
          },
          {
            title: "Rotate a certificate credential",
            why: "LAB-Daemon proves who it is with a certificate instead of a secret. This replaces it and proves the new one works.",
            code: {
              title: "PowerShell 7",
              body: `cd ${WORKDIR}\n./lab/testapp/Start-F360TestApp.ps1 -TenantId {tenant} -NewCertificate`,
            },
            clicks: [
              "Wait one minute after the script finishes. Paste http://localhost:5173/#livetest and click Run client credentials.",
            ],
            success: "The script prints Uploaded certificate … to LAB-Daemon, and the Live test run ends with The API accepted the access token.",
            realWorld: "The lab script replaces the old certificate at once. At work, upload the new certificate alongside the old one, switch the service, then remove the old one.",
          },
          {
            title: "Watch for failures and expiry",
            why: "Expired secrets are the most common cause of a job that silently stops.",
            clicks: [
              "Paste http://localhost:5173/#overview and look at Upcoming expirations and Needs attention.",
              "In Entra, open Enterprise applications > PRAC-Expenses-OIDC > Sign-in logs to see user sign-ins.",
            ],
            success: "The new secret's expiry date is listed, and the lab.user1 and lab.user2 sign-ins appear in the logs.",
          },
          {
            title: "Review access and permissions",
            why: "Check that only the right people can sign in and that the app hasn't collected permissions it doesn't use.",
            clicks: [
              "Enterprise applications > PRAC-Expenses-OIDC > Users and groups: remove anyone who doesn't need it.",
              "App registrations > PRAC-Expenses-OIDC > API permissions: remove any permission the app doesn't use (click …, then Remove permission).",
            ],
            success: "The app has only the users and permissions it needs.",
          },
        ],
      },
      {
        id: "remove",
        title: "Remove",
        summary: STAGE_INTRO.remove,
        steps: [
          {
            title: "Confirm nobody still uses it",
            why: "Check both people (sign-ins) and the export job (token requests) before switching it off.",
            clicks: ["Enterprise applications > PRAC-Expenses-OIDC > Sign-in logs, Date Last 7 days."],
            success: "Only your own test sign-ins are listed.",
            realWorld: "Service principal (job) sign-ins are a separate tab that needs Entra ID P1. At work, also check the job's own logs.",
          },
          {
            title: "Disable sign-in first",
            why: "Reversible in seconds if something still depends on it.",
            clicks: [
              "Enterprise applications > PRAC-Expenses-OIDC > Properties: set Enabled for users to sign-in? to No and click Save.",
              "Run the sign-in PowerShell as lab.user1@{domain}.",
            ],
            success: "Microsoft refuses the sign-in because the application is disabled.",
          },
          {
            title: "Delete the secrets",
            why: "A deleted app can be restored for 30 days, along with its secrets. Delete them first so nothing can use them.",
            clicks: ["App registrations > PRAC-Expenses-OIDC > Certificates & secrets: delete every client secret."],
            success: "The Client secrets tab says No client secrets have been created for this application.",
          },
          {
            title: "Delete the registration",
            why: "Removes the app and its enterprise application from the tenant.",
            clicks: [
              `Paste ${APP_REGISTRATIONS}, click the All applications tab, then PRAC-Expenses-OIDC.`,
              "Click Delete in the bar at the top and confirm.",
              "Optional: open the Deleted applications tab, click PRAC-Expenses-OIDC, and click Delete permanently to skip the 30-day wait.",
            ],
            success: "PRAC-Expenses-OIDC is gone from All applications and Enterprise applications.",
          },
          {
            title: "Close the record",
            why: "Keep the inventory true.",
            clicks: ["Inventory > PRAC-Expenses-OIDC > Delete > Yes, delete."],
            success: "Overview no longer lists the secret's expiry.",
            open: { route: "inventory", label: "Open Inventory" },
          },
        ],
      },
    ],
  },

  // ------------------------------------------------------------------ SCIM
  {
    id: "scim",
    title: "SCIM provisioning",
    protocols: ["scim"],
    story: "Expenses needs an account for each person before they can sign in, updated when they change job and disabled when they leave. Entra does this with SCIM. The lab SCIM app on your PC plays Expenses' user directory, reached through a free Cloudflare tunnel.",
    stages: [
      {
        id: "create",
        title: "Create",
        summary: STAGE_INTRO.create,
        steps: [
          {
            title: "Agree the one identifier",
            why: "SCIM creates the account; SAML or OIDC signs the person in. They must use the same value (userName in SCIM, the NameID in SAML), or the person signs in and the app says user not found.",
            clicks: [
              "Paste http://localhost:5173/#wizards and click SCIM provisioning from Entra ID to an app.",
              "Read steps 1 and 2. In the lab, userName comes from the user principal name, the same value PRAC-Expenses-SAML sends as its NameID.",
            ],
            success: "You can say which Entra attribute fills userName and why.",
            open: { route: "wizards", params: { id: "entra-scim" }, label: "Open the SCIM wizard" },
          },
          {
            title: "Connect Entra to the app and provision the first user",
            why: "The script creates the enterprise app F360-ScimApp, gives Entra the app's address (Tenant URL) and a fresh secret token, runs Test connection, and provisions lab.user1 on demand so you don't wait 40 minutes. Sign in as admin@{domain} when asked. Leave this window open: it shows every request Entra sends.",
            code: {
              title: "PowerShell 7",
              body: `cd ${WORKDIR}\ngit pull\n./lab/scim/Start-F360ScimLab.ps1 -TenantId {tenant}`,
            },
            success: "The window shows Test connection passed. and then Result: Success, with a POST /scim/Users 201 line.",
            realWorld: "At work the vendor gives you the Tenant URL and token, and you type them into Enterprise applications > the app > Provisioning.",
          },
          {
            title: "Read what Entra sent",
            why: "Entra ID Free has no provisioning logs, so the lab writes each request to a file. Reading one shows exactly what the app received.",
            code: {
              title: "PowerShell 7 (a second window; copies the newest request to the clipboard)",
              body: `cd ${WORKDIR}\nGet-ChildItem ./lab/scim/logs -Filter *POST* | Sort-Object LastWriteTime | Select-Object -Last 1 | Get-Content -Raw | Set-Clipboard\n'Copied. Paste only the part above ----- response ----- into the SCIM checker.'`,
            },
            clicks: ["Paste http://localhost:5173/#scim and paste the request part into the box."],
            success: "The SCIM checker shows userName lab.user1@{domain}, active true, and no red findings.",
            open: { route: "scim", label: "Open SCIM checker" },
          },
          {
            title: "Write it down in the inventory",
            why: "The SCIM token is a credential that expires. When it does, provisioning stops with no sign-in error, so you need its date on record.",
            clicks: [
              "Inventory > PRAC-Expenses-SAML (the sign-in side of the same app) > set Provisioning to scim.",
              "SCIM endpoint: the Tenant URL the script printed. SCIM token expires: the vendor's date (in the lab, the token lasts only as long as the window is open; use today). Matching attribute userName. Click Save integration.",
            ],
            success: "The integration shows both its sign-in and its provisioning settings.",
            open: { route: "inventory", label: "Open Inventory" },
          },
        ],
      },
      {
        id: "maintain",
        title: "Maintain",
        summary: STAGE_INTRO.maintain,
        steps: [
          {
            title: "Joiner: a new starter gets an account",
            why: "Assigning someone to the app puts them in scope. On the next cycle, or on demand, Entra creates their account.",
            clicks: [
              `Paste ${ENTERPRISE_APPS} and click F360-ScimApp.`,
              "Users and groups > Add user/group. Under Users tick lab.user2. Under Select a role pick User (never Default Access). Click Assign.",
              "Click Provision on demand in the left menu, search lab.user2, select them, and click Provision.",
            ],
            success: "The on-demand result shows Create user succeeded, and the PowerShell window shows POST /scim/Users 201 for lab.user2.",
            realWorld: "A Default Access assignment is skipped as NotEffectivelyEntitled. Always pick the app's real role.",
          },
          {
            title: "Mover: a change in Entra reaches the app",
            why: "When someone changes job, the app should learn about it without anyone touching the app.",
            clicks: [
              `Paste ${ALL_USERS}, click lab.user2, Edit properties, Job information tab, set Job title to Expenses approver, then Save.`,
              "F360-ScimApp > Provision on demand, search lab.user2, click Provision.",
            ],
            success: "The PowerShell window shows a PATCH /scim/Users/… request that replaces title with Expenses approver.",
          },
          {
            title: "Rotate the SCIM token",
            why: "The token lets Entra write to the app. If it leaks or expires, you replace it on both sides.",
            clicks: [
              "Press Enter in the SCIM PowerShell window to stop it, then run the Start-F360ScimLab command from Create again.",
            ],
            success: "Test connection passed. again, with a brand-new token that the script never shows or saves.",
            realWorld: "At work, generate the new token in the app, paste it into Provisioning > Admin credentials > Secret Token, click Test connection, then Save. Then revoke the old one in the app.",
          },
          {
            title: "Watch for failures",
            why: "A broken token or app shows no sign-in error. People just stop getting accounts.",
            code: {
              title: "PowerShell 7 (press Enter in the running SCIM window first)",
              body: `cd ${WORKDIR}\n./lab/scim/Start-F360ScimLab.ps1 -TenantId {tenant} -Fault 401`,
            },
            success: "Test connection fails with a 401, the same thing Entra sees when a token is wrong or expired. Stop it with Enter and run the normal command again.",
            realWorld: "Set Provisioning > Settings > Notification Email so Entra emails you when the job goes into quarantine.",
            open: { route: "playbooks", params: { id: "scim-401" }, label: "SCIM 401 playbook" },
          },
        ],
      },
      {
        id: "remove",
        title: "Remove",
        summary: STAGE_INTRO.remove,
        steps: [
          {
            title: "Leaver: removing access disables the account",
            why: "This is the step nobody tests and the one auditors ask about. When someone leaves, their account in the app must be disabled.",
            clicks: [
              "F360-ScimApp > Users and groups: tick lab.user2, click Remove assignment, then Yes.",
              "Provision on demand, search lab.user2, click Provision.",
            ],
            success: "The PowerShell window shows PATCH /scim/Users/… with active set to false. The account is disabled, not deleted, so its expense history is kept.",
            open: { route: "playbooks", params: { id: "scim-leaver" }, label: "Leaver playbook" },
          },
          {
            title: "Decommission the provisioning connection",
            why: "Stopping provisioning before you delete the app is a choice. If it's still running when you unassign everyone, Entra disables every account in the app. Decide which you want first.",
            clicks: ["Press Enter in the SCIM PowerShell window. That stops the app and the tunnel and pauses the cycle."],
            code: {
              title: "PowerShell 7",
              body: `cd ${WORKDIR}\n./lab/scim/Start-F360ScimLab.ps1 -TenantId {tenant} -Remove\nRemove-Item ./lab/scim/data/store.json -ErrorAction SilentlyContinue\n'The lab SCIM app has forgotten every user.'`,
            },
            success: "PowerShell prints Deleted F360-ScimApp, then The lab SCIM app has forgotten every user. F360-ScimApp is gone from Enterprise applications.",
            realWorld: "At work: Provisioning > Stop provisioning, agree with the vendor what happens to the accounts and data, then delete the enterprise app.",
          },
          {
            title: "Close the record",
            why: "The inventory should no longer claim this app is provisioned.",
            clicks: ["Inventory > PRAC-Expenses-SAML > set Provisioning to none and click Save integration (or delete the whole integration if you removed the SAML app too)."],
            success: "No SCIM token expiry is listed for it on Overview.",
          },
        ],
      },
    ],
  },
];

/** Puts the reader's lab tenant ID and domain into the walkthrough text. */
export function fillLab(text: string, tenant: string, domain: string) {
  return text.split("{tenant}").join(tenant.trim() || "<lab tenant ID>").split("{domain}").join(domain.trim() || "<lab domain>");
}

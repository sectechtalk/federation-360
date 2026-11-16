import { emptyOidc, emptySaml, emptyScim, type AppIntegration, type ProtocolId } from "../lib/types";

export interface WizardField {
  key: string;
  label: string;
  placeholder?: string;
  /** What this value is, in plain words. */
  help: string;
  /** What goes wrong when it's wrong. */
  pitfall?: string;
  multiline?: boolean;
  type?: "text" | "date" | "select";
  options?: string[];
  /** Returns an error message, or null. */
  validate?: (v: string, all: Record<string, string>) => string | null;
}

export interface WizardStep {
  title: string;
  /** Where to click. */
  where?: string;
  explain: string;
  /** Things to do on this step, in order. */
  actions?: string[];
  fields?: WizardField[];
  /** Short note on why this matters. */
  why?: string;
}

export interface Wizard {
  id: string;
  title: string;
  protocol: ProtocolId;
  platform: string;
  summary: string;
  minutes: number;
  youWillLearn: string[];
  steps: WizardStep[];
  /** Turns the answers into text blocks for the summary page. */
  outputs: (v: Record<string, string>) => { title: string; body: string; lang?: string }[];
  testPlan: string[];
  toApp: (v: Record<string, string>) => Partial<AppIntegration>;
}

const https = (v: string) => (!v ? null : /^https:\/\//.test(v) || /^http:\/\/localhost/.test(v) ? null : "Must start with https:// (http is only acceptable for localhost).");
const guid = (v: string) => (!v || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v.trim()) ? null : "Should be a GUID like 8f2b6c1e-0d4a-4a7e-9a51-3c0d2e7b9f10.");
const T = (v: Record<string, string>, k: string, d = `<${k}>`) => v[k]?.trim() || d;

export const WIZARDS: Wizard[] = [
  // ---------------------------------------------------------------
  {
    id: "entra-saml",
    title: "SAML single sign-on for an app in Entra ID",
    protocol: "saml",
    platform: "Microsoft Entra ID",
    summary: "Connect a SaaS or in-house web app to Entra with SAML, using a non-gallery enterprise application.",
    minutes: 25,
    youWillLearn: ["What Entity ID, ACS (Reply URL) and NameID mean", "Which values go in which system", "How certificate signing works and how to test"],
    steps: [
      {
        title: "Collect the app's (SP) details",
        explain:
          "In SAML the app is the Service Provider (SP) and Entra is the Identity Provider (IdP). Before touching Entra, get two values from the app's SSO settings page or its SP metadata file. If the app gives you a metadata file or URL, load it in the Metadata checker to read them.",
        fields: [
          { key: "appName", label: "App name", placeholder: "Expense Portal", help: "What users will see in My Apps." },
          {
            key: "entityId",
            label: "SP Entity ID (Identifier)",
            placeholder: "https://expenses.contoso.example/saml/metadata",
            help: "A unique name for the app. It can look like a URL but is just an identifier. Entra puts it in the assertion's <Audience>.",
            pitfall: "If it doesn't match the SP exactly (even a trailing slash), the SP rejects the assertion (audience mismatch) or Entra returns AADSTS700016.",
          },
          {
            key: "acsUrl",
            label: "ACS URL (Reply URL)",
            placeholder: "https://expenses.contoso.example/saml/acs",
            help: "Assertion Consumer Service: the app's endpoint that receives the SAML response via the user's browser (HTTP POST).",
            pitfall: "If it doesn't match what the app sends, Entra returns AADSTS50011.",
            validate: https,
          },
          {
            key: "signOnUrl",
            label: "Sign-on URL (optional)",
            placeholder: "https://expenses.contoso.example/login",
            help: "The app's own login page. Setting it makes the My Apps tile start SP-initiated sign-in, which more apps support.",
            validate: https,
          },
        ],
      },
      {
        title: "Create the enterprise application",
        where: "Entra admin center > Identity > Applications > Enterprise applications > New application > Create your own application",
        explain: "Choose “Integrate any other application you don't find in the gallery (Non-gallery)”. If the app is in the gallery, picking it pre-fills some settings and shows the vendor's tutorial.",
        actions: ["Name it the same as above.", "Open the new app > Single sign-on > SAML."],
        why: "The enterprise application (service principal) is the object Entra uses for sign-in, user assignment and Conditional Access.",
      },
      {
        title: "Basic SAML Configuration",
        where: "Single sign-on > SAML > Basic SAML Configuration > Edit",
        explain: "Enter the SP values from step 1. These tell Entra who the assertion is for and where to send it.",
        actions: [
          "Identifier (Entity ID) = the SP Entity ID. Mark it Default.",
          "Reply URL (ACS URL) = the ACS URL.",
          "Sign on URL = the app's login page (optional).",
          "Relay State: leave blank unless the vendor says otherwise.",
          "Save.",
        ],
      },
      {
        title: "Attributes & Claims",
        where: "Single sign-on > SAML > Attributes & Claims > Edit",
        explain: "Decide how the app identifies users. The Unique User Identifier becomes the <NameID>. The app looks up the account by this value, so it must match what the app has stored.",
        fields: [
          {
            key: "nameIdSource",
            label: "Unique User Identifier (Name ID) source",
            type: "select",
            options: ["user.userprincipalname", "user.mail", "user.onpremisessamaccountname", "user.employeeid", "user.objectid"],
            help: "UPN is the default. Use mail only if every user has a mailbox and the app keys accounts on email.",
            pitfall: "If UPN and email differ for some users, they'll get 'user not found' in the app.",
          },
          {
            key: "nameIdFormat",
            label: "Name identifier format",
            type: "select",
            options: [
              "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
              "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
              "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
              "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            ],
            help: "Most apps want emailAddress or unspecified. Use whatever the vendor's docs say.",
          },
        ],
        actions: ["Add any extra attributes the app needs (e.g. givenname, surname, groups). Use the exact attribute names the app expects."],
      },
      {
        title: "SAML signing certificate",
        where: "Single sign-on > SAML > SAML Certificates",
        explain:
          "Entra signs every SAML response with a private key. The app verifies the signature with the matching certificate. Download the Federation Metadata XML (or the Base64 certificate) and give it to the app. Note the thumbprint and expiry date so you can track it.",
        actions: [
          "Add a notification email (a team mailbox) for expiry warnings.",
          "Signing Option: 'Sign SAML assertion' is default. Use 'Sign SAML response and assertion' if the app requires it.",
          "Signing Algorithm: SHA-256.",
        ],
        fields: [
          { key: "thumbprint", label: "Certificate thumbprint", placeholder: "749A276BF39BC76DFAA117BB9F8605D526A5B63F", help: "Shown on the SAML Certificates card. Used later to confirm which certificate signed a response." },
          { key: "certExpires", label: "Certificate expiry", type: "date", help: "Default lifetime is 3 years. When it expires, sign-in breaks until the app has the new one." },
        ],
      },
      {
        title: "Configure the app (SP) side",
        where: "The app's SSO / SAML settings page",
        explain: "Copy these values from the 'Set up <app>' card in Entra into the app. Many apps accept the Federation Metadata URL directly, which also makes certificate rollover easier.",
        fields: [
          { key: "tenantId", label: "Directory (tenant) ID", placeholder: "8f2b6c1e-0d4a-4a7e-9a51-3c0d2e7b9f10", help: "Entra admin center > Overview. Used to build the values below.", validate: guid },
        ],
        actions: [
          "Login URL (IdP SSO URL) → app's 'IdP SSO URL' / 'SAML endpoint'.",
          "Microsoft Entra Identifier → app's 'IdP Entity ID' / 'Issuer'.",
          "Logout URL → app's 'IdP SLO URL' (optional).",
          "Upload the certificate, or paste the App Federation Metadata URL.",
        ],
      },
      {
        title: "Assign users and groups",
        where: "Enterprise application > Users and groups > Add user/group",
        explain: "With Assignment required = Yes (recommended), only assigned users and groups can sign in. Others get AADSTS50105.",
        actions: ["Assign a test user first, then a group.", "Groups need Entra ID P1. Nested groups aren't supported for assignment."],
        why: "Assignment is your access control and makes access reviews meaningful.",
      },
      {
        title: "Test and capture",
        explain: "Use 'Test single sign-on with <app>' on the SAML page, then try from the app's own login page and from My Apps. If it fails, capture the SAMLResponse (browser developer tools > Network > the POST to the ACS URL > Payload) and paste it into the SAML decoder with this app selected.",
        actions: ["Test as an assigned user.", "Test as an unassigned user (should fail with AADSTS50105).", "Save to inventory."],
      },
    ],
    outputs: (v) => {
      const t = T(v, "tenantId", "{tenant-id}");
      return [
        {
          title: "Values to give the app (IdP side)",
          body: `IdP Entity ID / Issuer:  https://sts.windows.net/${t}/
IdP SSO URL:             https://login.microsoftonline.com/${t}/saml2
IdP Logout URL:          https://login.microsoftonline.com/${t}/saml2
Federation metadata:     https://login.microsoftonline.com/${t}/federationmetadata/2007-06/federationmetadata.xml?appid=<application-id>
Signing cert thumbprint: ${T(v, "thumbprint", "(record from Entra)")}`,
        },
        {
          title: "Values entered in Entra (SP side)",
          body: `Identifier (Entity ID): ${T(v, "entityId")}
Reply URL (ACS):        ${T(v, "acsUrl")}
Sign on URL:            ${T(v, "signOnUrl", "(blank)")}
NameID source:          ${T(v, "nameIdSource", "user.userprincipalname")}
NameID format:          ${T(v, "nameIdFormat", "emailAddress")}`,
        },
      ];
    },
    testPlan: [
      "Assigned user signs in from the app's login page (SP-initiated): lands in the app.",
      "Same user from My Apps (IdP-initiated or via Sign on URL): lands in the app.",
      "Unassigned user: blocked with AADSTS50105.",
      "Capture a SAMLResponse and run it through the decoder: no red findings.",
      "Record certificate expiry and owner in the inventory.",
    ],
    toApp: (v) => ({
      name: v.appName || "New SAML app",
      protocol: "saml",
      status: "testing",
      saml: {
        ...emptySaml(),
        entityId: v.entityId || "",
        acsUrl: v.acsUrl || "",
        signOnUrl: v.signOnUrl || "",
        idpEntityId: v.tenantId ? `https://sts.windows.net/${v.tenantId.trim()}/` : "",
        nameIdSource: v.nameIdSource || "user.userprincipalname",
        nameIdFormat: v.nameIdFormat || emptySaml().nameIdFormat,
        certThumbprint: v.thumbprint || "",
        certExpires: v.certExpires || "",
      },
    }),
  },
  // ---------------------------------------------------------------
  {
    id: "entra-aws-idc",
    title: "Entra ID as the identity source for AWS IAM Identity Center",
    protocol: "saml",
    platform: "AWS IAM Identity Center",
    summary: "Workforce sign-in to AWS accounts with Entra (SAML) and automatic user/group provisioning (SCIM), then access through permission sets.",
    minutes: 45,
    youWillLearn: ["How SAML (sign-in) and SCIM (provisioning) work together", "Where permission sets fit", "The usual causes of 'invalid SAML response'"],
    steps: [
      {
        title: "Understand the moving parts",
        explain:
          "Entra authenticates users (SAML). SCIM creates the same users and groups inside IAM Identity Center ahead of time, because Identity Center only accepts a sign-in for a user it already knows. Permission sets define what a user can do in an AWS account; you assign groups + permission sets to accounts.",
        why: "Most failures are one of these three pieces: SAML trust, missing provisioned user, or missing account assignment.",
      },
      {
        title: "Switch the identity source in IAM Identity Center",
        where: "AWS console > IAM Identity Center > Settings > Identity source > Actions > Change identity source > External identity provider",
        explain: "AWS shows its Service provider metadata. Download the metadata file, and note the two URLs. Don't click Next until you have Entra's metadata (step 3).",
        fields: [
          { key: "awsAcs", label: "IAM Identity Center ACS URL", placeholder: "https://us-east-1.signin.aws.amazon.com/platform/saml/acs/…", help: "Where Entra will POST the SAML response.", validate: https },
          { key: "awsIssuer", label: "IAM Identity Center issuer URL (SP entity ID)", placeholder: "https://us-east-1.signin.aws.amazon.com/platform/saml/d-…", help: "Goes into Entra's Identifier field." },
          { key: "portalUrl", label: "AWS access portal URL", placeholder: "https://d-9067000000.awsapps.com/start", help: "Users start here. Shown on the IAM Identity Center dashboard." },
        ],
        why: "Changing the identity source changes how every user signs in to AWS. The confirmation screen lists what is kept and what is removed: read it, do the change in a planned window, and keep a documented emergency access path (root or a break-glass IAM user).",
      },
      {
        title: "Create the Entra enterprise app from the gallery",
        where: "Entra admin center > Enterprise applications > New application > search “AWS IAM Identity Center”",
        explain: "Add the gallery app, open Single sign-on > SAML, and use 'Upload metadata file' with the AWS metadata. This fills Identifier and Reply URL correctly. Then download Entra's Federation Metadata XML.",
        fields: [{ key: "tenantId", label: "Entra tenant ID", placeholder: "8f2b6c1e-…", help: "Entra Overview page.", validate: guid }],
        actions: ["Back in AWS, upload Entra's Federation Metadata XML as the IdP SAML metadata, then confirm the change."],
      },
      {
        title: "Turn on automatic provisioning (SCIM)",
        where: "IAM Identity Center > Settings > Automatic provisioning > Enable",
        explain: "AWS shows a SCIM endpoint and an access token. Copy both now; the token is shown once.",
        fields: [
          { key: "scimEndpoint", label: "SCIM endpoint", placeholder: "https://scim.us-east-1.amazonaws.com/…/scim/v2", help: "Entra calls this to create and update users and groups.", validate: https },
          { key: "scimTokenExpires", label: "Access token expiry", type: "date", help: "IAM Identity Center SCIM tokens expire after one year. When it expires, provisioning silently stops and new joiners can't sign in." },
        ],
      },
      {
        title: "Configure provisioning in Entra",
        where: "Enterprise app > Provisioning > Get started > Provisioning Mode: Automatic",
        explain: "Paste the SCIM endpoint into Tenant URL and the token into Secret Token, then Test Connection. Review Mappings: userPrincipalName → userName is the default and must match the SAML NameID.",
        actions: [
          "Scope: 'Sync only assigned users and groups'.",
          "Assign the groups that should exist in AWS (Users and groups).",
          "Nested group members aren't provisioned; assign the groups that directly contain users.",
          "Start provisioning. The first cycle can take a while; watch Provisioning logs.",
        ],
      },
      {
        title: "Create permission sets and assign them",
        where: "IAM Identity Center > Multi-account permissions > Permission sets, then AWS accounts",
        explain: "A permission set is a template of IAM policies that becomes a role in each account it's assigned to. Assign provisioned groups to accounts with a permission set.",
        actions: [
          "Prefer least privilege: start from job-function policies and add a permissions boundary if needed.",
          "Set session duration (e.g. 1–4 hours for admin sets).",
          "Keep administrator permission sets on separate admin groups, ideally time-bound via an approval process.",
        ],
        fields: [{ key: "permSets", label: "Permission sets planned", multiline: true, placeholder: "ReadOnly → all accounts → AWS-ReadOnly group\nAdmin → sandbox → AWS-Admins group", help: "Write them down for the access review and the inventory." }],
      },
      {
        title: "Test",
        explain: "Sign in at the AWS access portal URL as a provisioned test user. You should see the accounts and roles assigned to their groups. If you get an error after the Entra sign-in, capture the SAML response and decode it with this app selected.",
        actions: ["Confirm the user exists in Identity Center > Users with the right username.", "Sign in at the portal.", "Assume a role and check the session in CloudTrail (AssumeRoleWithSAML).", "Save to inventory."],
      },
    ],
    outputs: (v) => [
      {
        title: "Entra Basic SAML Configuration",
        body: `Identifier (Entity ID): ${T(v, "awsIssuer")}
Reply URL (ACS):        ${T(v, "awsAcs")}
Sign on URL:            ${T(v, "portalUrl")}`,
      },
      {
        title: "Provisioning",
        body: `Tenant URL:      ${T(v, "scimEndpoint")}
Token expires:   ${T(v, "scimTokenExpires", "(record it!)")}
Matching:        userPrincipalName -> userName (must equal SAML NameID)`,
      },
      { title: "Permission sets", body: T(v, "permSets", "(none recorded)") },
    ],
    testPlan: [
      "Provisioning logs show the test user and group created in AWS.",
      "Test user sees the expected accounts and permission sets in the access portal.",
      "User removed from the group in Entra loses access after the next provisioning cycle (verify the leaver path).",
      "Calendar reminder set for the SCIM token expiry.",
    ],
    toApp: (v) => ({
      name: "AWS IAM Identity Center",
      protocol: "saml",
      provisioning: "scim",
      status: "testing",
      saml: {
        ...emptySaml(),
        entityId: v.awsIssuer || "",
        acsUrl: v.awsAcs || "",
        signOnUrl: v.portalUrl || "",
        idpEntityId: v.tenantId ? `https://sts.windows.net/${v.tenantId.trim()}/` : "",
      },
      notes: [v.scimTokenExpires ? `SCIM token expires ${v.scimTokenExpires}.` : "", v.permSets ? `Permission sets:\n${v.permSets}` : ""].filter(Boolean).join("\n"),
    }),
  },
  // ---------------------------------------------------------------
  {
    id: "entra-scim",
    title: "SCIM provisioning from Entra ID to an app",
    protocol: "scim",
    platform: "Microsoft Entra ID",
    summary: "Have Entra create, update and disable accounts in an app automatically, and make sure the provisioned account matches what the app receives at sign-in.",
    minutes: 30,
    youWillLearn: ["How provisioning (SCIM) and sign-in (SAML or OIDC) depend on one shared identifier", "What Tenant URL, Secret Token, matching and scope mean", "How to test one user before turning it on for everyone"],
    steps: [
      {
        title: "Get the app's SCIM details",
        explain:
          "SCIM is a REST API that the app exposes. Entra is the client: it calls the app to create, update and disable users. From the app's admin console (usually under Security, SSO or Provisioning) you need two things: the SCIM base URL and a credential.",
        fields: [
          { key: "appName", label: "App name", placeholder: "Expense Portal", help: "The enterprise application this provisioning belongs to. Use the same app that already does single sign-on." },
          {
            key: "tenantUrl",
            label: "SCIM base URL (Tenant URL)",
            placeholder: "https://expenses.contoso.example/scim/v2",
            help: "The root of the app's SCIM API. Entra adds /Users and /Groups to it.",
            pitfall: "Including /Users in this URL, or leaving out /scim/v2, gives 404 on every request.",
            validate: https,
          },
          { key: "auth", label: "How Entra authenticates", type: "select", options: ["Long-lived bearer token", "OAuth 2.0 client credentials"], help: "A bearer token is one secret string pasted into Entra. Client credentials is safer because tokens are short-lived and refreshed automatically; use it when the app supports it." },
          { key: "tokenExpires", label: "Token or secret expiry date", type: "date", help: "When the credential stops working.", pitfall: "When it expires there is no sign-in error. Provisioning just stops: joiners get no account and leavers keep theirs." },
        ],
        why: "The credential lets Entra create and disable accounts in the app, so it is as sensitive as an admin password. Generate it with a service or break-glass admin account, not a personal one that will be offboarded.",
      },
      {
        title: "Choose the one identifier both sides will use",
        explain:
          "This is the step that prevents “user not found”. At sign-in the app receives an identifier (the SAML NameID, or a claim such as preferred_username). SCIM writes the account's userName. The app can only connect a sign-in to an account when those two values are the same.",
        fields: [
          { key: "sso", label: "How users sign in to this app", type: "select", options: ["SAML", "OpenID Connect"], help: "The protocol the app already uses for single sign-on." },
          { key: "signInSource", label: "Sign-in identifier comes from", placeholder: "user.userprincipalname", help: "SAML: the source of Unique User Identifier (Name ID) under Attributes & Claims. OIDC: the claim the app matches on." },
          {
            key: "userNameSource",
            label: "SCIM userName comes from",
            placeholder: "userPrincipalName",
            help: "The directory attribute mapped to userName in the provisioning attribute mapping. Entra's default is userPrincipalName.",
            pitfall: "If sign-in sends the UPN and userName is filled from mail, every user whose UPN and email differ is locked out of the app.",
            validate: (v, all) => {
              const n = (x: string) => x.toLowerCase().replace(/^user\./, "").trim();
              return v && all.signInSource && n(v) !== n(all.signInSource) ? `Different from the sign-in source (${all.signInSource}). Use the same attribute for both unless you are certain the values are always equal.` : null;
            },
          },
          { key: "matchAttribute", label: "Match existing accounts on", type: "select", options: ["userName", "externalId"], help: "Before creating anyone, Entra searches the app for this attribute. A match links to the existing account; no match creates a new one.", pitfall: "Matching on externalId when existing accounts have none makes Entra try to create duplicates (409 Conflict)." },
        ],
        why: "Sign-in and provisioning are configured on different screens and often by different people. Writing the shared identifier down once is what keeps them aligned.",
      },
      {
        title: "Connect Entra to the app",
        where: "Entra admin center > Entra ID > Enterprise apps > your app > Provisioning",
        explain: "Give Entra the URL and credential, and prove they work before going further.",
        actions: [
          "Select New configuration (older tenants: Get started, then set Provisioning Mode to Automatic).",
          "Paste the SCIM base URL into Tenant URL.",
          "Paste the token into Secret Token. Paste the token only, without the word Bearer and without spaces.",
          "Select Test connection. Entra calls the app and reports success or the HTTP error.",
          "Select Create or Save.",
        ],
        fields: [
          { key: "flag", label: "Send standard PATCH requests", type: "select", options: ["Yes, add ?aadOptscim062020 to the Tenant URL", "No, use Entra's default format"], help: "By default Entra sends op as Add/Replace/Remove and active as the text \"False\". The flag makes it send the standard lower-case ops and a real true/false.", pitfall: "Without the flag, strict apps answer 400, and some loose ones read \"False\" as true, so leavers stay enabled." },
        ],
        why: "Test connection only proves the URL and credential. It doesn't prove users will be created correctly; the on-demand test in step 6 does that.",
      },
      {
        title: "Review the attribute mappings",
        where: "Provisioning > Attribute mapping (or Mappings) > Provision Microsoft Entra ID Users",
        explain: "Mappings decide what Entra writes into each SCIM attribute. Keep the list short: every extra attribute is another way for the app to reject a request.",
        actions: [
          "Confirm userName is mapped from the source you chose in step 2.",
          "Open the mapping for your matching attribute and set “Match objects using this attribute” to Yes with precedence 1.",
          "Leave the active mapping as it is. It turns a disabled or deleted Entra user into active = false, which is how leavers lose access.",
          "Delete mappings for attributes the app doesn't support (check the vendor's SCIM documentation).",
          "If the app compares userName case-sensitively, change the mapping to an expression: ToLower([userPrincipalName]).",
          "If the app has no group feature, disable Provision Microsoft Entra ID Groups.",
        ],
        why: "Entra's defaults: userPrincipalName to userName, mail to emails[type eq \"work\"].value, mailNickname to externalId, and a Switch on IsSoftDeleted to active.",
      },
      {
        title: "Set who gets an account",
        where: "Provisioning > Settings > Scope, and the app's Users and groups page",
        explain: "Scope decides which users Entra sends. Assignment is also what allows a user to sign in, so one assignment controls both gates.",
        fields: [
          { key: "scope", label: "Scope", type: "select", options: ["Sync only assigned users and groups", "Sync all users and groups"], help: "Assigned-only is the safe choice: an account exists in the app only for people you assigned." },
          { key: "notify", label: "Failure notification email", placeholder: "identity-team@contoso.example", help: "Entra emails this address when the job goes into quarantine." },
        ],
        actions: [
          "On Users and groups, assign one test user first.",
          "Remember that members of nested groups are not provisioned, and that assigning groups needs Entra ID P1 or higher.",
        ],
        why: "“Sync all” creates an account, and may consume a paid licence in the app, for every user in the directory.",
      },
      {
        title: "Test with one user",
        where: "Provisioning > Provision on demand",
        explain: "Provision on demand runs the whole process for a single user immediately and shows every step: import, scope check, match, and the action sent to the app.",
        actions: [
          "Select the test user and choose Provision.",
          "Open the Perform action step and view its details. Copy the request and response into the SCIM checker.",
          "In the SCIM checker, enter the identifier the app receives at sign-in and confirm the comparison shows an exact match on userName.",
          "Sign in to the app as the test user in a private window.",
          "Unassign the test user, provision on demand again, and confirm the app shows the account as inactive.",
        ],
        why: "Testing the leaver path now is the only way to know it works. Nobody reports an account that should have been disabled.",
      },
      {
        title: "Turn it on and watch the first cycle",
        where: "Provisioning > Start provisioning, then Provisioning logs",
        explain: "The first cycle evaluates every user in scope and can take from minutes to hours. After that, incremental cycles run about every 40 minutes.",
        actions: [
          "Assign the real users or groups, then select Start provisioning.",
          "In Provisioning logs, filter Status to Failure and Skipped. Open each distinct error once and look it up in Playbooks.",
          "Put the credential's expiry date in your calendar and in the inventory entry this wizard creates.",
        ],
      },
    ],
    outputs: (v) => {
      const flag = (v.flag ?? "Yes").startsWith("Yes");
      const base = T(v, "tenantUrl");
      const url = flag && v.tenantUrl ? `${v.tenantUrl.trim().replace(/\?.*$/, "")}?aadOptscim062020` : base;
      const match = T(v, "matchAttribute", "userName");
      const src = T(v, "userNameSource", "userPrincipalName");
      return [
        {
          title: "Entra provisioning settings",
          body: `Enterprise app:   ${T(v, "appName")}
Provisioning mode: Automatic
Tenant URL:       ${url}
Authentication:   ${T(v, "auth", "Long-lived bearer token")}
Secret Token:     (paste in Entra only; never store it here)
Credential expiry: ${T(v, "tokenExpires", "(record it!)")}
Scope:            ${T(v, "scope", "Sync only assigned users and groups")}
Notify on failure: ${T(v, "notify", "(none)")}`,
        },
        {
          title: "Identifier agreement",
          body: `Sign-in (${T(v, "sso", "SAML")}) sends:  ${T(v, "signInSource", "user.userprincipalname")}
SCIM userName from:     ${src}
Match existing users on: ${match}  (precedence 1)

These two sources must produce the same value for every user.`,
        },
        {
          title: "Attribute mapping (minimum)",
          body: `${src.padEnd(22)} -> userName
Switch([IsSoftDeleted], , "False", "True", "True", "False") -> active
mail                   -> emails[type eq "work"].value
givenName              -> name.givenName
surname                -> name.familyName
mailNickname           -> externalId`,
        },
        {
          title: "Check the endpoint yourself (PowerShell 7)",
          body: `$base  = '${base.replace(/\?.*$/, "")}'
$token = Read-Host -AsSecureString 'SCIM token (hidden)'
$upn   = 'test.user@contoso.example'

# 1. Is this a SCIM endpoint, and what does it support?
Invoke-RestMethod "$base/ServiceProviderConfig" -Authentication Bearer -Token $token | ConvertTo-Json -Depth 5

# 2. The same lookup Entra does before it creates a user
$filter = [uri]::EscapeDataString("${match} eq \`"$upn\`"")
Invoke-RestMethod "$base/Users?filter=$filter" -Authentication Bearer -Token $token | ConvertTo-Json -Depth 8`,
        },
      ];
    },
    testPlan: [
      "Test connection succeeds.",
      "Provision on demand creates the test user; the provisioning log shows Create with status Success.",
      "SCIM checker shows an exact match between userName and the identifier sent at sign-in.",
      "The test user signs in to the app and lands in their own account, not a new empty one.",
      "Changing the user's job title in Entra reaches the app within one cycle (about 40 minutes).",
      "Unassigning the user sets active to false in the app, and the user can no longer use it.",
      "The credential's expiry date is recorded in the inventory and on a calendar.",
    ],
    toApp: (v) => {
      const oidc = (v.sso ?? "SAML") === "OpenID Connect";
      return {
        name: v.appName || "SCIM app",
        protocol: oidc ? "oidc" : "saml",
        provisioning: "scim",
        status: "testing",
        saml: { ...emptySaml(), nameIdSource: oidc ? "" : v.signInSource || "user.userprincipalname" },
        scim: {
          ...emptyScim(),
          endpoint: v.tenantUrl?.trim() || "",
          tokenExpires: v.tokenExpires || "",
          matchAttribute: v.matchAttribute || "userName",
          userNameSource: v.userNameSource || "userPrincipalName",
        },
        notes: [`Provisioning scope: ${v.scope || "Sync only assigned users and groups"}.`, (v.flag ?? "Yes").startsWith("Yes") ? "Tenant URL uses ?aadOptscim062020 (standard PATCH)." : "", v.notify ? `Quarantine notifications go to ${v.notify}.` : ""].filter(Boolean).join("\n"),
      };
    },
  },
  // ---------------------------------------------------------------
  {
    id: "entra-oidc",
    title: "OpenID Connect sign-in for a web app (auth code + PKCE)",
    protocol: "oidc",
    platform: "Microsoft Entra ID",
    summary: "Register an app in Entra and connect a web or single-page app using the authorization code flow with PKCE.",
    minutes: 20,
    youWillLearn: ["Client ID vs tenant ID vs object ID", "Why redirect URIs must match exactly", "Which token the app gets and what to check in it"],
    steps: [
      {
        title: "Decide the app type",
        explain:
          "A confidential client runs on a server and can keep a secret (e.g. ASP.NET, Node server). A public client runs on the user's device (single-page apps, mobile, desktop) and cannot keep a secret, so it relies on PKCE alone.",
        fields: [
          { key: "appName", label: "App name", placeholder: "Partner Portal", help: "Shown on the consent screen." },
          { key: "clientType", label: "Client type", type: "select", options: ["confidential (Web)", "public (SPA)"], help: "Determines the platform and whether a secret is needed." },
        ],
      },
      {
        title: "Register the application",
        where: "Entra admin center > Identity > Applications > App registrations > New registration",
        explain: "Pick 'Accounts in this organizational directory only' (single tenant) unless partners from other tenants must sign in. Add the first redirect URI under the right platform.",
        fields: [
          {
            key: "redirectUri",
            label: "Redirect URI",
            placeholder: "https://partners.contoso.example/signin-oidc",
            help: "Where Entra sends the authorization code. Register it under Web for confidential apps and Single-page application for SPAs.",
            pitfall: "Must match the redirect_uri the app sends exactly, or AADSTS50011. Registering a SPA URI under Web causes AADSTS9002326.",
            validate: https,
          },
          { key: "clientId", label: "Application (client) ID", placeholder: "5d1e2f3a-…", help: "From the app's Overview page after registering. Identifies the app in every request.", validate: guid },
          { key: "tenantId", label: "Directory (tenant) ID", placeholder: "8f2b6c1e-…", help: "Also on Overview. Forms the authority URL.", validate: guid },
        ],
      },
      {
        title: "Authentication settings",
        where: "App registration > Authentication",
        explain: "Leave the implicit grant checkboxes off; auth code + PKCE doesn't need them. Add a front-channel logout URL if the app supports sign-out notification.",
        actions: ["Check the redirect URI is under the right platform.", "Add localhost URIs only to dev registrations, not production."],
      },
      {
        title: "Client credential (confidential apps only)",
        where: "App registration > Certificates & secrets",
        explain: "Confidential apps prove who they are when redeeming the code. A certificate is safer than a secret. If you use a secret, copy its Value (not the Secret ID) into a key vault right away.",
        fields: [{ key: "secretExpires", label: "Secret/certificate expiry", type: "date", help: "Max 24 months for secrets. Expired secret = outage (AADSTS7000222)." }],
      },
      {
        title: "API permissions and claims",
        where: "App registration > API permissions, and Token configuration",
        explain: "For sign-in you need the OIDC scopes openid, profile, email (and offline_access for refresh tokens). Add optional claims (e.g. email, groups) under Token configuration.",
        fields: [{ key: "scopes", label: "Scopes requested", placeholder: "openid profile email offline_access", help: "Space separated. Add an API's scopes if the app calls an API." }],
      },
      {
        title: "Configure the app and test",
        explain: "Put the values below into the app's OIDC settings (most libraries need just authority, client ID, redirect URI and scopes). Sign in, then paste the ID token into the JWT tool with this app selected: aud must be the client ID and iss the v2.0 issuer.",
        actions: ["Sign in as a test user.", "Decode the ID token.", "Save to inventory."],
      },
    ],
    outputs: (v) => {
      const t = T(v, "tenantId", "{tenant-id}");
      const c = T(v, "clientId", "{client-id}");
      const r = T(v, "redirectUri", "{redirect-uri}");
      const s = T(v, "scopes", "openid profile email");
      return [
        {
          title: "App settings",
          body: `Authority:     https://login.microsoftonline.com/${t}/v2.0
Discovery:     https://login.microsoftonline.com/${t}/v2.0/.well-known/openid-configuration
Client ID:     ${c}
Redirect URI:  ${r}
Scopes:        ${s}
Expected iss:  https://login.microsoftonline.com/${t}/v2.0
Expected aud:  ${c}`,
        },
        {
          title: "What the authorize request looks like",
          body: `https://login.microsoftonline.com/${t}/oauth2/v2.0/authorize
  ?client_id=${c}
  &response_type=code
  &redirect_uri=${encodeURIComponent(r)}
  &scope=${encodeURIComponent(s)}
  &state=<random>
  &nonce=<random>
  &code_challenge=<BASE64URL(SHA256(code_verifier))>
  &code_challenge_method=S256`,
        },
      ];
    },
    testPlan: [
      "Sign-in completes and returns to the redirect URI.",
      "ID token: iss, aud, exp, nonce all correct (JWT tool shows no red findings).",
      "Sign-out works.",
      "Production registration has no localhost or wildcard redirect URIs.",
      "Secret expiry recorded in the inventory with an owner.",
    ],
    toApp: (v) => ({
      name: v.appName || "New OIDC app",
      protocol: "oidc",
      status: "testing",
      oidc: {
        ...emptyOidc(),
        clientId: v.clientId || "",
        redirectUris: v.redirectUri || "",
        clientType: v.clientType?.startsWith("public") ? "public" : "confidential",
        grantType: "authorization_code",
        scopes: v.scopes || "openid profile email",
        audience: v.clientId || "",
        issuer: v.tenantId ? `https://login.microsoftonline.com/${v.tenantId.trim()}/v2.0` : "",
        secretExpires: v.secretExpires || "",
      },
    }),
  },
  // ---------------------------------------------------------------
  {
    id: "entra-client-credentials",
    title: "OAuth client credentials: a script or service calling Microsoft Graph",
    protocol: "oauth",
    platform: "Microsoft Entra ID",
    summary: "App-only access for automation (no user signed in), with application permissions, admin consent and ready-to-run PowerShell and Python.",
    minutes: 20,
    youWillLearn: ["Delegated vs application permissions", "Why scope is /.default", "How to read the roles claim in the token"],
    steps: [
      {
        title: "Delegated or application permissions?",
        explain:
          "Delegated permissions act on behalf of a signed-in user and can never exceed what that user can do. Application permissions let the app act as itself across the whole tenant. Client credentials always uses application permissions, so grant only what's needed.",
        why: "Overly broad application permissions on automation accounts are a common audit finding.",
      },
      {
        title: "Register the app",
        where: "App registrations > New registration (no redirect URI needed)",
        explain: "Name it after the job and owner, for example 'svc-payroll-sync (HR Systems)'.",
        fields: [
          { key: "appName", label: "App name", placeholder: "Payroll sync job", help: "Make the purpose obvious for future reviewers." },
          { key: "clientId", label: "Application (client) ID", placeholder: "a7b8c9d0-…", help: "From Overview.", validate: guid },
          { key: "tenantId", label: "Directory (tenant) ID", placeholder: "8f2b6c1e-…", help: "From Overview.", validate: guid },
        ],
      },
      {
        title: "Add a credential",
        where: "Certificates & secrets",
        explain: "Prefer a certificate (or a managed identity if the code runs in Azure, or workload identity federation for GitHub Actions/AWS). If you use a secret, store it in a vault, never in the script.",
        fields: [{ key: "secretExpires", label: "Credential expiry", type: "date", help: "Track it. An expired credential stops the job." }],
      },
      {
        title: "Grant application permissions",
        where: "API permissions > Add a permission > Microsoft Graph > Application permissions",
        explain: "Add only what the job needs, then click 'Grant admin consent for <tenant>'. Without admin consent the token has no roles and Graph returns 403.",
        fields: [{ key: "permissions", label: "Application permissions", placeholder: "User.Read.All", help: "Comma separated. These appear in the token's roles claim." }],
      },
      {
        title: "Request a token and call the API",
        explain: "The scope for client credentials is always the resource plus /.default, which means 'all application permissions already granted'. Run one of the samples, then paste the token into the JWT tool: roles should list your permissions and aud should be Graph.",
        actions: ["Run the sample.", "Decode the token.", "Save to inventory."],
      },
    ],
    outputs: (v) => {
      const t = T(v, "tenantId", "{tenant-id}");
      const c = T(v, "clientId", "{client-id}");
      return [
        {
          title: "Raw token request",
          body: `POST https://login.microsoftonline.com/${t}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=${c}
&client_secret=<from your vault>
&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default`,
        },
        {
          title: "PowerShell",
          lang: "powershell",
          body: `# Secret comes from a vault or secure prompt, never hard-coded.
$tenantId = "${t}"
$clientId = "${c}"
$secret   = Read-Host -AsSecureString "Client secret"
$plain    = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
              [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret))

try {
  $token = Invoke-RestMethod -Method Post \`
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" \`
    -Body @{
      grant_type    = "client_credentials"
      client_id     = $clientId
      client_secret = $plain
      scope         = "https://graph.microsoft.com/.default"
    }
  $headers = @{ Authorization = "Bearer $($token.access_token)" }
  $users = Invoke-RestMethod -Headers $headers \`
    -Uri "https://graph.microsoft.com/v1.0/users?\`$top=5&\`$select=displayName,userPrincipalName"
  $users.value | Format-Table displayName, userPrincipalName
}
catch {
  # The response body carries error, error_description (with the AADSTS code) and correlation_id
  Write-Error $_.ErrorDetails.Message
}`,
        },
        {
          title: "Python (msal)",
          lang: "python",
          body: `# pip install msal requests
import os, msal, requests

app = msal.ConfidentialClientApplication(
    client_id="${c}",
    authority="https://login.microsoftonline.com/${t}",
    client_credential=os.environ["CLIENT_SECRET"],  # inject from a vault / CI secret
)
result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
if "access_token" not in result:
    raise SystemExit(f"{result.get('error')}: {result.get('error_description')}")

r = requests.get(
    "https://graph.microsoft.com/v1.0/users?$top=5&$select=displayName,userPrincipalName",
    headers={"Authorization": f"Bearer {result['access_token']}"},
    timeout=30,
)
r.raise_for_status()
for u in r.json()["value"]:
    print(u["displayName"], u["userPrincipalName"])`,
        },
      ];
    },
    testPlan: [
      "Token request succeeds; JWT tool shows roles with exactly the granted permissions.",
      "Graph call returns data (403 means missing permission or no admin consent).",
      "Credential is in a vault, with expiry and owner recorded in the inventory.",
      "Service principal is included in your periodic access review.",
    ],
    toApp: (v) => ({
      name: v.appName || "New daemon app",
      protocol: "oauth",
      status: "testing",
      oidc: {
        ...emptyOidc(),
        clientId: v.clientId || "",
        clientType: "confidential",
        grantType: "client_credentials",
        scopes: "https://graph.microsoft.com/.default",
        audience: "https://graph.microsoft.com",
        issuer: v.tenantId ? `https://sts.windows.net/${v.tenantId.trim()}/` : "",
        secretExpires: v.secretExpires || "",
      },
      notes: v.permissions ? `Application permissions: ${v.permissions}` : "",
    }),
  },
];

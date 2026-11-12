import type { ProtocolId } from "../lib/types";

export interface FlowStep {
  from: number;
  to: number;
  label: string;
  note?: string;
}

export interface Flow {
  id: string;
  title: string;
  protocol: ProtocolId;
  actors: string[];
  intro: string;
  steps: FlowStep[];
  watch: string[];
}

export const FLOWS: Flow[] = [
  {
    id: "saml-sp",
    title: "SAML, SP-initiated sign-in",
    protocol: "saml",
    actors: ["User's browser", "App (SP)", "Entra ID (IdP)"],
    intro: "The user starts at the app. The app sends them to the IdP with a request; the IdP sends them back with a signed assertion. The browser carries everything; the app and IdP never talk directly.",
    steps: [
      { from: 0, to: 1, label: "Open app", note: "No session yet" },
      { from: 1, to: 0, label: "302 to IdP + SAMLRequest", note: "AuthnRequest: Issuer = SP entity ID, ACS URL, ID" },
      { from: 0, to: 2, label: "GET /saml2?SAMLRequest=…", note: "Redirect binding (deflated + base64)" },
      { from: 2, to: 2, label: "Sign in, MFA, Conditional Access", note: "AADSTS errors appear here" },
      { from: 2, to: 0, label: "HTML form with SAMLResponse", note: "Signed assertion: Audience, Recipient, NameID" },
      { from: 0, to: 1, label: "POST to ACS URL", note: "Capture this in dev tools for the decoder" },
      { from: 1, to: 1, label: "Validate signature, audience, time", note: "App-side errors appear here" },
      { from: 1, to: 0, label: "Session cookie, user is in" },
    ],
    watch: ["Request Issuer must match the Identifier at Entra.", "ACS URL in the request must be a registered Reply URL.", "Response Audience/Recipient must match what the app expects.", "Clock skew breaks the validity window."],
  },
  {
    id: "saml-idp",
    title: "SAML, IdP-initiated sign-in",
    protocol: "saml",
    actors: ["User's browser", "App (SP)", "Entra ID (IdP)"],
    intro: "The user clicks a tile in My Apps. There's no request, so the response has no InResponseTo. Some apps refuse this as 'unsolicited'.",
    steps: [
      { from: 0, to: 2, label: "Click tile in My Apps" },
      { from: 2, to: 0, label: "HTML form with SAMLResponse", note: "No InResponseTo" },
      { from: 0, to: 1, label: "POST to ACS URL" },
      { from: 1, to: 0, label: "Session cookie" },
    ],
    watch: ["Setting a Sign on URL in Entra turns My Apps clicks into SP-initiated sign-ins, which more apps accept."],
  },
  {
    id: "oidc-code",
    title: "OIDC authorization code + PKCE",
    protocol: "oidc",
    actors: ["User's browser", "App", "Entra ID"],
    intro: "The app redirects the user to sign in and gets back a one-time code. It then swaps the code for tokens directly with Entra (back channel). PKCE proves the same app started and finished the flow.",
    steps: [
      { from: 0, to: 1, label: "Open app" },
      { from: 1, to: 0, label: "302 to /authorize", note: "client_id, redirect_uri, scope, state, nonce, code_challenge" },
      { from: 0, to: 2, label: "GET /authorize" },
      { from: 2, to: 2, label: "Sign in, consent", note: "AADSTS50011 / 65001 here" },
      { from: 2, to: 0, label: "302 to redirect_uri?code=…&state=…" },
      { from: 0, to: 1, label: "GET redirect_uri with code" },
      { from: 1, to: 2, label: "POST /token", note: "code + code_verifier (+ secret if confidential)" },
      { from: 2, to: 1, label: "id_token, access_token, refresh_token" },
      { from: 1, to: 1, label: "Validate id_token: iss, aud, exp, nonce, signature" },
    ],
    watch: ["redirect_uri must match exactly in both requests.", "state and nonce must round-trip (cookies + SameSite).", "SPAs must register under the SPA platform."],
  },
  {
    id: "oauth-cc",
    title: "OAuth client credentials (app-only)",
    protocol: "oauth",
    actors: ["Script / service", "Entra ID", "API (e.g. Graph)"],
    intro: "No user and no browser. The app authenticates as itself and gets an access token containing its application permissions (roles).",
    steps: [
      { from: 0, to: 1, label: "POST /token", note: "grant_type=client_credentials, scope=<resource>/.default, secret or cert" },
      { from: 1, to: 0, label: "access_token (roles claim)" },
      { from: 0, to: 2, label: "GET /v1.0/users  Authorization: Bearer …" },
      { from: 2, to: 2, label: "Validate token: aud, iss, roles" },
      { from: 2, to: 0, label: "200 data, or 401/403" },
    ],
    watch: ["Admin consent is required for application permissions.", "Track the secret/certificate expiry.", "403 = valid token but missing permission; 401 = token itself rejected."],
  },
];

export const GLOSSARY: { term: string; protocols: ProtocolId[]; def: string }[] = [
  { term: "Identity provider (IdP)", protocols: ["saml", "oidc", "oauth"], def: "The system that authenticates users and issues assertions or tokens. Entra ID, Okta, Ping, AD FS. In OAuth it's called the authorization server." },
  { term: "Service provider (SP) / Relying party (RP)", protocols: ["saml", "oidc"], def: "The application that trusts the IdP. SAML says SP, OIDC says relying party or client." },
  { term: "Entity ID", protocols: ["saml"], def: "A unique name for a SAML party. The SP's entity ID is the 'Identifier' in Entra and appears as the Audience. The IdP's entity ID is the Issuer." },
  { term: "ACS URL (Reply URL)", protocols: ["saml"], def: "Assertion Consumer Service. The SP endpoint that receives the SAML response via HTTP POST." },
  { term: "Assertion", protocols: ["saml"], def: "The signed XML statement inside a SAML response: who the user is (NameID), attributes, audience, and validity window." },
  { term: "NameID", protocols: ["saml"], def: "The user identifier in an assertion. Entra calls it the Unique User Identifier. The SP matches accounts on it." },
  { term: "Binding", protocols: ["saml"], def: "How a SAML message travels: HTTP-Redirect (in the URL, deflated), HTTP-POST (in a form), or Artifact." },
  { term: "RelayState", protocols: ["saml"], def: "An opaque value passed alongside the SAML message, usually the page to land on after sign-in." },
  { term: "Metadata", protocols: ["saml"], def: "An XML file describing a party: entity ID, endpoints and certificates. Exchanging metadata avoids copy-paste errors." },
  { term: "Client ID", protocols: ["oidc", "oauth"], def: "The app's public identifier at the IdP. In Entra, the Application (client) ID GUID." },
  { term: "Client secret / certificate", protocols: ["oidc", "oauth"], def: "The credential a confidential client uses at the token endpoint. Certificates and workload identity federation are safer than secrets." },
  { term: "Redirect URI", protocols: ["oidc", "oauth"], def: "Where the IdP sends the user back with a code. Must exactly match a registered value." },
  { term: "Scope", protocols: ["oidc", "oauth"], def: "A permission the app requests. openid/profile/email are OIDC scopes; User.Read or api://x/Read are API scopes; /.default means 'everything already granted'." },
  { term: "Consent", protocols: ["oidc", "oauth"], def: "Approval for an app to use permissions. Users can consent to low-risk delegated permissions if policy allows; admins must consent to application permissions." },
  { term: "ID token", protocols: ["oidc"], def: "A JWT telling the app who signed in. Its audience is the app's client ID. Never send it to an API." },
  { term: "Access token", protocols: ["oauth"], def: "A credential for calling an API. Its audience is the API. Clients should treat it as opaque." },
  { term: "Refresh token", protocols: ["oidc", "oauth"], def: "Long-lived credential used to get new access tokens without user interaction. Revoked by password reset or admin action." },
  { term: "JWT", protocols: ["oidc", "oauth"], def: "JSON Web Token: header.payload.signature, each base64url encoded. Signed, usually not encrypted, so anyone holding it can read it." },
  { term: "JWKS", protocols: ["oidc", "oauth"], def: "JSON Web Key Set: the IdP's public signing keys, published at jwks_uri. Tokens name their key with kid." },
  { term: "Discovery document", protocols: ["oidc", "oauth"], def: ".well-known/openid-configuration: lists the issuer, endpoints and supported features. Libraries configure themselves from it." },
  { term: "PKCE", protocols: ["oidc", "oauth"], def: "Proof Key for Code Exchange. The app sends a hash (code_challenge) when it starts and the original (code_verifier) when it redeems the code, so a stolen code is useless." },
  { term: "Issuer (iss)", protocols: ["saml", "oidc", "oauth"], def: "Who issued the token or assertion. Must exactly match what the app trusts." },
  { term: "Audience (aud)", protocols: ["saml", "oidc", "oauth"], def: "Who the token or assertion is meant for. The receiver must reject anything not addressed to it." },
  { term: "Delegated vs application permissions", protocols: ["oauth"], def: "Delegated: the app acts for a signed-in user (scp claim). Application: the app acts as itself (roles claim), tenant-wide." },
  { term: "Service principal / Enterprise application", protocols: ["saml", "oidc", "oauth"], def: "The app's instance in a tenant, where assignment, consent and Conditional Access apply. The app registration is the global definition." },
  { term: "Conditional Access", protocols: ["saml", "oidc", "oauth"], def: "Entra policies evaluated at sign-in (who, what app, where, which device) that grant, block, or require MFA or a compliant device." },
  { term: "Clock skew", protocols: ["saml", "oidc", "oauth"], def: "Difference between two systems' clocks. Validators allow a few minutes; beyond that, valid tokens look expired." },
  { term: "SCIM", protocols: ["scim"], def: "System for Cross-domain Identity Management. A REST API standard for creating, updating and deleting users and groups in apps. Coming in a later module." },
  { term: "JIT provisioning", protocols: ["saml", "oidc"], def: "Just-in-time: the app creates the account on first sign-in from the assertion's attributes. Simple, but doesn't remove leavers." },
];

export const METHOD = [
  { title: "Get the exact error", body: "Screenshot the full error, including the AADSTS code, Correlation ID, Request ID and timestamp. 'SSO is broken' isn't enough to start." },
  { title: "Find out who failed: IdP or app", body: "Error on login.microsoftonline.com (or your IdP's page) = the IdP refused. Error on the app's page after the redirect back = the app refused the assertion or token." },
  { title: "Read the IdP's logs", body: "Entra sign-in logs: search by Correlation ID or user. The Basic info, Conditional Access and Troubleshooting tabs usually name the cause." },
  { title: "Capture the message", body: "Browser developer tools > Network > Preserve log. For SAML grab the SAMLRequest (redirect) and SAMLResponse (POST to the ACS). For OIDC grab the authorize URL and the tokens." },
  { title: "Decode and compare", body: "Use the decoders here with the app selected. They compare issuer, audience, ACS, time window and certificate against the inventory." },
  { title: "Change one thing, retest, record", body: "Fix the single mismatch, test in a private window, then update the inventory and note what happened. That record becomes your runbook." },
];

export const SKILLS_MAP = [
  { skill: "Build and troubleshoot integrations using SAML, OpenID Connect, OAuth", where: "Wizards, SAML decoder, JWT decoder, Playbooks", route: "wizards" },
  { skill: "Entra ID SSO, federation, MFA, Conditional Access", where: "Entra SAML and OIDC wizards; AADSTS playbooks for MFA and Conditional Access", route: "playbooks" },
  { skill: "AWS workforce federation, IAM Identity Center, permission sets", where: "Entra to AWS IAM Identity Center wizard; AWS playbooks", route: "wizards" },
  { skill: "Credential lifecycle for app identities and service accounts", where: "Inventory expiry tracking and the client credentials wizard", route: "inventory" },
  { skill: "PowerShell / Python and REST APIs such as Microsoft Graph", where: "Generated PowerShell and Python in the client credentials wizard", route: "wizards" },
  { skill: "Identity service reliability, root-cause resolution", where: "Troubleshooting method below and the playbooks", route: "playbooks" },
  { skill: "SCIM provisioning and joiner/mover/leaver", where: "Next module (planned). AWS wizard already covers SCIM setup.", route: "learn" },
];

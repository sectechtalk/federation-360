// Learn page: "SSO vs OAuth vs OIDC vs SAML", the first topic. The animation lives in src/assets/learn and is drawn by
// tools/identity-gif (original artwork in Federation 360's own colours). This text is the same story, for screen
// readers, for anyone who prefers reading, and for reduced-motion users, who see a still picture instead.
import type { ProtocolId } from "../lib/types";

export const BASICS_ID = "sso-oauth-oidc-saml";
export const BASICS_TITLE = "SSO vs OAuth vs OIDC vs SAML";
export const BASICS_INTRO =
  "Four names you hear every day that answer two different questions. Authentication proves who you are: OpenID Connect and SAML 2.0 do that. Authorization decides what an app may do for you: OAuth 2.0 does that. SSO is the experience of signing in once and using many apps, and it is built on the other three.";

export const BASICS_ALT =
  "Animation in seven scenes: SSO, OAuth 2.0, OpenID Connect and SAML 2.0 step by step, how they work together in one sign-in, and a cheat sheet. The same content is written out below the animation.";

export interface BasicsCard {
  name: string;
  role: string;
  protocol?: ProtocolId;
  what: string;
  token: string;
  use: string;
  steps: string[];
  takeaway: string;
}

export const BASICS_CARDS: BasicsCard[] = [
  {
    name: "SSO (single sign-on)",
    role: "The experience",
    what: "Sign in once, use many apps. Not a protocol.",
    token: "The identity provider's session, plus a SAML assertion or OIDC ID token for each app",
    use: "No second password prompt across your work apps",
    steps: [
      "Without SSO, every app asks for its own password.",
      "With SSO you sign in once, at your identity provider (for example Microsoft Entra ID), with your password and MFA.",
      "The identity provider keeps a session, so it remembers that you already signed in.",
      "When you open another app, it asks the identity provider, which vouches for you. No password prompt.",
    ],
    takeaway: "SSO is the experience, not a protocol. Underneath, each app uses SAML 2.0 or OpenID Connect to trust the identity provider.",
  },
  {
    name: "OAuth 2.0",
    role: "Authorization",
    protocol: "oauth",
    what: "Lets an app call an API on your behalf, with only the permission (scope) you approved.",
    token: "Access token, meant for the API",
    use: "An app reading your mail or calendar",
    steps: [
      "The app sends you to the authorization server and names what it wants, the scope (for example Calendars.Read).",
      "The authorization server signs you in and asks you to approve. OAuth 2.0 itself does not define how you sign in.",
      "You approve. You never give your password to the app.",
      "The app gets a short-lived, one-time authorization code back through your browser.",
      "The app swaps the code for an access token on a direct back-channel call, with its secret, certificate or PKCE verifier.",
      "The app calls the API with the access token. The API checks the signature, audience, expiry and scope, and returns only what the scope allows.",
    ],
    takeaway: "OAuth 2.0 grants access, not identity. The access token is meant for the API, not for the app to learn who you are.",
  },
  {
    name: "OpenID Connect (OIDC)",
    role: "Authentication",
    protocol: "oidc",
    what: "An identity layer on top of OAuth 2.0.",
    token: "ID token (a JWT), meant for the app",
    use: "Modern web, mobile and SaaS sign-in",
    steps: [
      "The app sends you to the OpenID provider and asks for the openid scope, which turns OAuth 2.0 into an OIDC sign-in.",
      "You sign in at the OpenID provider, never at the app.",
      "The app gets a one-time code back through your browser and swaps it at the token endpoint, exactly as in OAuth 2.0.",
      "It gets two tokens: an ID token for itself, and an access token for calling APIs.",
      "The app validates the ID token: signature, iss, aud (must be its own client ID), exp and nonce. Now it knows who you are.",
    ],
    takeaway: "OIDC = OAuth 2.0 + an ID token. The ID token is for the app, and it says who signed in.",
  },
  {
    name: "SAML 2.0",
    role: "Authentication",
    protocol: "saml",
    what: "Signed XML assertions carried by the browser.",
    token: "SAML assertion, meant for the app (the service provider)",
    use: "Enterprise SSO to business apps",
    steps: [
      "You open the app (the service provider). It does not know you yet.",
      "The app sends your browser to the identity provider with a SAML AuthnRequest. The app and the identity provider never talk directly.",
      "You sign in at the identity provider, or it reuses the SSO session you already have.",
      "The identity provider returns a signed SAML response (XML) inside a form that submits itself to the app's Assertion Consumer Service (ACS) URL.",
      "The app checks the signature with the identity provider's certificate, the audience and the time window, then lets you in.",
    ],
    takeaway: "SAML 2.0 sends signed XML assertions through the browser. It is the workhorse of enterprise SSO to business apps.",
  },
];

export const BASICS_TOGETHER = [
  "You open the expenses app at work.",
  "SSO: you signed in to Entra ID earlier this morning, so there is no password prompt.",
  "Authentication: OIDC or SAML 2.0 tells the app who you are.",
  "Authorization: OAuth 2.0 gives the app an access token for the API it calls on your behalf.",
  "The API checks the access token and returns only what the app is allowed to see.",
];

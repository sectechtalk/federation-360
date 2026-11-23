// Learn topic: Device SSO (macOS Platform SSO, Windows PRT).
// Facts are grounded in Microsoft Learn; the pages used are listed in DEVICE_SSO_SOURCES.
// Device sign-in sits in front of app federation, so this is a Learn topic, not a tool:
// it needs Intune and a Mac or Entra-joined Windows PC, which the free lab tenant doesn't have.
import type { Flow } from "./learn";

export const DEVICE_SSO_TITLE = "Device SSO (macOS Platform SSO, Windows PRT)";

export const DEVICE_SSO_INTRO =
  "Everything else on this page is app federation: one app trusting Entra through SAML, OpenID Connect or OAuth. Device SSO is the layer in front of it. When a managed Mac or Windows PC signs in to Entra, the device holds a Primary Refresh Token (PRT) for the user. Every later sign-in to a SAML or OIDC app reuses that PRT, which is why users on a managed device often never see a password prompt.";

export const DEVICE_FLOWS: Flow[] = [
  {
    id: "macos-psso",
    title: "macOS Platform SSO",
    protocol: "oauth",
    actors: ["Mac + Secure Enclave", "Enterprise SSO plug-in", "Microsoft Entra ID"],
    intro:
      "Intune (or another MDM) sends the Mac an Extensible SSO profile with Platform SSO settings. The Microsoft Enterprise SSO plug-in, delivered by Company Portal, registers the Mac and the user with Entra. macOS then asks Entra for a hardware-bound PRT and, optionally, Kerberos tickets. The plug-in uses the PRT to get each app its own token.",
    steps: [
      { from: 0, to: 0, label: "MDM profile arrives", note: "Extensible SSO + Platform SSO settings, auth method chosen by the admin" },
      { from: 0, to: 0, label: "Create device keys", note: "Device signing key + device encryption key, kept in the Secure Enclave" },
      { from: 0, to: 1, label: "Register this Mac", note: "User clicks the “Registration required” notification" },
      { from: 1, to: 2, label: "Device registration", note: "Sends public keys only; private keys never leave the Mac" },
      { from: 2, to: 1, label: "Device identity + registration certificate", note: "The Mac now appears in Entra > Devices" },
      { from: 0, to: 2, label: "User proof + device proof", note: "Password, Secure Enclave key or smart card, signed by the device key" },
      { from: 2, to: 0, label: "PRT (+ cloud and on-prem Kerberos TGTs)", note: "Encrypted so only this Mac can open it" },
      { from: 0, to: 1, label: "Share PRT through Apple's framework", note: "The plug-in can use it; apps never see it" },
      { from: 1, to: 2, label: "App asks for a token; plug-in uses the PRT", note: "Silent request, no prompt" },
      { from: 2, to: 1, label: "Token for that one app and resource", note: "The app gets only its own token" },
    ],
    watch: [
      "No Intune profile or no Company Portal means no plug-in, and no Platform SSO.",
      "After a restart FileVault still needs the local Mac password. Touch ID works only after that first unlock.",
      "With the Password method the Mac password is kept in sync with Entra. With the Secure Enclave method the local password stays separate.",
      "Kerberos tickets are optional. If they're missing, check the Kerberos SSO extension profile (Apple owns it) and run app-sso platform -s.",
    ],
  },
  {
    id: "windows-prt",
    title: "Windows PRT",
    protocol: "oauth",
    actors: ["Windows sign-in (CloudAP)", "Web Account Manager (WAM)", "Microsoft Entra ID"],
    intro:
      "On an Entra joined or hybrid joined Windows PC, the CloudAP plugin gets the PRT when the user signs in to Windows. The PRT is bound to the device with keys protected by the TPM. Office, Teams and other apps ask Web Account Manager (WAM) for tokens, and WAM uses the PRT so nobody is prompted.",
    steps: [
      { from: 0, to: 2, label: "Windows sign-in, PRT request", note: "Password, Windows Hello or FIDO2, signed with the TPM-protected device key" },
      { from: 2, to: 0, label: "PRT + session key", note: "Session key is encrypted to the TPM; renewed about every 4 hours" },
      { from: 1, to: 1, label: "App (Outlook, Teams) asks WAM for a token" },
      { from: 1, to: 0, label: "Sign the request with the session key", note: "Proof that the request comes from this device" },
      { from: 1, to: 2, label: "PRT-signed token request", note: "Silent, no prompt" },
      { from: 2, to: 1, label: "Access token (+ refresh token)", note: "WAM keeps the refresh token, encrypted with DPAPI" },
      { from: 1, to: 1, label: "App gets only the access token" },
    ],
    watch: [
      "Run dsregcmd /status as the signed-in user. AzureAdPrt : YES means the PRT is there.",
      "A PRT that can't be refreshed eventually expires, and then prompts appear everywhere.",
      "Device-based Conditional Access (compliant or joined device) needs the PRT. Without it access is denied, not just prompted.",
      "Hybrid joined PCs may also hold an EnterprisePrt from AD FS. That's a different token.",
    ],
  },
  {
    id: "browser-prt",
    title: "Browser SSO into a SAML or OIDC app",
    protocol: "saml",
    actors: ["Browser on the device", "Broker (WAM or plug-in)", "Microsoft Entra ID", "Your SAML / OIDC app"],
    intro:
      "This is where the PRT meets the apps you manage in Federation 360. The app still sends a normal SAML AuthnRequest or OIDC authorize request. The difference is at Entra: the browser attaches a short-lived PRT cookie, so Entra already knows the user and the device and answers straight away.",
    steps: [
      { from: 0, to: 3, label: "Open the app" },
      { from: 3, to: 0, label: "302 to Entra (SAMLRequest or /authorize)", note: "Same as without device SSO" },
      { from: 0, to: 1, label: "Ask for a PRT cookie", note: "Only for Microsoft sign-in URLs" },
      { from: 1, to: 0, label: "PRT cookie, signed with the device's key" },
      { from: 0, to: 2, label: "Sign-in request + x-ms-RefreshTokenCredential", note: "The PRT cookie travels in this header" },
      { from: 2, to: 2, label: "Check device, user, Conditional Access", note: "Satisfies “require compliant device”" },
      { from: 2, to: 0, label: "SAML response or ID token, no prompt", note: "Plus a session cookie bound to the device" },
      { from: 0, to: 3, label: "POST to ACS / redirect_uri", note: "The app validates it exactly as usual" },
    ],
    watch: [
      "Private windows (InPrivate, Incognito, Firefox private) get no PRT, so the user is prompted. That's the quickest test.",
      "Chrome on Windows needs native support turned on or the Microsoft Single Sign On extension. Firefox needs its Windows SSO setting.",
      "On a Mac, Safari, Edge, Chrome and Firefox get SSO only when the SSO extension profile is installed.",
      "Your app never sees the PRT. It gets the same SAML assertion or ID token it always did.",
    ],
  },
];

/** Plain-language answers shown as cards. */
export const DEVICE_SSO_FACTS: { title: string; body: string }[] = [
  {
    title: "Why the user sees no prompt",
    body: "The proof happened when they signed in to the Mac or Windows. The device holds a PRT, the broker attaches it to every Entra request, and Entra already knows the user and the device. If MFA was used to get the PRT, that MFA claim carries over too.",
  },
  {
    title: "Apps never get the PRT",
    body: "Only the broker (WAM on Windows, the Enterprise SSO plug-in on a Mac) can use it. Each app or website receives a token for its own resource and nothing more, so one app can't reach another app's data.",
  },
  {
    title: "The PRT is tied to the hardware",
    body: "Its keys live in the Mac's Secure Enclave or the PC's TPM. Copying the PRT to another machine doesn't work, because every request must be signed by a key that can't be exported.",
  },
  {
    title: "FileVault still wants the local password",
    body: "After a restart, the Mac's local account password unlocks the disk. Platform SSO doesn't change that. Touch ID and SSO start working after the first unlock.",
  },
  {
    title: "Kerberos rides along on a Mac",
    body: "Entra can return a cloud Kerberos TGT and an on-premises AD TGT in the same reply as the PRT. Apple's Kerberos SSO extension then opens file shares and intranet sites without asking.",
  },
  {
    title: "When a prompt does appear",
    body: "Private browsing, a browser without SSO support, an expired PRT, a user who isn't the one registered on the device, or a Conditional Access policy that asks for fresh MFA (sign-in frequency).",
  },
];

/** Commands to run on the device. */
export const DEVICE_SSO_CHECKS: { title: string; body: string; success: string }[] = [
  {
    title: "On a Mac (Terminal)",
    body: "app-sso platform -s",
    success: "Near the bottom, SSO tokens are retrieved. With Kerberos turned on you'll see tgt_cloud and tgt_ad. In System Settings > Users & Groups > Network Account Server, Platform SSO shows Registered.",
  },
  {
    title: "On Windows (as the signed-in user)",
    body: "dsregcmd /status",
    success: "Under SSO State, AzureAdPrt : YES, with an AzureAdPrtUpdateTime in the last few hours. Under Device State, AzureAdJoined : YES.",
  },
];

/** Where the same settings live in the admin portals. */
export const DEVICE_SSO_PORTALS: { label: string; url: string; what: string }[] = [
  {
    label: "Entra: All devices",
    url: "https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/Devices/menuId/Devices",
    what: "Registered Macs and PCs, their join type and whether they're compliant.",
  },
  {
    label: "Entra: Sign-in logs",
    url: "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/SignInLogsList.ReactView",
    what: "Open a sign-in, then Device info. A PRT sign-in shows the device ID and join type.",
  },
  {
    label: "Entra: Conditional Access",
    url: "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies",
    what: "Policies that require a compliant or joined device depend on the PRT.",
  },
  {
    label: "Intune: macOS configuration profiles",
    url: "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMacOsMenu/~/configuration",
    what: "Settings catalog > Authentication > Extensible Single Sign On (SSO) holds the Platform SSO settings.",
  },
];

/** Microsoft Learn pages this topic is based on. */
export const DEVICE_SSO_SOURCES: { label: string; url: string }[] = [
  { label: "Architecture and authentication flow for macOS Platform SSO", url: "https://learn.microsoft.com/entra/identity/devices/macos-platform-sso-architecture" },
  { label: "Understanding Primary Refresh Token (PRT)", url: "https://learn.microsoft.com/entra/identity/devices/concept-primary-refresh-token" },
  { label: "Platform SSO configuration guide for macOS using Intune", url: "https://learn.microsoft.com/intune/device-configuration/settings-catalog/configure-platform-sso-macos" },
  { label: "Kerberos SSO in Platform SSO", url: "https://learn.microsoft.com/entra/identity/devices/device-join-macos-platform-single-sign-on-kerberos-configuration" },
  { label: "Troubleshoot devices with dsregcmd", url: "https://learn.microsoft.com/entra/identity/devices/troubleshoot-device-dsregcmd" },
  { label: "Demystifying macOS Platform SSO (Entra blog)", url: "https://techcommunity.microsoft.com/blog/microsoft-entra-blog/demystifying-macos-platform-sso-how-apple-and-microsoft-entra-id-work-together/4437423" },
];

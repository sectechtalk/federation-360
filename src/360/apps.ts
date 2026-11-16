// The 360 app family, shown by the app switcher at the top of every 360 app's rail.
// Same list as 360-apps.js in the other 360 apps. An app with no url yet shows as "Not linked yet".
export type App360 = { id: string; name: string; about: string; url: string };

export const APPS_360: App360[] = [
  { id: "e-360", name: "Entity 360", about: "Identity investigation", url: "" },
  { id: "r-360", name: "Remediation 360", about: "Changes and rollouts", url: "" },
  { id: "hm-360", name: "HeatMap 360", about: "Health, updates and exposure", url: "" },
  { id: "f-360", name: "Federation 360", about: "SAML, OIDC and OAuth", url: "" },
  { id: "c-360", name: "Certificates 360", about: "Certificates", url: "" },
];

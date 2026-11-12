export type Platform = "entra" | "aws-idc" | "okta" | "ping" | "adfs" | "other";
export type Environment = "prod" | "test" | "dev";
export type ProtocolId = "saml" | "oidc" | "oauth" | "scim";
export type AppStatus = "live" | "testing" | "planned" | "broken";

export interface Tenant {
  id: string;
  name: string;
  platform: Platform;
  /** Directory (tenant) ID, AWS instance ARN, Okta org URL, etc. */
  tenantRef: string;
  domain: string;
  environment: Environment;
  notes: string;
  example?: boolean;
  updatedAt: string;
}

export interface SamlSettings {
  /** SP entity ID, also called Identifier or Audience URI. */
  entityId: string;
  /** Assertion Consumer Service URL, also called Reply URL. */
  acsUrl: string;
  signOnUrl: string;
  /** The IdP's entity ID (Issuer), e.g. https://sts.windows.net/{tenant}/ */
  idpEntityId: string;
  nameIdFormat: string;
  nameIdSource: string;
  /** SHA-1 thumbprint of the IdP signing certificate the SP trusts. */
  certThumbprint: string;
  /** ISO date the signing certificate expires. */
  certExpires: string;
}

export interface OidcSettings {
  clientId: string;
  redirectUris: string; // newline separated
  grantType: "authorization_code" | "client_credentials" | "device_code" | "implicit";
  clientType: "confidential" | "public";
  scopes: string;
  /** Expected audience (aud) for tokens this app receives. */
  audience: string;
  issuer: string;
  /** ISO date the client secret or certificate expires. */
  secretExpires: string;
}

export interface AppIntegration {
  id: string;
  tenantId: string;
  name: string;
  protocol: ProtocolId;
  environment: Environment;
  owner: string;
  status: AppStatus;
  provisioning: "none" | "scim" | "jit" | "manual";
  saml: SamlSettings;
  oidc: OidcSettings;
  notes: string;
  example?: boolean;
  updatedAt: string;
}

export type Severity = "ok" | "info" | "warn" | "critical";

export interface Finding {
  severity: Severity;
  title: string;
  detail?: string;
  /** Playbook id to open for help. */
  playbook?: string;
}

export const PLATFORM_LABEL: Record<Platform, string> = {
  entra: "Microsoft Entra ID",
  "aws-idc": "AWS IAM Identity Center",
  okta: "Okta",
  ping: "Ping Identity",
  adfs: "AD FS",
  other: "Other / generic",
};

export const ENV_LABEL: Record<Environment, string> = { prod: "Production", test: "Test", dev: "Development" };

export const emptySaml = (): SamlSettings => ({
  entityId: "",
  acsUrl: "",
  signOnUrl: "",
  idpEntityId: "",
  nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  nameIdSource: "user.userprincipalname",
  certThumbprint: "",
  certExpires: "",
});

export const emptyOidc = (): OidcSettings => ({
  clientId: "",
  redirectUris: "",
  grantType: "authorization_code",
  clientType: "confidential",
  scopes: "openid profile email",
  audience: "",
  issuer: "",
  secretExpires: "",
});

export const newId = () =>
  Math.random().toString(36).slice(2, 8) + Date.now().toString(36).slice(-4);

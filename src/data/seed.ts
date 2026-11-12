import { emptyOidc, emptySaml, type AppIntegration, type Tenant } from "../lib/types";

const day = (n: number) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);
const now = () => new Date().toISOString();

export const EXAMPLE_TENANT_ID = "8f2b6c1e-0d4a-4a7e-9a51-3c0d2e7b9f10";

/** Fictional example data, clearly marked, so every screen has something to show. */
export function exampleData(): { tenants: Tenant[]; apps: AppIntegration[] } {
  const tenants: Tenant[] = [
    { id: "ex-contoso", name: "Contoso (corporate)", platform: "entra", tenantRef: EXAMPLE_TENANT_ID, domain: "contoso.example", environment: "prod", notes: "Primary workforce tenant. Example data.", example: true, updatedAt: now() },
    { id: "ex-aws", name: "Contoso AWS organization", platform: "aws-idc", tenantRef: "arn:aws:sso:::instance/ssoins-72230000example", domain: "d-9067000000.awsapps.com", environment: "prod", notes: "Identity source: external IdP (Contoso Entra). Example data.", example: true, updatedAt: now() },
    { id: "ex-fabrikam", name: "Fabrikam OpCo (test)", platform: "entra", tenantRef: "3c9d7a20-5b1f-4e6c-8d2a-7f0e1b4c6a99", domain: "fabrikam.example", environment: "test", notes: "Acquired operating company, migrating to Contoso tenant. Example data.", example: true, updatedAt: now() },
  ];
  const base = (p: Partial<AppIntegration>): AppIntegration => ({
    id: "",
    tenantId: "ex-contoso",
    name: "",
    protocol: "saml",
    environment: "prod",
    owner: "",
    status: "live",
    provisioning: "none",
    saml: emptySaml(),
    oidc: emptyOidc(),
    notes: "",
    example: true,
    updatedAt: now(),
    ...p,
  });
  const apps: AppIntegration[] = [
    base({
      id: "ex-expenses",
      name: "Expense Portal",
      owner: "Finance Apps team",
      saml: { ...emptySaml(), entityId: "https://expenses.contoso.example/saml/metadata", acsUrl: "https://expenses.contoso.example/saml/acs", signOnUrl: "https://expenses.contoso.example/login", idpEntityId: `https://sts.windows.net/${EXAMPLE_TENANT_ID}/`, certThumbprint: "749A276BF39BC76DFAA117BB9F8605D526A5B63F", certExpires: day(1094) },
      provisioning: "jit",
      notes: "Gallery-less SAML app. Use this one with the SAML decoder samples.",
    }),
    base({
      id: "ex-awsidc",
      name: "AWS IAM Identity Center",
      owner: "Cloud Platform team",
      saml: { ...emptySaml(), entityId: "https://us-east-1.signin.aws.amazon.com/platform/saml/d-9067000000", acsUrl: "https://us-east-1.signin.aws.amazon.com/platform/saml/acs/1a2b3c4d-example", signOnUrl: "https://d-9067000000.awsapps.com/start", idpEntityId: `https://sts.windows.net/${EXAMPLE_TENANT_ID}/`, nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", certThumbprint: "0E24FD3E6EFE4791B1836C578E37C358511533F8", certExpires: day(20) },
      provisioning: "scim",
      notes: "SCIM token in IAM Identity Center expires yearly. Example data.",
    }),
    base({
      id: "ex-hr",
      tenantId: "ex-fabrikam",
      name: "HR Analytics",
      environment: "test",
      status: "broken",
      owner: "",
      saml: { ...emptySaml(), entityId: "hr-analytics", acsUrl: "http://hr-test.fabrikam.example/sso/acs", idpEntityId: "https://sts.windows.net/3c9d7a20-5b1f-4e6c-8d2a-7f0e1b4c6a99/", certExpires: day(-12) },
      notes: "Users get AADSTS50011 since the vendor moved the app to a new URL.",
    }),
    base({
      id: "ex-partner",
      name: "Partner Portal",
      protocol: "oidc",
      owner: "Digital team",
      oidc: { ...emptyOidc(), clientId: "5d1e2f3a-4b5c-4d6e-8f70-819203a4b5c6", redirectUris: "https://partners.contoso.example/signin-oidc", clientType: "confidential", grantType: "authorization_code", scopes: "openid profile email offline_access", audience: "5d1e2f3a-4b5c-4d6e-8f70-819203a4b5c6", issuer: `https://login.microsoftonline.com/${EXAMPLE_TENANT_ID}/v2.0`, secretExpires: day(-5) },
      status: "live",
    }),
    base({
      id: "ex-payroll",
      name: "Payroll sync job",
      protocol: "oauth",
      owner: "HR Systems team",
      oidc: { ...emptyOidc(), clientId: "a7b8c9d0-1e2f-4a3b-9c4d-5e6f7a8b9c0d", redirectUris: "", clientType: "confidential", grantType: "client_credentials", scopes: "https://graph.microsoft.com/.default", audience: "https://graph.microsoft.com", issuer: `https://sts.windows.net/${EXAMPLE_TENANT_ID}/`, secretExpires: day(200) },
      notes: "Daemon that reads users from Graph (User.Read.All application permission).",
    }),
    base({
      id: "ex-field",
      name: "Field Service app",
      protocol: "oidc",
      owner: "Operations IT",
      oidc: { ...emptyOidc(), clientId: "c3d4e5f6-0718-4293-a4b5-c6d7e8f90a1b", redirectUris: "https://field.contoso.example/auth/callback\nhttp://localhost:3000/auth/callback", clientType: "public", grantType: "authorization_code", scopes: "openid profile api://field-api/Jobs.Read", audience: "c3d4e5f6-0718-4293-a4b5-c6d7e8f90a1b", issuer: `https://login.microsoftonline.com/${EXAMPLE_TENANT_ID}/v2.0` },
      notes: "Single-page app using auth code + PKCE.",
    }),
  ];
  return { tenants, apps };
}

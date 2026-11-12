/** Example messages, generated with current timestamps so they behave like fresh captures. */
import { bytesToB64, bytesToB64url, deflateRaw, toUtf8 } from "../lib/encoding";
import { SAMPLE_CERT_CURRENT, SAMPLE_CERT_EXPIRING } from "./sampleCerts";
import { EXAMPLE_TENANT_ID } from "./seed";

const iso = (offsetSec: number) => new Date(Date.now() + offsetSec * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const rid = () => "_" + crypto.randomUUID();

interface SamlOpts {
  audience: string;
  acs: string;
  cert: string;
  notBefore: number;
  notOnOrAfter: number;
  inResponseTo?: string;
  sigAlg?: string;
}

function response(o: SamlOpts) {
  const issuer = `https://sts.windows.net/${EXAMPLE_TENANT_ID}/`;
  const irt = o.inResponseTo ? ` InResponseTo="${o.inResponseTo}"` : "";
  const alg = o.sigAlg ?? "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  return `<samlp:Response ID="${rid()}" Version="2.0" IssueInstant="${iso(0)}" Destination="${o.acs}"${irt} xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">${issuer}</Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <Assertion ID="${rid()}" IssueInstant="${iso(0)}" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
    <Issuer>${issuer}</Issuer>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
      <SignedInfo>
        <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <SignatureMethod Algorithm="${alg}"/>
        <Reference URI="#example"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>EXAMPLE-NOT-A-REAL-DIGEST=</DigestValue></Reference>
      </SignedInfo>
      <SignatureValue>EXAMPLE-NOT-A-REAL-SIGNATURE=</SignatureValue>
      <KeyInfo><X509Data><X509Certificate>${o.cert}</X509Certificate></X509Data></KeyInfo>
    </Signature>
    <Subject>
      <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">avery.lee@contoso.example</NameID>
      <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <SubjectConfirmationData${irt} NotOnOrAfter="${iso(o.notOnOrAfter)}" Recipient="${o.acs}"/>
      </SubjectConfirmation>
    </Subject>
    <Conditions NotBefore="${iso(o.notBefore)}" NotOnOrAfter="${iso(o.notOnOrAfter)}">
      <AudienceRestriction><Audience>${o.audience}</Audience></AudienceRestriction>
    </Conditions>
    <AttributeStatement>
      <Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid"><AttributeValue>${EXAMPLE_TENANT_ID}</AttributeValue></Attribute>
      <Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier"><AttributeValue>0b1c2d3e-4f50-4617-8a9b-0c1d2e3f4a5b</AttributeValue></Attribute>
      <Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"><AttributeValue>Avery</AttributeValue></Attribute>
      <Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"><AttributeValue>Lee</AttributeValue></Attribute>
      <Attribute Name="http://schemas.microsoft.com/claims/authnmethodsreferences"><AttributeValue>http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password</AttributeValue><AttributeValue>http://schemas.microsoft.com/claims/multipleauthn</AttributeValue></Attribute>
    </AttributeStatement>
    <AuthnStatement AuthnInstant="${iso(-20)}" SessionIndex="${rid()}">
      <AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef></AuthnContext>
    </AuthnStatement>
  </Assertion>
</samlp:Response>`;
}

export const SAML_SAMPLES = [
  {
    id: "healthy",
    label: "Healthy response (Expense Portal)",
    appId: "ex-expenses",
    build: async () =>
      bytesToB64(toUtf8(response({ audience: "https://expenses.contoso.example/saml/metadata", acs: "https://expenses.contoso.example/saml/acs", cert: SAMPLE_CERT_CURRENT, notBefore: -300, notOnOrAfter: 3300, inResponseTo: "_a1b2c3d4e5f60718" }))),
  },
  {
    id: "audience",
    label: "Audience + ACS mismatch",
    appId: "ex-expenses",
    build: async () =>
      bytesToB64(toUtf8(response({ audience: "https://expenses.contoso.example/saml/metadata/", acs: "https://expenses-old.contoso.example/saml/acs", cert: SAMPLE_CERT_CURRENT, notBefore: -300, notOnOrAfter: 3300 }))),
  },
  {
    id: "rolled",
    label: "Rolled certificate + clock skew",
    appId: "ex-expenses",
    build: async () =>
      bytesToB64(toUtf8(response({ audience: "https://expenses.contoso.example/saml/metadata", acs: "https://expenses.contoso.example/saml/acs", cert: SAMPLE_CERT_EXPIRING, notBefore: 600, notOnOrAfter: 4200, sigAlg: "http://www.w3.org/2000/09/xmldsig#rsa-sha1" }))),
  },
  {
    id: "request",
    label: "AuthnRequest (Redirect binding)",
    appId: "ex-expenses",
    build: async () => {
      const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1b2c3d4e5f60718" Version="2.0" IssueInstant="${iso(0)}" Destination="https://login.microsoftonline.com/${EXAMPLE_TENANT_ID}/saml2" AssertionConsumerServiceURL="https://expenses.contoso.example/saml/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>https://expenses.contoso.example/saml/metadata</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>`;
      const b64 = bytesToB64(await deflateRaw(toUtf8(xml)));
      return `https://login.microsoftonline.com/${EXAMPLE_TENANT_ID}/saml2?SAMLRequest=${encodeURIComponent(b64)}&RelayState=%2Freports`;
    },
  },
];

/** Signs example JWTs with a throwaway key generated in this browser. */
export async function makeJwtSample(kind: "id" | "access" | "graph"): Promise<{ token: string; jwks: string; appId: string }> {
  const kp = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const kid = "example-" + Math.random().toString(36).slice(2, 8);
  const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const now = Math.floor(Date.now() / 1000);
  const tid = EXAMPLE_TENANT_ID;
  let header: any = { typ: "JWT", alg: "RS256", kid };
  let payload: any;
  let appId = "ex-partner";
  if (kind === "id") {
    payload = {
      aud: "5d1e2f3a-4b5c-4d6e-8f70-819203a4b5c6",
      iss: `https://login.microsoftonline.com/${tid}/v2.0`,
      iat: now - 30, nbf: now - 30, exp: now + 3570,
      name: "Avery Lee", preferred_username: "avery.lee@contoso.example", email: "avery.lee@contoso.example",
      nonce: "n-0S6_WzA2Mj", oid: "0b1c2d3e-4f50-4617-8a9b-0c1d2e3f4a5b",
      sub: "pW9xS1mXH3o0Vf3z1EXAMPLEsub", tid, ver: "2.0",
    };
  } else if (kind === "access") {
    appId = "ex-field";
    payload = {
      aud: "api://field-api",
      iss: `https://sts.windows.net/${tid}/`,
      iat: now - 3700, nbf: now - 3700, exp: now - 100,
      appid: "c3d4e5f6-0718-4293-a4b5-c6d7e8f90a1b", scp: "Jobs.Read", ver: "1.0",
      oid: "0b1c2d3e-4f50-4617-8a9b-0c1d2e3f4a5b", sub: "EXAMPLEsubForApi", tid, upn: "avery.lee@contoso.example",
    };
  } else {
    appId = "ex-payroll";
    header = { ...header, nonce: "EXAMPLE-graph-nonce" };
    payload = {
      aud: "https://graph.microsoft.com",
      iss: `https://sts.windows.net/${tid}/`,
      iat: now - 60, nbf: now - 60, exp: now + 3540,
      appid: "a7b8c9d0-1e2f-4a3b-9c4d-5e6f7a8b9c0d", idtyp: "app", roles: ["User.Read.All"], ver: "1.0",
      oid: "9e8d7c6b-5a49-4382-a716-f5e4d3c2b1a0", sub: "9e8d7c6b-5a49-4382-a716-f5e4d3c2b1a0", tid,
    };
  }
  const enc = (o: any) => bytesToB64url(toUtf8(JSON.stringify(o)));
  const input = enc(header) + "." + enc(payload);
  const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, toUtf8(input)));
  const jwks = JSON.stringify({ keys: [{ kty: "RSA", use: "sig", kid, n: pub.n, e: pub.e }] }, null, 2);
  return { token: input + "." + bytesToB64url(sig), jwks, appId };
}

export const SAMPLE_IDP_METADATA = `<?xml version="1.0" encoding="utf-8"?>
<EntityDescriptor ID="_example" entityID="https://sts.windows.net/${EXAMPLE_TENANT_ID}/" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>${SAMPLE_CERT_EXPIRING}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
    <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>${SAMPLE_CERT_CURRENT}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/${EXAMPLE_TENANT_ID}/saml2"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/${EXAMPLE_TENANT_ID}/saml2"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://login.microsoftonline.com/${EXAMPLE_TENANT_ID}/saml2"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;

export const SAMPLE_DISCOVERY = JSON.stringify(
  {
    token_endpoint: `https://login.microsoftonline.com/${EXAMPLE_TENANT_ID}/oauth2/v2.0/token`,
    token_endpoint_auth_methods_supported: ["client_secret_post", "private_key_jwt", "client_secret_basic"],
    jwks_uri: `https://login.microsoftonline.com/${EXAMPLE_TENANT_ID}/discovery/v2.0/keys`,
    response_modes_supported: ["query", "fragment", "form_post"],
    subject_types_supported: ["pairwise"],
    id_token_signing_alg_values_supported: ["RS256"],
    response_types_supported: ["code", "id_token", "code id_token", "id_token token"],
    scopes_supported: ["openid", "profile", "email", "offline_access"],
    issuer: `https://login.microsoftonline.com/${EXAMPLE_TENANT_ID}/v2.0`,
    request_uri_parameter_supported: false,
    userinfo_endpoint: "https://graph.microsoft.com/oidc/userinfo",
    authorization_endpoint: `https://login.microsoftonline.com/${EXAMPLE_TENANT_ID}/oauth2/v2.0/authorize`,
    end_session_endpoint: `https://login.microsoftonline.com/${EXAMPLE_TENANT_ID}/oauth2/v2.0/logout`,
    claims_supported: ["sub", "iss", "aud", "exp", "iat", "nonce", "name", "preferred_username", "email", "oid", "tid", "ver"],
  },
  null,
  2,
);

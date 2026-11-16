/** Example HAR files for the Flow Tracer, built with fresh timestamps from the SAML examples. */
import { bytesToB64, deflateRaw, toUtf8 } from "../lib/encoding";
import { SAML_SAMPLES } from "./samples";
import { EXAMPLE_TENANT_ID } from "./seed";

const iso = (offsetSec: number) => new Date(Date.now() + offsetSec * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

async function authnRequestUrl(acs: string) {
  const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1b2c3d4e5f60718" Version="2.0" IssueInstant="${iso(-2)}" Destination="https://login.microsoftonline.com/${EXAMPLE_TENANT_ID}/saml2" AssertionConsumerServiceURL="${acs}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>https://expenses.contoso.example/saml/metadata</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>`;
  const b64 = bytesToB64(await deflateRaw(toUtf8(xml)));
  return `https://login.microsoftonline.com/${EXAMPLE_TENANT_ID}/saml2?SAMLRequest=${encodeURIComponent(b64)}&RelayState=%2Freports`;
}

const entry = (offset: number, method: string, url: string, status: number, extra: Record<string, any> = {}) => ({
  startedDateTime: new Date(Date.now() + offset * 1000).toISOString(),
  request: { method, url, headers: [{ name: "Cookie", value: "ESTSAUTH=example-cookie-that-the-tracer-drops" }], ...(extra.request ?? {}) },
  response: { status, headers: [], content: { mimeType: "text/html", text: "" }, ...(extra.response ?? {}) },
});

export const HAR_SAMPLES = [
  {
    id: "saml-ok",
    label: "Healthy SAML sign-in",
    build: async () => {
      const response = await SAML_SAMPLES.find((s) => s.id === "healthy")!.build();
      return {
        log: {
          version: "1.2",
          entries: [
            entry(-30, "GET", "https://expenses.contoso.example/reports", 302),
            entry(-29, "GET", await authnRequestUrl("https://expenses.contoso.example/saml/acs"), 200),
            entry(-12, "POST", "https://login.microsoftonline.com/common/login", 200),
            entry(-1, "POST", "https://expenses.contoso.example/saml/acs", 302, {
              request: { postData: { mimeType: "application/x-www-form-urlencoded", params: [{ name: "SAMLResponse", value: encodeURIComponent(response) }, { name: "RelayState", value: "%2Freports" }] } },
            }),
            entry(0, "GET", "https://expenses.contoso.example/reports", 200),
          ],
        },
      };
    },
  },
  {
    id: "saml-50011",
    label: "Reply URL mismatch (AADSTS50011)",
    build: async () => ({
      log: {
        version: "1.2",
        entries: [
          entry(-5, "GET", await authnRequestUrl("https://expenses-old.contoso.example/saml/acs"), 200, {
            response: {
              content: {
                mimeType: "text/html",
                text: `<html><body><div id="error">AADSTS50011: The redirect URI 'https://expenses-old.contoso.example/saml/acs' specified in the request does not match the redirect URIs configured for the application 'f6a1c2d3-0000-4000-8000-000000000001'. Make sure the redirect URI sent in the request matches one added to your application in the Azure portal.</div></body></html>`,
              },
            },
          }),
        ],
      },
    }),
  },
];

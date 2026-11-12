import { b64ToBytes, inflateRaw, normalizeThumbprint, utf8 } from "./encoding";
import { parseCertificate, type CertInfo } from "./x509";
import type { Finding } from "./types";

const NS = {
  p: "urn:oasis:names:tc:SAML:2.0:protocol",
  a: "urn:oasis:names:tc:SAML:2.0:assertion",
  ds: "http://www.w3.org/2000/09/xmldsig#",
  md: "urn:oasis:names:tc:SAML:2.0:metadata",
};

export interface DecodeResult {
  xml: string;
  steps: string[];
}

/**
 * Accepts anything a person is likely to paste: raw XML, base64 (POST binding),
 * base64 + deflate (Redirect binding), URL-encoded values, a full URL with
 * SAMLRequest/SAMLResponse in the query string, or a form body.
 */
export async function decodeSamlInput(raw: string): Promise<DecodeResult> {
  const steps: string[] = [];
  let s = raw.trim();
  if (!s) throw new Error("Paste a SAML message first.");
  if (s.startsWith("<")) return { xml: s, steps: ["Input is already XML."] };

  const m = s.match(/(?:^|[?&\s])(SAMLRequest|SAMLResponse)=([^&\s]+)/);
  if (m) {
    s = m[2];
    steps.push(`Found the ${m[1]} parameter.`);
  }
  if (/%[0-9A-Fa-f]{2}/.test(s)) {
    s = decodeURIComponent(s.replace(/\+/g, "%20"));
    steps.push("URL-decoded the value.");
  }
  let bytes: Uint8Array;
  try {
    bytes = b64ToBytes(s);
    steps.push("Base64-decoded the value.");
  } catch {
    throw new Error("This isn't valid base64. Copy the full SAMLResponse or SAMLRequest value, without quotes.");
  }
  const text = utf8(bytes);
  if (text.trimStart().startsWith("<")) return { xml: text.trim(), steps };
  try {
    const inflated = utf8(await inflateRaw(bytes));
    steps.push("Inflated it (Redirect binding messages are deflate-compressed).");
    return { xml: inflated.trim(), steps };
  } catch {
    throw new Error("Decoded the base64, but the result isn't XML or compressed XML. Check you copied the whole value.");
  }
}

const first = (root: Element | Document, ns: string, tag: string) =>
  root.getElementsByTagNameNS(ns, tag)[0] as Element | undefined;
const all = (root: Element | Document, ns: string, tag: string) =>
  Array.from(root.getElementsByTagNameNS(ns, tag));
const txt = (el?: Element | null) => el?.textContent?.trim() ?? "";

export interface SamlSignature {
  location: "Response" | "Assertion";
  signatureAlgorithm: string;
  digestAlgorithm: string;
  cert?: CertInfo;
}

export interface SamlAttribute {
  name: string;
  friendlyName?: string;
  values: string[];
}

export interface ParsedSaml {
  kind: "Response" | "AuthnRequest" | "LogoutRequest" | "LogoutResponse" | "Other";
  rootName: string;
  id: string;
  issueInstant?: Date;
  destination: string;
  inResponseTo: string;
  issuer: string;
  statusCode: string;
  subStatusCode: string;
  statusMessage: string;
  encryptedAssertion: boolean;
  assertion?: {
    id: string;
    issuer: string;
    issueInstant?: Date;
    nameId: string;
    nameIdFormat: string;
    recipient: string;
    subjectNotOnOrAfter?: Date;
    subjectInResponseTo: string;
    notBefore?: Date;
    notOnOrAfter?: Date;
    audiences: string[];
    authnContext: string;
    authnInstant?: Date;
    sessionIndex: string;
    attributes: SamlAttribute[];
  };
  request?: {
    acsUrl: string;
    protocolBinding: string;
    nameIdPolicy: string;
    forceAuthn: boolean;
    isPassive: boolean;
    requestedAuthnContext: string[];
    comparison: string;
  };
  signatures: SamlSignature[];
}

const date = (v: string | null) => (v ? new Date(v) : undefined);
const shortUrn = (v: string) => v.split(":").pop() || v;

export async function parseSaml(xml: string): Promise<ParsedSaml> {
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  const err = doc.getElementsByTagName("parsererror")[0];
  if (err) throw new Error("The XML didn't parse. It may be truncated or edited. " + txt(err).slice(0, 160));
  const root = doc.documentElement;
  const local = root.localName;
  const kind: ParsedSaml["kind"] =
    local === "Response" || local === "AuthnRequest" || local === "LogoutRequest" || local === "LogoutResponse"
      ? local
      : "Other";

  const directIssuer = Array.from(root.children).find((c) => c.localName === "Issuer");
  const status = first(root, NS.p, "StatusCode");
  const subStatus = status ? first(status, NS.p, "StatusCode") : undefined;

  const result: ParsedSaml = {
    kind,
    rootName: root.nodeName,
    id: root.getAttribute("ID") ?? "",
    issueInstant: date(root.getAttribute("IssueInstant")),
    destination: root.getAttribute("Destination") ?? "",
    inResponseTo: root.getAttribute("InResponseTo") ?? "",
    issuer: txt(directIssuer),
    statusCode: status?.getAttribute("Value") ?? "",
    subStatusCode: subStatus?.getAttribute("Value") ?? "",
    statusMessage: txt(first(root, NS.p, "StatusMessage")),
    encryptedAssertion: !!first(root, NS.a, "EncryptedAssertion"),
    signatures: [],
  };

  const assertion = first(root, NS.a, "Assertion");
  if (assertion) {
    const nameId = first(assertion, NS.a, "NameID");
    const scd = first(assertion, NS.a, "SubjectConfirmationData");
    const cond = first(assertion, NS.a, "Conditions");
    const authn = first(assertion, NS.a, "AuthnStatement");
    result.assertion = {
      id: assertion.getAttribute("ID") ?? "",
      issuer: txt(first(assertion, NS.a, "Issuer")),
      issueInstant: date(assertion.getAttribute("IssueInstant")),
      nameId: txt(nameId),
      nameIdFormat: nameId?.getAttribute("Format") ?? "",
      recipient: scd?.getAttribute("Recipient") ?? "",
      subjectNotOnOrAfter: date(scd?.getAttribute("NotOnOrAfter") ?? null),
      subjectInResponseTo: scd?.getAttribute("InResponseTo") ?? "",
      notBefore: date(cond?.getAttribute("NotBefore") ?? null),
      notOnOrAfter: date(cond?.getAttribute("NotOnOrAfter") ?? null),
      audiences: all(assertion, NS.a, "Audience").map((e) => txt(e)),
      authnContext: txt(first(assertion, NS.a, "AuthnContextClassRef")),
      authnInstant: date(authn?.getAttribute("AuthnInstant") ?? null),
      sessionIndex: authn?.getAttribute("SessionIndex") ?? "",
      attributes: all(assertion, NS.a, "Attribute").map((a) => ({
        name: a.getAttribute("Name") ?? "",
        friendlyName: a.getAttribute("FriendlyName") ?? undefined,
        values: all(a, NS.a, "AttributeValue").map((v) => txt(v)),
      })),
    };
  }

  if (kind === "AuthnRequest") {
    const policy = first(root, NS.p, "NameIDPolicy");
    const rac = first(root, NS.p, "RequestedAuthnContext");
    result.request = {
      acsUrl: root.getAttribute("AssertionConsumerServiceURL") ?? "",
      protocolBinding: root.getAttribute("ProtocolBinding") ?? "",
      nameIdPolicy: policy?.getAttribute("Format") ?? "",
      forceAuthn: root.getAttribute("ForceAuthn") === "true",
      isPassive: root.getAttribute("IsPassive") === "true",
      requestedAuthnContext: rac ? all(rac, NS.a, "AuthnContextClassRef").map((e) => txt(e)) : [],
      comparison: rac?.getAttribute("Comparison") ?? "exact",
    };
  }

  for (const sig of all(root, NS.ds, "Signature")) {
    const parent = sig.parentElement;
    const location = parent?.localName === "Assertion" ? "Assertion" : "Response";
    const certB64 = txt(first(sig, NS.ds, "X509Certificate"));
    let cert: CertInfo | undefined;
    if (certB64) {
      try {
        cert = await parseCertificate(certB64);
      } catch {
        cert = undefined;
      }
    }
    result.signatures.push({
      location,
      signatureAlgorithm: first(sig, NS.ds, "SignatureMethod")?.getAttribute("Algorithm") ?? "",
      digestAlgorithm: first(sig, NS.ds, "DigestMethod")?.getAttribute("Algorithm") ?? "",
      cert,
    });
  }
  return result;
}

export interface SamlExpectations {
  spEntityId?: string;
  acsUrl?: string;
  idpEntityId?: string;
  certThumbprint?: string;
}

export interface CheckOptions {
  /** The moment to evaluate time conditions at. */
  at: Date;
  skewSeconds: number;
}

const fmt = (d?: Date) => (d ? d.toISOString().replace(".000", "") : "missing");
const norm = (u: string) => u.trim().replace(/\/+$/, "").toLowerCase();
/** SPs compare identifiers exactly. Explain near-misses (trailing slash, case) explicitly. */
const differs = (a: string, b: string) => a.trim() !== b.trim();
const nearMiss = (a: string, b: string) =>
  differs(a, b) && norm(a) === norm(b) ? " They differ only by a trailing slash or letter case, which still counts as a mismatch." : "";

export function checkSaml(p: ParsedSaml, exp: SamlExpectations, opt: CheckOptions): Finding[] {
  const f: Finding[] = [];
  const at = opt.at.getTime();
  const skew = opt.skewSeconds * 1000;

  if (p.kind === "Other") {
    f.push({ severity: "warn", title: `Unrecognized root element <${p.rootName}>`, detail: "Expected a SAML Response or AuthnRequest." });
    return f;
  }

  if (p.kind === "AuthnRequest" && p.request) {
    const r = p.request;
    f.push({ severity: "info", title: "This is a request from the app (SP) to the identity provider", detail: "It shows what the app asks for. Compare its Issuer and ACS URL with what's configured at the identity provider." });
    if (exp.spEntityId && p.issuer && differs(p.issuer, exp.spEntityId))
      f.push({ severity: "critical", title: "Request Issuer doesn't match the app's Identifier (Entity ID)", detail: `Request says "${p.issuer}", inventory says "${exp.spEntityId}". Entra rejects this with AADSTS700016.`, playbook: "AADSTS700016" });
    else if (p.issuer) f.push({ severity: "ok", title: "Issuer present", detail: p.issuer });
    if (r.acsUrl && exp.acsUrl && differs(r.acsUrl, exp.acsUrl))
      f.push({ severity: "critical", title: "Requested ACS URL doesn't match the configured Reply URL", detail: `Request asks for "${r.acsUrl}", inventory has "${exp.acsUrl}". Entra rejects this with AADSTS50011.`, playbook: "AADSTS50011" });
    else if (r.acsUrl) f.push({ severity: "ok", title: "ACS URL in request", detail: r.acsUrl });
    if (r.requestedAuthnContext.length)
      f.push({ severity: "warn", title: "The app demands a specific authentication method", detail: `RequestedAuthnContext (${r.comparison}): ${r.requestedAuthnContext.map(shortUrn).join(", ")}. If the user signed in another way (MFA, passwordless, federated), Entra returns AADSTS75011.`, playbook: "AADSTS75011" });
    if (r.forceAuthn) f.push({ severity: "info", title: "ForceAuthn=true", detail: "The user will be asked to sign in again even with an active session." });
    if (r.isPassive) f.push({ severity: "info", title: "IsPassive=true", detail: "The IdP must not show any prompt. If interaction is needed the sign-in fails." });
    if (r.nameIdPolicy) f.push({ severity: "info", title: "Requested NameID format", detail: r.nameIdPolicy });
    return f;
  }

  if (p.kind !== "Response") {
    f.push({ severity: "info", title: `${p.kind} message`, detail: "Logout messages are decoded but not checked in this version." });
    return f;
  }

  // Status
  if (p.statusCode.endsWith(":Success")) f.push({ severity: "ok", title: "Status: Success" });
  else
    f.push({
      severity: "critical",
      title: `Status: ${shortUrn(p.statusCode) || "missing"}${p.subStatusCode ? " / " + shortUrn(p.subStatusCode) : ""}`,
      detail: (p.statusMessage || "The identity provider refused the sign-in.") + " Look up the message or AADSTS code in Playbooks.",
    });

  if (p.encryptedAssertion) {
    f.push({ severity: "info", title: "The assertion is encrypted", detail: "Only the app holding the private key can read it. To troubleshoot, temporarily turn off token encryption in a test environment, or check the app's own logs." });
  }

  // Issuer
  const issuer = p.assertion?.issuer || p.issuer;
  if (!issuer) f.push({ severity: "critical", title: "No Issuer in the response" });
  else if (exp.idpEntityId && differs(issuer, exp.idpEntityId))
    f.push({ severity: "critical", title: "Issuer doesn't match the identity provider the app trusts", detail: `Response Issuer "${issuer}", app expects "${exp.idpEntityId}".${nearMiss(issuer, exp.idpEntityId) || " Common after copying settings between tenants."}`, playbook: "saml-issuer" });
  else f.push({ severity: "ok", title: "Issuer", detail: issuer });

  // Destination & Recipient
  const a = p.assertion;
  if (exp.acsUrl) {
    if (p.destination && differs(p.destination, exp.acsUrl))
      f.push({ severity: "critical", title: "Destination doesn't match the app's ACS URL", detail: `Response was addressed to "${p.destination}", app's ACS is "${exp.acsUrl}".${nearMiss(p.destination, exp.acsUrl)}`, playbook: "saml-acs" });
    if (a?.recipient && differs(a.recipient, exp.acsUrl))
      f.push({ severity: "critical", title: "Recipient doesn't match the app's ACS URL", detail: `SubjectConfirmationData Recipient "${a.recipient}", app's ACS "${exp.acsUrl}". The SP will reject this.${nearMiss(a.recipient, exp.acsUrl)}`, playbook: "saml-acs" });
    if ((!p.destination || !differs(p.destination, exp.acsUrl)) && (!a?.recipient || !differs(a.recipient, exp.acsUrl)))
      f.push({ severity: "ok", title: "Destination and Recipient match the ACS URL", detail: exp.acsUrl });
  } else if (a?.recipient) {
    f.push({ severity: "info", title: "Recipient (ACS URL)", detail: a.recipient + " — pick an app above to compare." });
  }

  if (!a) {
    if (!p.encryptedAssertion) f.push({ severity: p.statusCode.endsWith(":Success") ? "critical" : "info", title: "No assertion in the response" });
  } else {
    // Audience
    if (!a.audiences.length) f.push({ severity: "warn", title: "No AudienceRestriction", detail: "Most SPs require an Audience equal to their entity ID." });
    else if (exp.spEntityId && !a.audiences.some((x) => !differs(x, exp.spEntityId!)))
      f.push({ severity: "critical", title: "Audience doesn't match the app's Entity ID", detail: `Assertion is for "${a.audiences.join(", ")}", app's Entity ID is "${exp.spEntityId}".${nearMiss(a.audiences[0], exp.spEntityId)} Fix the Identifier (Entity ID) at the IdP so it exactly matches the SP.`, playbook: "saml-audience" });
    else f.push({ severity: exp.spEntityId ? "ok" : "info", title: "Audience", detail: a.audiences.join(", ") + (exp.spEntityId ? "" : " — pick an app above to compare.") });

    // Time window
    if (a.notBefore && at + skew < a.notBefore.getTime())
      f.push({ severity: "critical", title: "Assertion isn't valid yet (NotBefore is in the future)", detail: `NotBefore ${fmt(a.notBefore)}, evaluated at ${fmt(opt.at)}. The SP's clock is likely behind the IdP's.`, playbook: "clock-skew" });
    if (a.notOnOrAfter && at - skew >= a.notOnOrAfter.getTime())
      f.push({ severity: "critical", title: "Assertion has expired (NotOnOrAfter passed)", detail: `NotOnOrAfter ${fmt(a.notOnOrAfter)}, evaluated at ${fmt(opt.at)}. If this is an old capture, switch the evaluation time to "when it was issued".`, playbook: "clock-skew" });
    if (a.subjectNotOnOrAfter && at - skew >= a.subjectNotOnOrAfter.getTime() && !(a.notOnOrAfter && at - skew >= a.notOnOrAfter.getTime()))
      f.push({ severity: "critical", title: "Subject confirmation window has passed", detail: `SubjectConfirmationData NotOnOrAfter ${fmt(a.subjectNotOnOrAfter)}.`, playbook: "clock-skew" });
    const inWindow =
      (!a.notBefore || at + skew >= a.notBefore.getTime()) && (!a.notOnOrAfter || at - skew < a.notOnOrAfter.getTime());
    if (inWindow && a.notBefore && a.notOnOrAfter)
      f.push({ severity: "ok", title: "Within its validity window", detail: `${fmt(a.notBefore)} to ${fmt(a.notOnOrAfter)} (±${opt.skewSeconds}s skew allowed)` });

    // SP vs IdP initiated
    if (p.inResponseTo || a.subjectInResponseTo)
      f.push({ severity: "info", title: "SP-initiated sign-in", detail: `InResponseTo ${p.inResponseTo || a.subjectInResponseTo}. The app must still have this request ID in its session, or it rejects the response (common with multiple tabs or load balancers without sticky sessions).` });
    else f.push({ severity: "info", title: "IdP-initiated sign-in (no InResponseTo)", detail: "Started from My Apps or the IdP. Some apps don't allow this; if so, start from the app's login page." });

    // NameID
    if (!a.nameId) f.push({ severity: "warn", title: "No NameID", detail: "Most apps match the user on NameID." });
    else f.push({ severity: "info", title: "NameID (the user identifier the app will match on)", detail: `${a.nameId}  ·  format ${shortUrn(a.nameIdFormat) || "unspecified"}` });

    // AWS role attribute
    const role = a.attributes.find((x) => x.name === "https://aws.amazon.com/SAML/Attributes/Role");
    if (role) {
      const bad = role.values.filter((v) => !/arn:aws:iam::\d{12}:role\/.+,\s*arn:aws:iam::\d{12}:saml-provider\/.+|arn:aws:iam::\d{12}:saml-provider\/.+,\s*arn:aws:iam::\d{12}:role\/.+/.test(v));
      if (bad.length)
        f.push({ severity: "critical", title: "AWS Role attribute is malformed", detail: `Each value must be "role ARN,provider ARN". Bad: ${bad.join(" | ")}`, playbook: "aws-invalid-saml" });
      else f.push({ severity: "ok", title: "AWS Role attribute is well formed", detail: role.values.join(" | ") });
      if (!a.attributes.some((x) => x.name === "https://aws.amazon.com/SAML/Attributes/RoleSessionName"))
        f.push({ severity: "critical", title: "AWS RoleSessionName attribute is missing", detail: "Direct IAM federation requires it.", playbook: "aws-invalid-saml" });
    }
  }

  // Signatures
  if (!p.signatures.length)
    f.push({ severity: p.statusCode.endsWith(":Success") ? "critical" : "info", title: "Not signed", detail: "No XML signature found. A successful response must be signed." });
  for (const s of p.signatures) {
    const alg = shortUrn(s.signatureAlgorithm.split("#").pop() || "");
    if (/sha1/i.test(s.signatureAlgorithm))
      f.push({ severity: "warn", title: `${s.location} signed with SHA-1`, detail: "SHA-1 is deprecated. Switch the signing algorithm to SHA-256 unless the app can't handle it." });
    else f.push({ severity: "ok", title: `${s.location} is signed`, detail: alg });
    if (s.cert) {
      const c = s.cert;
      if (c.daysLeft < 0) f.push({ severity: "critical", title: "Signing certificate has expired", detail: `${c.subject}, expired ${c.notAfter.toDateString()}`, playbook: "saml-signature" });
      else if (c.daysLeft < 30) f.push({ severity: "warn", title: `Signing certificate expires in ${c.daysLeft} days`, detail: `${c.subject}. Plan the rollover now.`, playbook: "cert-rollover" });
      if (exp.certThumbprint) {
        if (normalizeThumbprint(exp.certThumbprint) === c.sha1)
          f.push({ severity: "ok", title: "Signing certificate matches the thumbprint on file", detail: c.sha1 });
        else
          f.push({ severity: "critical", title: "Signing certificate is NOT the one on file", detail: `Response signed with ${c.sha1}, inventory expects ${normalizeThumbprint(exp.certThumbprint)}. The IdP probably rolled its certificate; upload the new one to the app.`, playbook: "saml-signature" });
      }
    }
  }
  if (p.signatures.length)
    f.push({ severity: "info", title: "About signature checks", detail: "This tool confirms which certificate signed the message and compares it to the one on file. The app itself does the full cryptographic verification." });

  // Clock skew hint
  if (p.issueInstant) {
    const diff = Math.abs(Date.now() - p.issueInstant.getTime());
    if (diff < 10 * 60000 && diff > 2 * 60000)
      f.push({ severity: "warn", title: `IssueInstant is ${Math.round(diff / 1000)}s off from this computer's clock`, detail: "If this is a fresh capture, the clocks may be out of sync.", playbook: "clock-skew" });
  }
  return f;
}

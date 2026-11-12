import type { ProtocolId } from "./types";

/**
 * The protocol registry. Every screen reads protocol metadata from here, so adding
 * a protocol (SCIM, Kerberos, LDAP, WS-Federation...) starts with one entry below,
 * then its tools, wizard and playbooks are added under their own files.
 */
export interface ProtocolModule {
  id: ProtocolId;
  name: string;
  short: string;
  /** One-line purpose shown on cards. */
  purpose: string;
  /** What question the protocol answers. */
  answers: string;
  status: "available" | "planned";
  /** Tool routes that support this protocol. */
  tools: string[];
}

export const PROTOCOLS: ProtocolModule[] = [
  {
    id: "saml",
    name: "SAML 2.0",
    short: "SAML",
    purpose: "Browser single sign-on using signed XML assertions.",
    answers: "Who is this user, and has the identity provider vouched for them?",
    status: "available",
    tools: ["saml", "metadata"],
  },
  {
    id: "oidc",
    name: "OpenID Connect",
    short: "OIDC",
    purpose: "Sign-in built on OAuth 2.0, using JSON ID tokens (JWTs).",
    answers: "Who is this user? (authentication)",
    status: "available",
    tools: ["jwt", "metadata"],
  },
  {
    id: "oauth",
    name: "OAuth 2.0",
    short: "OAuth",
    purpose: "Delegated or app-only access to APIs using access tokens.",
    answers: "What is this app allowed to do? (authorization)",
    status: "available",
    tools: ["jwt", "metadata"],
  },
  {
    id: "scim",
    name: "SCIM 2.0",
    short: "SCIM",
    purpose: "Provisioning: creating, updating and removing users and groups in apps.",
    answers: "Does the user's account exist in the app, with the right groups?",
    status: "planned",
    tools: [],
  },
];

export const protocolById = (id: ProtocolId) => PROTOCOLS.find((p) => p.id === id)!;

# Federation 360

A dashboard for setting up, managing and troubleshooting **SAML 2.0, OpenID Connect and OAuth 2.0**
integrations across tenants (Microsoft Entra ID, AWS IAM Identity Center, Okta, Ping, AD FS, generic apps).
It also teaches as you go: every field and finding explains what it means and what breaks when it's wrong.

## What's inside

| Area | What it does |
| --- | --- |
| Overview | Health of every integration: problems, expiring certificates/secrets, coverage per tenant. |
| Inventory | Tenants and app integrations with identifiers, URLs, cert/secret expiry, owner. JSON backup/import. |
| Setup wizards | Entra SAML app, Entra → AWS IAM Identity Center (SAML + SCIM), OIDC auth code + PKCE, OAuth client credentials (with PowerShell and Python). |
| SAML decoder | Decodes POST/Redirect binding messages, checks status, issuer, audience, ACS, time window, signing cert vs inventory, AWS role attributes. |
| JWT decoder | Explains claims, checks iss/aud/exp, verifies RS/PS/ES/HS signatures against a pasted JWKS. |
| Metadata checker | SAML metadata (endpoints, certs, expiry), OIDC discovery, JWKS. |
| Playbooks | 45 error playbooks: AADSTS codes, SAML app-side errors, AWS, OAuth/OIDC. |
| Learn | Sequence diagrams of each flow, glossary, troubleshooting method, job-skills map. |

Everything runs in the browser. Nothing you paste is sent anywhere.

**Use it online:** https://sectechtalk.github.io/federation-360/ (deployed from `main` by `.github/workflows/pages.yml`).
Your inventory is saved only in your own browser; use **Back up / import** to move it.

## Run it

```bash
npm install
npm run dev      # http://localhost:5173
npm test         # unit tests for the SAML, JWT, X.509, metadata and health logic
npm run build    # dist/index.html (single file) + dist/federation-360.html (Claude artifact body)
```

Outside a Claude artifact the inventory is stored in the browser's localStorage. Inside the published
artifact it uses the artifact database (`src/lib/store.ts` picks automatically).

## Extending (SCIM and other protocols)

1. Add the protocol to `src/lib/protocols.ts` (set `status: "available"`).
2. Add its tool view under `src/views/` and a route in `src/App.tsx`.
3. Add wizards to `src/data/wizards.ts` and playbooks to `src/data/playbooks.ts`.
4. Add its health checks to `src/lib/health.ts`.

## Layout

```
src/lib/      protocol logic (saml.ts, jwt.ts, x509.ts, metadata.ts, health.ts, store.ts)
src/data/     content (wizards, playbooks, learn, samples, example inventory)
src/views/    one file per screen
tests/        vitest tests
```

Sample certificates and tokens are generated for examples only and sign nothing real.

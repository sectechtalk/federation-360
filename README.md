# Federation 360

**Just been told you own single sign-on? Start here.**

Federation 360 is a free dashboard for the people who set up, look after and fix **sign-in between systems**:
SAML 2.0, OpenID Connect, OAuth 2.0 and SCIM 2.0, across Microsoft Entra ID, AWS IAM Identity Center, Okta, Ping,
AD FS and any app that speaks those standards. It is written for someone who has only heard the words and has just
been handed the job: every page explains what a field means, what breaks when it is wrong, and what to do next.

It runs in your browser. Nothing you paste into it is sent anywhere.

## The four words, in plain English

| Word | What it does | What you'll hear at work |
| --- | --- | --- |
| **SAML** | Lets people use their one work account to sign in to another company's app (Salesforce, Workday, ServiceNow) without a separate password. | "SSO", "the SAML cert is expiring", "entity ID", "reply URL" |
| **OpenID Connect (OIDC)** | Does the same job for newer web and mobile apps: it proves who the user is. | "app registration", "client ID", "redirect URI", "ID token" |
| **OAuth** | Decides what an app is allowed to do, such as read a calendar or call an API. OIDC is built on top of it. | "client secret", "access token", "scopes", "consent" |
| **SCIM** | Creates and removes a person's account in an app automatically when they join or leave. | "provisioning", "the user isn't in the app yet", "quarantine" |

## Your first three weeks with it

1. **Week 1: learn the words and practise safely.** Open **Start here** (the page the app opens on), then **Learn**. Build a free practice
   tenant with **Build your lab** so you can break things where nobody is affected.
2. **Weeks 2 to 3: find out what you own.** Use **Discover** to read every SAML, OIDC and OAuth app in your Entra
   tenant (read-only). It lands in **Inventory**, where you record owners and what each app is for.
3. **Every week after that: keep it healthy.** Check **Overview** for expired or expiring certificates and secrets,
   broken settings and apps with no owner. When a sign-in fails, use **Flow tracer** and **Playbooks**.

## What's inside

**Getting started**

| Page | What it does |
| --- | --- |
| Start here | The page the app opens on. SAML, OIDC/OAuth and SCIM in plain words, a first/next/every-week path with ticks saved in your browser, and a "someone just asked me to..." guide that sends you to the right page. |

**Manage**

| Page | What it does |
| --- | --- |
| Overview | This week's health: what to do today, expired and expiring certificates and secrets, problems, coverage per tenant. |
| Inventory | Every tenant and app integration: identifiers, URLs, certificate, secret and SCIM token expiry, owner. Back up and import as JSON. **Export expiry report** saves a list of every certificate and secret with its expiry date, never the secret values, for certificates-360 or any other tool ([format](docs/credentials-export.md)). |
| Discover | Reads every SAML, OIDC and OAuth app in an Entra tenant through Microsoft Graph, read-only: certificates, secrets (names and dates only), redirect URIs, owners, permissions and consent. Merges it into Inventory without deleting anything. |
| Setup wizards | Step-by-step setups that fill in the values for you: SAML app in Entra, Entra to AWS IAM Identity Center (SAML and SCIM), SCIM provisioning from Entra, OIDC sign-in with PKCE, OAuth client credentials (with PowerShell and Python). |

**Troubleshoot**

| Page | What it does |
| --- | --- |
| Flow tracer | Drop a HAR file recorded in Edge or Chrome. It lays out every sign-in hop, decodes each SAML message and token, checks the response against the request, maps AADSTS errors to playbooks, and can save a redacted copy to share. |
| Live test | Runs real SAML, OpenID Connect and client credentials sign-ins against your practice tenant through the lab test app, and shows every hop with the same checks. |
| Connectivity test | Builds a list of every sign-in endpoint your apps depend on and packages a Windows PowerShell script that checks, from real devices, that they can reach them. No agent is installed. |
| SAML decoder | Decodes a SAML request or response and checks status, issuer, audience, reply URL, time window, signing certificate and AWS role attributes. |
| JWT decoder | Explains every claim in a token, checks issuer, audience and expiry, and verifies the signature against a pasted key set (JWKS). |
| SCIM checker | Explains SCIM requests, responses and errors, flags Entra's non-standard PATCH format, and compares the provisioned account with the name used at sign-in. |
| Metadata checker | Checks SAML metadata (endpoints, certificates, expiry), OIDC discovery documents and JWKS. |
| Playbooks | 52 fixes for common errors: AADSTS codes, SAML errors shown by apps, AWS, OAuth and OIDC, SCIM provisioning. |

**Learn**

| Page | What it does |
| --- | --- |
| Learn | How to create, maintain and remove each kind of integration, sequence diagrams of every flow, a glossary and a troubleshooting method. |
| Build your lab | Click-by-click steps and a kit (`lab/`) to build your own free Entra practice tenant with Terraform. |

## Use it

### Online

Open **https://sectechtalk.github.io/federation-360/**. Your inventory is saved only in your own browser; use
**Back up / import** on the Inventory page to move it. Discover works online through the export script (below).
Live test and the Discover **Sign in and scan** button need the app running on your own PC.

### On your PC with Docker (recommended)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) (free for personal use) and Git.

```powershell
git clone https://github.com/sectechtalk/federation-360.git
cd federation-360
docker compose up --build -d     # open http://localhost:5173
```

| Command | What it does |
| --- | --- |
| `docker compose logs -f dev` | Watch the app's log (Ctrl+C stops watching, not the app). |
| `docker compose down` | Stop it. |
| `docker compose --profile preview up --build -d preview` | Run the production build on http://localhost:8080. |

Both ports listen on `127.0.0.1` only, so nobody else on your network can open them. The app starts again on its own
when Docker starts, until you stop it with `docker compose down`. If you change `package.json`, run
`docker compose down -v` and then `docker compose up --build -d`. Keep port 5173: Discover's browser sign-in uses
`http://localhost:5173` as its redirect URI.

### On your PC with Node.js

```bash
npm install
npm run dev      # http://localhost:5173
npm test         # unit tests
npm run build    # dist/index.html, one self-contained file
```

## What it sends, and where

| Feature | Talks to | When |
| --- | --- | --- |
| Decoders, checkers, Flow tracer, Inventory | Nothing. Everything stays in the browser tab. | Always |
| Discover | Microsoft Graph, read-only (`Application.Read.All`, `Directory.Read.All`, delegated) | Only after you sign in |
| Live test | Microsoft Entra ID and the lab test app you run yourself | Only when you press a test button |
| Connectivity test script | Only the hosts in its plan, anonymously | When it runs on a device |

Graph never returns secret values, and the export script also drops certificate bodies and secret hints.
Flow tracer keeps only sign-in hops (cookies and page content are dropped), and **Download redacted copy** also
removes codes, token signatures and SAML signature values.

## Discover your tenant

Two ways in, one result. Use a test tenant first.

1. **Export script (works everywhere, including online).** On the **Discover** page press
   **Download Export-F360EntraInventory.ps1**, then in PowerShell 7:

   ```powershell
   cd $HOME\Downloads
   Unblock-File .\Export-F360EntraInventory.ps1
   .\Export-F360EntraInventory.ps1 -TenantId <your-tenant-id>
   ```

   Sign in when asked. The script uses the Microsoft Graph PowerShell module, sends GET requests only and saves
   `f360-entra-export.json`. Load that file on the Discover page. Add `-UseDeviceCode` to sign in with a code instead.
2. **Sign in and scan (when the app runs on `http://localhost:5173`).** Signs in as a single-page app with PKCE against
   the lab's `F360-Discovery` app registration (Terraform output `discovery_client_id`). The token stays in memory.

Merge rules: the tenant wins for technical facts; you win for status, environment, provisioning, SCIM and notes.
Hand-entered apps are matched by client ID or SAML entity ID. Nothing is ever deleted; apps that disappear are flagged.

## Flow tracer: see a sign-in hop by hop

Works on any app with nothing installed. Open the app in an InPrivate window, press **F12**, open **Network**, tick
**Preserve log**, sign in, right-click the list and choose **Save all as HAR with content**, then drop the file on the
Flow tracer page. The file is read in that tab only.

## Build your lab (free)

The **Build your lab** page walks you through creating a free Microsoft Entra test tenant (Entra ID Free, no
subscription or paid licence needed) and filling it with test apps and users using Terraform, run from GitHub Actions
with no stored secrets.

| File | What it does |
| --- | --- |
| `lab/bootstrap/New-F360LabBootstrap.ps1` | One-time setup: test users and a secret-less deploy identity that trusts GitHub Actions. Saves `lab/lab-values.json` (not committed). |
| `lab/Connect-F360LabPipeline.ps1` | Creates the HCP Terraform workspace (free, Local execution) and sets the GitHub environment, variables and secret. |
| `lab/Invoke-F360Lab.ps1` | Runs plan, apply or destroy in GitHub Actions and prints the result. |
| `lab/terraform/` | The test apps for SAML, OIDC and OAuth. |
| `.github/workflows/lab.yml` | The workflow the scripts start. |
| `lab/scim/Start-F360ScimLab.ps1` | Optional. A SCIM 2.0 app on your PC behind a free Cloudflare quick tunnel, with Entra provisioning pointed at it. Every request is saved for the SCIM checker. |
| `lab/testapp/Start-F360TestApp.ps1` | Optional. Starts the lab test app in Docker on `http://localhost:5174` for the **Live test** page. |
| `lab/testapp/azure/` | Optional. The same test app on Azure Static Web Apps, Free plan only ([details](lab/testapp/azure/README.md)). |

```powershell
./lab/bootstrap/New-F360LabBootstrap.ps1 -TenantId <lab-tenant-id> -GitHubRepository <you>/federation-360 -IUnderstandThisIsALabTenant
./lab/Connect-F360LabPipeline.ps1 -TerraformOrganization <your-hcp-terraform-org>
./lab/Invoke-F360Lab.ps1 -Action plan
./lab/Invoke-F360Lab.ps1 -Action apply
./lab/scim/Start-F360ScimLab.ps1 -TenantId <lab-tenant-id>   # optional: SCIM provisioning
./lab/testapp/Start-F360TestApp.ps1                          # optional: Live test page
```

**Only ever point the lab kit at a tenant you created for testing.** It creates users and apps.

### Live test

The lab test app (`lab/testapp/server.mjs`, Node, no dependencies) plays three parts:

| Test | Who does what | Entra side (created by the lab Terraform) |
| --- | --- | --- |
| SAML | The test app sends the SAML request and receives the response at `/saml/acs`. It can break the request on purpose (wrong Issuer, wrong reply URL) so you can see the error. | `LAB-TestApp-SAML` |
| OpenID Connect | Federation 360 signs in with authorization code and PKCE, then hands the access token to the test app's API. | `F360-LiveTest`, delegated `Jobs.Read` on `LAB-API` |
| Client credentials | The test app signs in as `LAB-Daemon` with a certificate (the private key stays on your PC) and checks the app-only token. | `LAB-Daemon`, `Jobs.Read.All` on `LAB-API` |

The test app's API checks tokens the way a real API must (signature against Entra's published keys, issuer, audience,
lifetime, tenant, scope or role) and shows every check. No tunnel is needed, because Entra sends SAML responses and
codes back through the browser and allows `http://localhost` reply URLs. After the lab `apply`, run
`./lab/testapp/Start-F360TestApp.ps1` once; it finds the lab apps, creates the `LAB-Daemon` certificate, writes
`lab/testapp/.local/config.json` (not committed) and starts the container. Then open `http://localhost:5173/#livetest`.

## Connectivity test (agentless)

Checks from real Windows devices that they can reach every identity provider and app endpoint their sign-ins depend on.
One script, `connectivity/Test-F360Connectivity.ps1` (Windows PowerShell 5.1, no modules), runs as an Intune
Remediations **detection** script. It can also be published through Remediation 360.

- **Checks**, all anonymous: DNS, TCP 443, TLS (trust, expiry, protocol, and TLS inspection on
  `login.microsoftonline.com`), an unauthenticated GET, and the device clock against Entra (5 minute limit). No
  credentials or tokens are sent. Behind a proxy it uses the proxy Windows would use.
- **Plan**: the Connectivity test page builds it from the apps you choose and embeds it in the script, so the signed
  script and its plan can't drift.
- **Output**: a JSON file per run in `C:\ProgramData\F360\results` (newest 20 kept), one summary line for Intune, and
  exit 1 when a check failed (Intune shows *With issues*). `connectivity/Remediate-F360Connectivity.ps1` does nothing;
  publish with *Run remediation script* off.
- **Results**: drop the JSON files, an Intune device status export, or pasted summary lines on the page for a
  by-device and by-check view with advice.

Try it on your own PC first. Download the plan from the page into Downloads, then:

```powershell
cd $HOME\federation-360
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\connectivity\Test-F360Connectivity.ps1 -PlanPath "$HOME\Downloads\f360-plan-<id>.json" -OutputDir "$HOME\federation-360\connectivity\results"
```

## For developers

### Layout

```
src/views/        one file per page
src/lib/          protocol logic (saml.ts, jwt.ts, scim.ts, x509.ts, metadata.ts, flow.ts, har.ts, health.ts, store.ts)
src/lib/discovery browser sign-in (entraLive.ts) and inventory merge (merge.ts)
src/data/         content (wizards, playbooks, learn, lab steps, samples, example inventory)
src/360/          shared look and app switcher for the 360 family of tools
lab/              practice tenant kit, SCIM lab app, Live test app
connectivity/     agentless connectivity test script
vendor/           the shared tenant collector package
tests/            vitest tests
docs/             file formats
```

### The tenant collector

Discover's Graph collector, the Entra mapper, the credentials export format and the PowerShell export script live in the
shared package `@sectechtalk/f360-collector` (MIT), which other 360 tools use too. It is included as a package file,
`vendor/sectechtalk-f360-collector-<version>.tgz`, so installing needs no registry or token. To take a new version,
put the new `.tgz` in `vendor/`, run `npm install ./vendor/sectechtalk-f360-collector-<version>.tgz`, delete the old
one and commit.

### Adding a protocol

1. Add it to `src/lib/protocols.ts` (set `status: "available"`).
2. Add its page under `src/views/` and a route in `src/App.tsx`.
3. Add wizards to `src/data/wizards.ts` and playbooks to `src/data/playbooks.ts`.
4. Add its health checks to `src/lib/health.ts`.

### House rules

- Buttons always have a filled colour that never matches the page; disabled buttons are grey with a dashed border.
  `tests/button-contrast.test.ts` fails the build if a page breaks this.
- Everything in the lab must stay on free tiers.
- The `security` workflow runs `npm audit`, a secret scan (gitleaks), the tests and the build on every pull request.

Sample certificates and tokens in the app are generated for examples only and sign nothing real. Example tenants and
apps are fictional.

## License

MIT. See [LICENSE](LICENSE).

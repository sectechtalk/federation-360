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
   broken settings and apps with no owner. When a sign-in fails, use **Flow tracer** and **Playbooks**. The
   **Flow tracer training** on the Learn page teaches that in seven short exercises before the first real one.

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

**Protect**

| Page | What it does |
| --- | --- |
| MFA and SSO coverage | How many people have a phishing-resistant sign-in method (passkey, Windows Hello, macOS Platform SSO), which admins don't, a three-wave rollout plan with a download of who is left in each wave, the authentication methods policy, and SSO coverage: which enterprise apps use SAML or OIDC, require assignment and remove leavers with SCIM. Works on Entra ID Free (it counts methods per user instead of using Microsoft's P1 report). Read with `posture/Export-F360Posture.ps1` or by signing in. |
| OAuth grants | Every permission your apps hold, rated Critical, High, Medium or Low by what it lets the app do on its own. Finds apps that could take over the tenant, apps that read everyone's mail or files with no user signed in, third-party apps users approved without IT (shadow IT), powerful apps with no owner, and grants the app no longer asks for. Links to the Entra and Azure portal pages that change each one, and exports a CSV. Uses the permissions Discover already reads; no extra access. |
| Detections | Nine identity detection rules written as tested code: MFA fatigue, password spray, password guessing followed by a sign-in, legacy authentication, a session token used from two countries, new sign-in method right after a sign-in from a new country, a risky sign-in that succeeded (Entra ID Protection rated it medium or high), a sensitive change (role, MFA method, credentials, password) right after a risky sign-in, and app consent right after a suspicious sign-in. Each has its MITRE ATT&CK technique, false positives, a response playbook and the same logic in KQL for Microsoft Sentinel. Reads sign-in and audit logs you load (the admin center's Download JSON works on Entra ID Free; `detections/Export-F360SignIns.ps1` reads them through Graph on P1), an Entity 360 timeline CSV, or reads them straight from the tenant with **Read from your tenant** (P1 or higher; risk levels need P2). |
| How access ends | For every enterprise app: access, ID and SAML token life (Entra default or a token lifetime policy), Conditional Access sign-in frequency, persistent browser and continuous access evaluation (P1), and the health of its SCIM provisioning job (schedule, last cycle, quarantine). Adds a **declared app profile** on each Inventory entry for what only the vendor knows: the app's own session length, idle timeout and whether it ends sessions on a SCIM disable. Read with `access/Export-F360Access.ps1` or by signing in (adds the read-only Synchronization.Read.All permission). |
| Activity | Loads all four Entra sign-in log tabs (interactive, non-interactive silent refreshes, service principal, managed identity), audit logs, provisioning logs and Entity 360's timeline CSV, and keeps a small per-person, per-app summary in this browser: last sign-in, last silent refresh, protocol, devices that used device SSO, SCIM results, and account events such as disabled and sessions revoked. Measures **refresh cadence**: how often each app really goes back to Entra. Free tenants use the admin center's Download JSON; `activity/Export-F360Activity.ps1` and sign-in read through Graph on P1. With the Federation 360 Capture extension, **Live refresh capture** lists the token refreshes this browser makes, per app, with the gap between them and the token lifetime that came back. |
| Investigate | One incident, every source, one timeline. Load sign-in and audit logs (files, **Read from your tenant**, or **Investigate this person** on a Detections hit), Detections exports, Entity 360 timeline CSVs, and Exchange evidence (`Get-InboxRule` and `Get-MessageTraceV2` as JSON); anything else is kept and hashed. Every step is tagged with its MITRE ATT&CK technique and grouped by tactic; a likely phishing lure, forwarding or hiding inbox rules, role and credential changes are flagged. Scope (addresses that got in, apps reached), a suggested severity with its reason, a verdict, findings, and a NIST SP 800-61 checklist with timed ticks. **Contain and clean up**: Remediation 360 hand-offs (disable everywhere, isolate a device seen in the suspicious sign-ins), the contain runbook, a clean-up runbook (MFA methods added during the incident, consent grants, inbox rules, revoke sessions again; What-if unless `-Run`), and **Verify containment** (account disabled, sessions revoked after containment, no successful sign-in since). **Download evidence pack**: the case as JSON with a SHA-256 chain of custody for every file, plus a one-page HTML incident report for leadership. |
| User lookup | One person, every app they can reach: assigned directly or through nested groups, consented, or simply signed in to. For each app it shows the last sign-in and silent refresh, whether tokens are likely still live, the last SCIM result, and the **offboarding exposure window**: how long they could still get in if you disabled them now, longest first. Apps whose own session length isn't declared show as unknown, so you know where to look. Flags sign-ins to Microsoft tools often used in device code phishing (Azure CLI, Graph Command Line Tools and others). `lookup/Export-F360UserAccess.ps1` or a read-only browser sign-in (Directory.Read.All, AuditLog.Read.All). **Contain**: **Disable user everywhere in Remediation 360**, **Remove from this app in Remediation 360** and **Isolate in Remediation 360** open Remediation 360 with the request filled in (Remediation 360 does the writes, as you, and audits them); **Download contain runbook** gives the same steps as PowerShell that only shows what it would do until you add `-Run`; **Verify with a fresh read** compares the read before and after; a lab offboarding drill records the measured times. |

**Troubleshoot**

| Page | What it does |
| --- | --- |
| Flow tracer | Shows sign-ins live from the Federation 360 Capture extension (Edge and Chrome), or a pasted or dropped HAR (HTTP Archive) recording. It lays out every sign-in hop, decodes each SAML message and token, checks the response against the request, maps AADSTS errors to playbooks, and can save a redacted copy to share. |
| Live test | Runs real SAML, OpenID Connect and client credentials sign-ins against your practice tenant through the lab test app, and shows every hop with the same checks. |
| Connectivity test | Builds a list of every sign-in endpoint your apps depend on and packages a Windows PowerShell script that checks, from real devices, that they can reach them. No agent is installed. |
| SAML decoder | Decodes a SAML request or response and checks status, issuer, audience, reply URL, time window, signing certificate and AWS role attributes. |
| JWT decoder | Explains every claim in a token, checks issuer, audience and expiry, and verifies the signature against a pasted key set (JWKS). |
| SCIM checker | Explains SCIM requests, responses and errors, flags Entra's non-standard PATCH format, and compares the provisioned account with the name used at sign-in. |
| Metadata checker | Checks SAML metadata (endpoints, certificates, expiry), OIDC discovery documents and JWKS. |
| Playbooks | 58 fixes for common errors and incidents: AADSTS codes, SAML errors shown by apps, AWS, OAuth and OIDC, SCIM provisioning, risky OAuth grants, the phishing-resistant MFA rollout, and responding to MFA fatigue, account takeover and stolen tokens. |

**Learn**

| Page | What it does |
| --- | --- |
| Learn | How to create, maintain and remove each kind of integration, sequence diagrams of every flow, a glossary and a troubleshooting method. Includes **Device SSO**: how macOS Platform SSO and the Windows Primary Refresh Token (PRT) sign a user in to the device, and how that carries on into browser SSO for SAML and OIDC apps, with what to check when the user is prompted anyway. Also the **Flow tracer training**: seven hands-on exercises that take a new admin from reading an example sign-in to capturing one, breaking one in the lab, diagnosing it and sharing a redacted copy. Read-only reading, no tenant access. |
| Build your lab | Click-by-click steps and a kit (`lab/`) to build your own free Entra practice tenant with Terraform. |

## Where each part stands

Honest status, so you know what has been proven and what hasn't.

| Status | Parts |
| --- | --- |
| **Run against a real free Entra test tenant** | Build your lab, Discover, Live test (SAML, OpenID Connect and client credentials), SCIM lab. |
| **Built and unit-tested, not yet run for real** | Federation 360 Capture extension (tested end to end in Chromium against a stand-in sign-in server; it loads and connects in Edge and Chrome, but a capture of a real Entra sign-in has not been confirmed yet). Flow tracer's Entra's verdict and `signin-logs/Connect-F360SignInLogs.ps1` (tested with Microsoft Graph mocked; needs an Entra ID P1 tenant to run for real). Connectivity test script (not yet published through Intune to managed devices). |
| **Tried on the built-in sample data only** | OAuth grants, MFA and SSO coverage, Detections (including Read from your tenant), Investigate, How access ends, Activity, User lookup. Their PowerShell scripts, `posture/Export-F360Posture.ps1`, `detections/Export-F360SignIns.ps1`, `access/Export-F360Access.ps1`, `activity/Export-F360Activity.ps1` and `lookup/Export-F360UserAccess.ps1`, have not been run yet. |
| **Reference content** | Start here, Learn (including Device SSO), Setup wizards, Playbooks, and the SAML, JWT, SCIM and metadata decoders, which work on anything you paste. |
| **Not built yet** | Identity settings kept as Terraform with drift checks, a SCIM joiner/mover/leaver test run, and access review sheets. |

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
| Detections | Nothing. Log files you load are read in that tab only. The export script and **Read from your tenant** talk to Microsoft Graph, read-only (`AuditLog.Read.All`), with your own sign-in. | When you load a file or click Read from this tenant |
| Investigate | Nothing. Files are read and hashed in that tab only; the case is gone on reload unless you download the evidence pack. **Read from your tenant** and **Verify containment** read Microsoft Graph with your own sign-in (`AuditLog.Read.All`, `Directory.Read.All`). The contain and clean-up runbooks change the tenant only when you run them with `-Run`. | When you add a file, read the tenant or click Verify containment |
| MFA and SSO coverage | Microsoft Graph, read-only (adds `UserAuthenticationMethod.Read.All` and `Policy.Read.All`, delegated). Keeps method types only, never phone numbers or keys. | Only after you sign in or load the script's file |
| Connectivity test script | Only the hosts in its plan, anonymously | When it runs on a device |
| Federation 360 Capture extension | Nothing. Hands sign-in hops only to Federation 360's own pages open in the same browser, when one asks. | While it's loaded |
| Flow tracer: Entra's verdict | Microsoft Graph sign-in logs, read-only (`AuditLog.Read.All`, delegated) | Only after you set it up and sign in |

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

**Automatic (recommended).** Load the Federation 360 Capture extension once, and every SAML, OpenID Connect and OAuth
sign-in in that browser appears on the Flow tracer page as it happens, decoded and checked. Nothing to save or upload.
The same `extension` folder works in both browsers:

| | Microsoft Edge | Google Chrome |
| --- | --- | --- |
| 1. Open | `edge://extensions` | `chrome://extensions` |
| 2. Turn on | **Developer mode** (left side) | **Developer mode** (top right) |
| 3. Click | **Load unpacked**, choose the `extension` folder in your federation-360 folder | **Load unpacked**, choose the `extension` folder in your federation-360 folder |
| 4. Private windows | **Details** > **Allow in InPrivate** | **Details** > **Allow in Incognito** |

Open Flow tracer (or click the extension's toolbar button): a green **Capturing** label shows it's connected. Sign in to
any app in another tab and the flow appears within a second; the newest sign-in opens by itself. Each sign-in is
listed with its time, its kind, the app it was for and, if it was stopped, the error code. An attempt the identity
provider refuses is a sign-in of its own, so the next attempt in the same tab doesn't run into it.

**New to this?** Click **New here? Take the training** on the Flow tracer page, or open
`http://localhost:5173/#learn/flow-training`. Seven exercises, each with where to click and what success looks like.
Exercises 1, 2, 3 and 7 need only a browser, 4 and 5 use the lab, and 6 needs a tenant with Entra ID P1 or higher.

What it keeps: SAML messages, authorize and token calls (including the token replies a single-page app fetches in the
background), redirects that carry a code or token, AADSTS error pages, and API calls with a token while that tab is
signing in. Everything else is ignored. From a posted form it keeps only the sign-in protocol's own fields: a typed
password, a one-time code and the identity provider's session values are dropped before the request is even
remembered, and `client_secret`, `code_verifier` and refresh tokens are recorded only as "(present)" or "(issued)".
The codes and tokens a sign-in brings back are kept, because decoding them is the point, so treat a browser with the
extension loaded like any place that holds live tokens.

Hops stay in browser memory until the browser closes. They are handed only to Federation 360's own pages
(`http://localhost:5173`, `http://localhost:8080`, the same ports on `127.0.0.1`, and the published site), and only
when the page asks; no other page on `localhost` receives anything. Tokens an app's own server requests never pass
through the browser, so no browser tool sees them; Entra's verdict (below) covers those.

**Entra's verdict.** Beside each sign-in, Flow tracer shows the matching entry from Entra's sign-in log in plain words:
whether Entra let the user in, the error, which Conditional Access policy blocked it and what to do. One-time setup per
tenant, in PowerShell 7, as a Global Administrator or Privileged Role Administrator:

```powershell
cd $HOME\federation-360
./signin-logs/Connect-F360SignInLogs.ps1 -TenantId <your-tenant-id-or-domain>
```

It creates a read-only single-page-app registration ("Federation 360 sign-in logs", delegated `AuditLog.Read.All`,
`Directory.Read.All`, `Policy.Read.ConditionalAccess`, no secret), grants admin consent and reopens Flow tracer connected.
Then click **Sign in to read sign-in logs** once a day. The person reading needs the **Security Reader** role
(Reports Reader works but hides policy names). Microsoft serves sign-in logs to apps only on Entra ID P1 or higher
(Microsoft 365 E3, E5 and E7 include it); on a free tenant the script changes nothing and Flow tracer points to the Entra
admin center instead. `-Remove` deletes the app registration.

**Without the extension.** Press **F12**, open **Network**, tick **Preserve log**, sign in, right-click the list and choose
**Copy** > **Copy all as HAR (sanitized)**, then press **Ctrl+V** on the Flow tracer page. A HAR (HTTP Archive) file saved
with **Save all as HAR with content** can also be dropped on the page. Either way it's read in that tab only.

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
src/components/   shared UI, including ActionButton and BusyNote (busy.tsx) for button feedback
src/lib/          protocol logic (saml.ts, jwt.ts, scim.ts, x509.ts, metadata.ts, flow.ts, har.ts, health.ts, store.ts),
                  OAuth grant ratings (grants.ts), MFA and SSO coverage (posture.ts), Entra sign-in logs (entraLogs.ts),
                  how access ends per app (access.ts, accessCollect.ts), activity summary (activity.ts, activityCollect.ts),
                  user lookup and exposure window (lookup.ts, lookupCollect.ts), contain hand-offs, runbook and verify (contain.ts)
src/lib/discovery browser sign-in (entraLive.ts) and inventory merge (merge.ts)
src/detections/   detection rules with KQL and ATT&CK (rules.ts), log normaliser (events.ts), sample log (sample.ts)
src/data/         content (wizards, playbooks, learn, device SSO, lab steps, samples, example inventory)
src/360/          shared look and app switcher for the 360 family of tools
extension/        Federation 360 Capture browser extension (Edge and Chrome)
signin-logs/      one-time setup for Entra's verdict in Flow tracer
posture/          MFA and SSO coverage export script
access/           How access ends export script
activity/         Activity export script
lookup/           User lookup export script
detections/       sign-in and audit log export script
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
- Every button shows it is doing something. Use `ActionButton` from `src/components/busy.tsx`: it shows a verb such as
  "Searching…" with a spinner and a seconds counter, then "✓" with what happened or "✗" with the exact error. A busy
  button stays coloured and never looks disabled. `tests/busy-feedback.test.tsx` checks every page.
- Everything in the lab must stay on free tiers.
- The `security` workflow runs `npm audit`, a secret scan (gitleaks), the tests and the build on every pull request.

Sample certificates and tokens in the app are generated for examples only and sign nothing real. Example tenants and
apps are fictional.

## License

MIT. See [LICENSE](LICENSE).

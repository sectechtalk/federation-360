# Lab test app on Azure Static Web Apps (Free)

The same test app as `lab/testapp/server.mjs`, hosted on Azure instead of Docker on your PC. Both run from one
shared file, `lab/testapp/core.mjs`, so they behave the same. Switch between them on Federation 360's Live test page.

## Cost: $0

- Static Web Apps **Free plan**: overage is "Unavailable" on Free ([quotas](https://learn.microsoft.com/azure/static-web-apps/quotas)),
  so when the monthly quota (100 GB) runs out the site stops; it never bills.
- The API is the Free plan's **managed functions** (HTTP only). No storage account, no Application Insights.
- The deploy script refuses to continue if the site is on any plan other than Free.
- It needs an active Azure subscription to live in. A Free Trial subscription is disabled when it ends unless it is
  upgraded to pay-as-you-go; the Free plan still costs nothing after the upgrade.

## How it differs from the PC version

| | PC (Docker) | Azure |
| --- | --- | --- |
| Address | http://localhost:5174 | https://&lt;name&gt;.azurestaticapps.net |
| SAML endpoints | /saml/login, /saml/acs | /api/saml/login, /api/saml/acs (Static Web Apps only routes code under /api) |
| Captures | kept in lab/testapp/captures | not kept: returned in the response, or in the URL fragment after SAML; Federation 360 keeps them in your browser |
| Client credentials key | lab/testapp/.local (never leaves your PC) | copied into the site's app settings (lab-only LAB-Daemon) |

While Entra is away, the first SAML hop rides in a 15-minute `HttpOnly; Secure; SameSite=None` cookie.

## Files

- `Deploy-F360TestAppAzure.ps1` creates the site (Free), adds the reply URL to LAB-TestApp-SAML, sets the GitHub
  variable `LAB_TESTAPP_CLOUD_ACS` (so the lab workflow keeps that reply URL), copies settings, deploys, checks it.
  `-Remove` deletes it.
- `stage.mjs` assembles `app/` and `api/` plus `../core.mjs` into one folder for the Static Web Apps CLI.
- `api/testapp` is one function (Node.js programming model v3, no npm packages) that serves every `/api/*` route.

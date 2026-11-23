import { WORKDIR } from "./workdir";

export const LAB_REPO = "https://github.com/sectechtalk/federation-360";

export interface LabStep {
  title: string;
  minutes: number;
  why: string;
  actions: string[];
  code?: { title: string; body: string }[];
  note?: string;
}

export const LAB_BUILDS = [
  { name: "F360-LiveTest", protocol: "oidc", what: "Single-page app for auth code + PKCE sign-ins from Federation 360." },
  { name: "F360-Discovery", protocol: "oidc", what: "Single-page app for “Sign in and scan” on Discover and “Sign in and read” on MFA and SSO coverage. Read-only delegated Graph permissions (Application.Read.All, Directory.Read.All, UserAuthenticationMethod.Read.All, Policy.Read.All); you consent on first sign-in." },
  { name: "LAB-OIDC-Playground", protocol: "oidc", what: "Sends a real ID token to jwt.ms so you can read it. Uses implicit flow on purpose, so the inventory flags it." },
  { name: "LAB-SAML-App", protocol: "saml", what: "Enterprise app with a signing certificate. Its SAML response is posted to jwt.ms. Assignment is required, so you can trigger AADSTS50105." },
  { name: "LAB-API", protocol: "oauth", what: "A protected API with a delegated scope (Jobs.Read) and an application role (Jobs.Read.All)." },
  { name: "LAB-Daemon", protocol: "oauth", what: "Client-credentials app already granted Jobs.Read.All on LAB-API. Add your own certificate to request tokens." },
  { name: "LAB-Users group", protocol: "scim", what: "Security group holding the test users." },
  { name: "F360-ScimApp (optional)", protocol: "scim", what: "Enterprise app that provisions lab.user1 to a SCIM app running on your PC. Made by lab/scim/Start-F360ScimLab.ps1, not Terraform, because it needs a secret token." },
] as const;

export const LAB_STEPS: LabStep[] = [
  {
    title: "Create an empty lab tenant",
    minutes: 5,
    why: "A separate tenant means nothing you break can affect real users. Microsoft requires a person to do this step; it can't be scripted.",
    actions: [
      "Sign in at https://entra.microsoft.com with an account in a tenant you already have.",
      "Go to Entra ID > Overview > Manage tenants > Create.",
      "Choose the Workforce type (it may be labelled Microsoft Entra ID or Governed Workforce). Enter an organization name (for example “F360 Lab”), an initial domain name (for example contosolab, giving contosolab.onmicrosoft.com) and your country.",
      "If it asks for a subscription and resource group, pick any subscription you own and create a resource group just for this (for example rg-lab). See the note below for why this is free.",
      "Select Create and complete the human check.",
      "Switch to the new tenant (Settings gear > Directories + subscriptions > Switch). Copy the Tenant ID from Entra ID > Overview.",
      "Create one cloud-only administrator in the new tenant (Users > New user, then Assigned roles > Add assignments > Global Administrator) and store its password safely. This is your emergency way in if the account you created the tenant with is ever lost.",
    ],
    note: "Why a resource group? The Governed Workforce flow stores one item called “Microsoft Entra ID Free” in your existing subscription. It is only a record linking the new tenant to your billing account so you can prove ownership and recover access. It has no cost. No tenant yet? A free Azure account (https://azure.microsoft.com/free) creates one. If Create is unavailable, your organization may block tenant creation; you need the Tenant Creator role.",
  },
  {
    title: "Keep it free",
    minutes: 1,
    why: "An Entra tenant with no Azure subscription and no paid licences has nothing that can bill you.",
    actions: [
      "Do not create an Azure subscription or add a payment method while signed in to the lab tenant.",
      "Do not start licence trials you don't intend to let expire.",
      "If step 1 made a resource group, open it in the Azure portal: it should hold only the Microsoft Entra ID Free item, and Cost analysis should show 0.",
      "Everything this kit builds works on the Entra ID Free tier. HCP Terraform (step 5) and GitHub Actions are used on their free plans.",
    ],
  },
  {
    title: "Get the tools and the kit",
    minutes: 5,
    why: "Everything after this is copy and paste in PowerShell 7. Start from your home folder, not C:\\Windows\\System32, or the script paths will not be found.",
    actions: [
      "Fork the repository on GitHub (or use your own copy). The examples use <you>/federation-360.",
      "Install PowerShell 7, Git and the GitHub CLI, then open a new PowerShell 7 window.",
      "Sign in to GitHub and download your fork.",
    ],
    code: [
      {
        title: "Windows PowerShell (one time)",
        body: `winget install --id Microsoft.PowerShell
winget install --id Git.Git
winget install --id GitHub.cli`,
      },
      {
        title: "PowerShell 7 (new window)",
        body: `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
gh auth login

cd $HOME
gh repo clone <you>/federation-360
cd federation-360`,
      },
    ],
  },
  {
    title: "Run the bootstrap script once",
    minutes: 5,
    why: "It creates the test users and a deploy identity for Terraform. The identity trusts GitHub Actions in your repository through OIDC, so no secret exists anywhere.",
    actions: [
      "Check your administrator exists. The first block lists every Global Administrator in the lab tenant.",
      "Run the script with -WhatIf to preview. It should list two test users and the app f360-lab-deployer, then stop (the later steps need the app to exist).",
      "Run it for real. Sign in as the lab tenant's Global Administrator and, if asked, tick “Consent on behalf of your organization”.",
      "Save the one-time passwords it prints for the test users in a password manager. They are shown once.",
      "The three values printed at the end (LAB_TENANT_ID, LAB_CLIENT_ID, LAB_USER_UPNS) are also saved to lab/lab-values.json for the next scripts. They are not secrets, and the file is not committed to git.",
    ],
    code: [
      {
        title: "Check the Global Administrators",
        body: `Connect-MgGraph -TenantId <lab-tenant-id> -NoWelcome -Scopes RoleManagement.Read.Directory,User.Read.All
(Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles(roleTemplateId='62e90394-69f5-4237-9190-012177145e10')/members").value | ForEach-Object { $_.userPrincipalName }`,
      },
      {
        title: "Preview, then run",
        body: `./lab/bootstrap/New-F360LabBootstrap.ps1 -TenantId <lab-tenant-id> -GitHubRepository <you>/federation-360 -IUnderstandThisIsALabTenant -WhatIf
./lab/bootstrap/New-F360LabBootstrap.ps1 -TenantId <lab-tenant-id> -GitHubRepository <you>/federation-360 -IUnderstandThisIsALabTenant`,
      },
      {
        title: "What success looks like",
        body: `Created app registration f360-lab-deployer
Granted Application.ReadWrite.All
...
Trusted GitHub Actions: repo:<you>@<owner-id>/federation-360@<repo-id>:environment:lab

Done. Use these values:
  LAB_TENANT_ID   = ...
  LAB_CLIENT_ID   = ...
  LAB_USER_UPNS   = ["lab.user1@...","lab.user2@..."]`,
      },
    ],
    note: "The “Trusted GitHub Actions” line is the subject Entra will accept. GitHub names repositories created since July 2026 as owner@id/repo@id, and the script reads those IDs with the GitHub CLI because Entra must match the subject exactly. The deploy identity can change applications, users and groups across the tenant. That is fine in a lab and is the reason never to run this in production.",
  },
  {
    title: "Create a free HCP Terraform account and token",
    minutes: 6,
    why: "Terraform remembers what it built in a state file. GitHub Actions runners are wiped after every run, so the state lives in HCP Terraform's free plan. Signing up and confirming an email need a person; the script in the next step does everything else.",
    actions: [
      "Create a HashiCorp account at https://portal.cloud.hashicorp.com/sign-up and confirm your email from the message HashiCorp sends. If the portal asks you to create an HCP organization, choose Personal.",
      "Open https://app.terraform.io/app/organizations. If it shows “Confirm email address”, use the link in your mailbox (or Resend confirmation link) before continuing.",
      "Select Create organization, choose Personal, and enter a unique name (for example <you>-f360). Do not add a payment method.",
      "You land on “Create a new Workspace”. Leave that page; the script creates the workspace.",
      "Open https://app.terraform.io/app/settings/tokens and select Create an API token. Description: f360-lab-github. Expiration: 30 days. Select Generate token and copy the token. It is shown once.",
    ],
    note: "The token is the only secret in this whole setup; treat it like a password. This kit creates no client secrets, so the state itself holds nothing sensitive. When the token expires the workflow fails at “terraform init”; create a new token and run the step 6 script again.",
  },
  {
    title: "Connect Terraform and GitHub with one script",
    minutes: 2,
    why: "The workflow needs a place for its state and a few settings in your repository. The script reads the lab values the bootstrap saved in lab/lab-values.json, so there is nothing to copy by hand.",
    actions: [
      "Run the script from your repository folder with your HCP Terraform organization name.",
      "When it asks for the HCP Terraform API token, paste it and press Enter. Nothing is shown as you paste, and the token is not written to disk.",
      "Add -WhatIf to preview what it would change.",
    ],
    code: [
      {
        title: "PowerShell 7",
        body: `./lab/Connect-F360LabPipeline.ps1 -TerraformOrganization <your HCP Terraform organization>`,
      },
      {
        title: "What the script does",
        body: `HCP Terraform (through its API, with your token)
  1. Sets the organization's default execution mode to Local
  2. Creates the workspace f360-lab, which stores the state

GitHub (through the GitHub CLI)
  3. Creates the environment "lab"
  4. Sets variables LAB_TENANT_ID, LAB_CLIENT_ID, LAB_USER_UPNS, TF_CLOUD_ORGANIZATION
  5. Stores the token as the secret TF_API_TOKEN`,
      },
      {
        title: "The same thing by hand, if you prefer",
        body: `# In HCP Terraform: Settings > General > Organizational default execution mode > Local > Update organization
# In HCP Terraform: Workspaces > New > Workspace > CLI-Driven Workflow > name it f360-lab > Create
$repo = '<you>/federation-360'
gh api -X PUT repos/$repo/environments/lab
gh variable set LAB_TENANT_ID --repo $repo --body '<lab-tenant-id>'
gh variable set LAB_CLIENT_ID --repo $repo --body '<LAB_CLIENT_ID from step 4>'
'["lab.user1@<domain>.onmicrosoft.com","lab.user2@<domain>.onmicrosoft.com"]' | gh variable set LAB_USER_UPNS --repo $repo
gh variable set TF_CLOUD_ORGANIZATION --repo $repo --body '<your HCP Terraform organization>'
gh secret set TF_API_TOKEN --repo $repo`,
      },
    ],
    note: "Local execution mode is required. In Remote mode the plan runs on HashiCorp's servers, which hold no trust with your tenant, so sign-in fails. Nothing stored in GitHub is an Entra credential: GitHub proves its identity to Entra with a short-lived token on every run. To get an approval step before every apply, open the repository's Settings > Environments > lab and add yourself as a required reviewer.",
  },
  {
    title: "Plan, then build the lab",
    minutes: 6,
    why: "Terraform creates every app the same way each time, and can remove it all again. A plan only previews; apply makes the changes. Every run is recorded under the repository's Actions tab.",
    actions: [
      "Run the plan. It starts the workflow in GitHub Actions, waits, and prints the result. Expect “Plan: 19 to add, 0 to change, 0 to destroy” on a first build.",
      "Run apply. When it finishes it prints the inventory JSON and the OIDC and SAML test links used in the next steps. Add -Open to see the run in your browser.",
    ],
    code: [
      {
        title: "PowerShell 7",
        body: `./lab/Invoke-F360Lab.ps1 -Action plan
./lab/Invoke-F360Lab.ps1 -Action apply`,
      },
      {
        title: "What happens in each run",
        body: `1. GitHub starts a clean Linux runner and checks out your repository
2. GitHub issues the run a short-lived identity token (OIDC)
3. terraform init      connects to the f360-lab workspace and downloads the Entra provider
4. terraform validate  checks the configuration
5. terraform plan      signs in to your tenant as f360-lab-deployer with that token and
                       compares the tenant with lab/terraform
6. terraform apply     (apply only) creates or updates the apps, then saves the new state`,
      },
      {
        title: "The same thing by hand, if you prefer",
        body: `gh workflow run lab.yml --repo $repo -f action=plan
Start-Sleep 8
$run = gh run list --repo $repo --workflow lab.yml --limit 1 --json databaseId --jq '.[0].databaseId'
gh run watch $run --repo $repo --exit-status
gh run view $run --repo $repo --log | Select-String 'Plan:|Error'`,
      },
      {
        title: "Alternative: build from your computer instead of GitHub (skips steps 5 and 6)",
        body: `# Needs Terraform and the Azure CLI. State stays on your machine.
az login --tenant <lab-tenant-id> --allow-no-subscriptions
cd lab/terraform
cp terraform.tfvars.example terraform.tfvars   # then edit the values
terraform init
terraform plan
terraform apply`,
      },
    ],
    note: "If “terraform init” fails with “Invalid workspace selection”, the workspace f360-lab does not exist in your HCP Terraform organization; run the step 6 script again. If it fails with unauthorized, the token is wrong or expired, or the organization name does not match. If sign-in fails with AADSTS700213 or AADSTS70021, the subject GitHub sent does not match the “Trusted GitHub Actions” line from step 4; the error text shows the subject GitHub presented.",
  },
  {
    title: "Import the lab into your inventory",
    minutes: 2,
    why: "The decoders compare real sign-ins against these entries.",
    actions: [
      "Copy the inventory JSON that the apply printed (it is also in the run summary in GitHub Actions). If you built from your computer, run the command below in lab/terraform.",
      "Open Inventory > Back up / import here, paste it, and choose Import.",
    ],
    code: [{ title: "Terminal", body: "terraform output -raw f360_inventory" }],
  },
  {
    title: "Run your first real sign-ins",
    minutes: 10,
    why: "Now you can watch each protocol work, then break it on purpose.",
    actions: [
      "OIDC: open the “OIDC test” link from the apply run summary (the oidc_playground_url output) in a private window and sign in as lab.user1. Copy the token from jwt.ms into the JWT decoder and pick LAB-OIDC-Playground.",
      "SAML: open the “SAML test” link (the saml_test_url output) as lab.user1. Copy the SAML response shown on jwt.ms into the SAML decoder and pick LAB-SAML-App.",
      "Break it: sign in to the SAML app as a user who isn't assigned (AADSTS50105), or edit the redirect URI in the OIDC URL by one character (AADSTS50011). Look each one up in Playbooks.",
      "Check the lab tenant's Sign-in logs after each attempt.",
    ],
    code: [{ title: "Terminal", body: "terraform output oidc_playground_url\nterraform output saml_test_url\nterraform output saml_metadata_url" }],
  },
  {
    title: "Add SCIM provisioning (optional)",
    minutes: 15,
    why: "SSO answers who the user is; SCIM decides whether the app has an account for them. Here Entra provisions a real user into a SCIM app on your own PC, and you read every request it sends. It stays free: Entra ID Free includes automatic user provisioning, the app runs on your computer with Node.js, and Cloudflare's quick tunnel needs no account.",
    actions: [
      "Install Node.js and cloudflared once (below), then open a new PowerShell 7 window.",
      "Run the script. Sign in as your lab Global Administrator and accept the permissions prompt. The first run creates the enterprise app F360-ScimApp and assigns only lab.user1 to it, so lab.user2 shows you what an unprovisioned user looks like.",
      "Watch the window. The script sets the Tenant URL and Secret Token, runs Test connection, then provisions lab.user1 on demand. Each request from Entra prints as one line (GET /Users?filter=..., POST /Users ...).",
      "Open a file in lab/scim/logs, copy its request or response part, and paste it into the SCIM checker. Put lab.user1's UPN in “Identifier the app receives at sign-in” to run the two-gates check.",
      "Break it: stop the script and start it with -Fault 401 (or 404, 409, 500), then use Provision on demand in the Entra admin center (Enterprise apps > F360-ScimApp > Provisioning) and look up the result in Playbooks.",
      "Press Enter in the script window to stop. Nothing keeps running and the tunnel address is gone. Run it again any time; a new address and token are set automatically.",
    ],
    code: [
      {
        title: "PowerShell 7 (one time)",
        body: `winget install --id OpenJS.NodeJS.LTS
winget install --id Cloudflare.cloudflared`,
      },
      {
        title: "PowerShell 7 (each time)",
        body: `cd ${WORKDIR}
git pull origin main
./lab/scim/Start-F360ScimLab.ps1 -TenantId <lab-tenant-id>`,
      },
      {
        title: "Other options",
        body: `./lab/scim/Start-F360ScimLab.ps1 -Fault 401        # every Users call fails with 401
./lab/scim/Start-F360ScimLab.ps1 -StartCycle      # also start the 40-minute cycle (paused when you stop)
./lab/scim/Start-F360ScimLab.ps1 -Reset           # forget the users the app has stored
./lab/scim/Start-F360ScimLab.ps1 -Remove          # delete F360-ScimApp from the tenant`,
      },
    ],
    note: "Entra ID Free limits: users only (group provisioning needs P1), direct assignment only (group assignment needs P1), and no provisioning logs in the admin center (P1). The files in lab/scim/logs replace those logs. Only users assigned to the app with a real role are provisioned (the script uses the role called User; the “Default Access” role is skipped as NotEffectivelyEntitled); unassigning lab.user1 makes the next cycle send PATCH active \"False\", which is how Entra disables a leaver. The bearer token lives only in the script's memory and in Entra; the log files never contain it.",
  },
  {
    title: "Tear down and rebuild",
    minutes: 3,
    why: "Being able to rebuild from nothing is what makes the lab repeatable, and is good recovery practice.",
    actions: [
      "Run destroy and confirm when asked. Everything Terraform created is removed.",
      "The test users and the deploy identity stay, so apply builds it all again.",
      "If you added SCIM, run ./lab/scim/Start-F360ScimLab.ps1 -Remove as well; Terraform does not manage F360-ScimApp.",
      "To remove everything, delete the f360-lab-deployer app registration and the test users, or delete the tenant.",
    ],
    code: [{ title: "PowerShell 7", body: "./lab/Invoke-F360Lab.ps1 -Action destroy\n./lab/Invoke-F360Lab.ps1 -Action apply     # build it all again" }],
  },
];

<#
.SYNOPSIS
  Puts the Federation 360 lab test app on Azure Static Web Apps (Free plan), so the Live test page can use it
  without Docker running the test app on your PC.

.DESCRIPTION
  Cost: $0. The site is created on the Static Web Apps Free plan, which has no paid overage (when its monthly
  quota runs out it stops serving instead of billing), and its API runs as the Free plan's managed functions.
  The script refuses to continue if the site is on any other plan. It never turns on Application Insights.
  Note: the site needs an active Azure subscription to live in. A "Free Trial" subscription is disabled when the
  trial ends unless you upgrade it to pay-as-you-go; upgrading doesn't make the Free plan cost anything.

  Each run:
    1. Runs ../Start-F360TestApp.ps1 -SkipContainers: signs in to the LAB tenant (Microsoft Graph), finds the lab
       apps and writes lab/testapp/.local (settings, plus the LAB-Daemon certificate for client credentials).
    2. Signs in to Azure (Azure CLI) in your MAIN tenant, and creates the resource group and the Static Web App
       on the Free plan if they don't exist yet.
    3. Adds the site's SAML reply URL (https://<site>/api/saml/acs) to LAB-TestApp-SAML in the lab tenant, and saves
       it as the GitHub variable LAB_TESTAPP_CLOUD_ACS so the lab workflow keeps it on every apply.
    4. Copies the lab settings and the LAB-Daemon certificate and key into the site's app settings. Nothing is
       committed to git.
    5. Deploys the site with the Static Web Apps CLI, run inside a node:22 Docker container (no Node needed on
       your PC), and checks that it answers.
    6. Prints the link that opens Federation 360's Live test page pointed at the Azure test app.

  The local Docker test app keeps working as before; switch between the two on the Live test page.

  Needs: PowerShell 7.3+, Microsoft.Graph.Authentication, Azure CLI (az), Docker Desktop running, and GitHub CLI
  (gh) for step 3's variable (skipped with a warning when gh isn't there).

.EXAMPLE
  cd $HOME\federation-360
  ./lab/testapp/azure/Deploy-F360TestAppAzure.ps1 -TenantId <lab-tenant-id>

.EXAMPLE
  # Delete the Static Web App (and its resource group when nothing else is in it).
  ./lab/testapp/azure/Deploy-F360TestAppAzure.ps1 -TenantId <lab-tenant-id> -Remove
#>
#Requires -Version 7.3
#Requires -Modules Microsoft.Graph.Authentication
[CmdletBinding()]
param(
    # LAB tenant ID (where the lab apps live). Not your main tenant.
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    # Azure subscription (main tenant) for the site. Default: the Azure CLI's current subscription.
    [string]$SubscriptionId,

    # Static Web App name.
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}[a-zA-Z0-9]$')]
    [string]$Name = 'f360-testapp',

    [string]$ResourceGroup = 'rg-f360-testapp',

    # Regions that offer Static Web Apps. The pages are served worldwide either way.
    [ValidateSet('eastus2', 'centralus', 'westus2', 'westeurope', 'eastasia')]
    [string]$Location = 'eastus2',

    # Where Federation 360 runs. The test app sends you back here after a SAML sign-in.
    [string]$F360Url = 'http://localhost:5173',

    # GitHub repository that runs the lab workflow, as owner/name. Defaults to this folder's origin remote.
    [string]$Repo,

    # Don't set the GitHub variable LAB_TESTAPP_CLOUD_ACS.
    [switch]$SkipGitHubVariable,

    # Delete the Static Web App instead of deploying it.
    [switch]$Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here     = $PSScriptRoot
$testApp  = Split-Path $here
$repoRoot = Split-Path (Split-Path $testApp)
$localDir = Join-Path $testApp '.local'
$swaCli   = '@azure/static-web-apps-cli@2.0.10'
Set-Location $repoRoot

if (-not $Repo) {
    # owner/name of this folder's GitHub remote, e.g. https://github.com/you/federation-360.git -> you/federation-360
    $origin = (& git remote get-url origin 2>$null)
    if ($origin -match 'github\.com[:/](?<repo>[^/]+/[^/]+?)(\.git)?/?$') { $Repo = $Matches.repo }
    elseif (-not $SkipGitHubVariable) { throw 'Could not read the GitHub repository from git remote origin. Pass -Repo <owner>/<name>, or -SkipGitHubVariable.' }
}

function Invoke-Az {
    # Runs az and returns its JSON output as objects; throws with az's own message when it fails.
    $out = & az @args --only-show-errors -o json 2>&1
    if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed: $($out -join "`n")" }
    $text = ($out | Where-Object { $_ -is [string] }) -join "`n"
    if ($text.Trim()) { $text | ConvertFrom-Json } else { $null }
}

function Get-Prop($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) { return $obj[$name] }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { $p.Value } else { $null }
}

function To-Base64([string]$text) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text)) }

# ---------------------------------------------------------------- tools
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'The Azure CLI is not installed. Install it with: winget install --exact --id Microsoft.AzureCLI   then open a new PowerShell 7 window and run this again.'
}
if (-not $Remove) {
    docker info --format '{{.ServerVersion}}' *> $null
    if ($LASTEXITCODE -ne 0) { throw 'Docker is not running. Start Docker Desktop, wait until it says "Engine running", then run this again.' }
}

# ---------------------------------------------------------------- Azure sign-in (MAIN tenant)
$account = $null
try { $account = Invoke-Az account show } catch { }
if (-not $account) {
    Write-Host 'Signing in to Azure (your main tenant, where the subscription is) ...' -ForegroundColor Cyan
    & az login --only-show-errors -o none
    if ($LASTEXITCODE -ne 0) { throw 'Azure sign-in failed.' }
}
if ($SubscriptionId) { Invoke-Az account set --subscription $SubscriptionId | Out-Null }
$account = Invoke-Az account show
if ($account.state -ne 'Enabled') {
    throw "Subscription '$($account.name)' is $($account.state). A Free Trial is disabled when it ends; upgrade it to pay-as-you-go in the portal (https://portal.azure.com/#view/Microsoft_Azure_Billing/SubscriptionsBladeV2) and run this again. The Free plan still costs nothing."
}
Write-Host "Azure subscription: $($account.name) ($($account.id))" -ForegroundColor Green

# ---------------------------------------------------------------- remove
if ($Remove) {
    $exists = $null
    try { $exists = Invoke-Az staticwebapp show --name $Name --resource-group $ResourceGroup } catch { }
    if ($exists) {
        Invoke-Az staticwebapp delete --name $Name --resource-group $ResourceGroup --yes | Out-Null
        Write-Host "Deleted Static Web App $Name." -ForegroundColor Green
    } else {
        Write-Host "No Static Web App $Name in $ResourceGroup." -ForegroundColor Yellow
    }
    $left = @()
    try { $left = @(Invoke-Az resource list --resource-group $ResourceGroup) } catch { }
    if (-not $left.Count) {
        try { Invoke-Az group delete --name $ResourceGroup --yes | Out-Null; Write-Host "Deleted resource group $ResourceGroup." -ForegroundColor Green } catch { }
    }
    Write-Host 'The reply URL stays on LAB-TestApp-SAML until the next lab apply after you clear the GitHub variable:'
    Write-Host "  gh variable delete LAB_TESTAPP_CLOUD_ACS --repo $Repo"
    return
}

# ---------------------------------------------------------------- 1. lab settings and certificate (LAB tenant)
& (Join-Path $testApp 'Start-F360TestApp.ps1') -TenantId $TenantId -SkipContainers
$configFile = Join-Path $localDir 'config.json'
if (-not (Test-Path $configFile)) { throw "Start-F360TestApp.ps1 did not write $configFile." }
$labConfig = Get-Content $configFile -Raw | ConvertFrom-Json -AsHashtable

# ---------------------------------------------------------------- 2. resource group and Static Web App (Free)
$provider = Invoke-Az provider show --namespace Microsoft.Web
if ($provider.registrationState -ne 'Registered') {
    Write-Host 'Registering the Microsoft.Web resource provider (free, one time) ...' -ForegroundColor Cyan
    Invoke-Az provider register --namespace Microsoft.Web --wait | Out-Null
}
Invoke-Az group create --name $ResourceGroup --location $Location --tags purpose=f360-lab-testapp | Out-Null

$site = $null
try { $site = Invoke-Az staticwebapp show --name $Name --resource-group $ResourceGroup } catch { }
if (-not $site) {
    Write-Host "Creating Static Web App $Name on the Free plan ..." -ForegroundColor Cyan
    $site = Invoke-Az staticwebapp create --name $Name --resource-group $ResourceGroup --location $Location --sku Free --tags purpose=f360-lab-testapp
}
$sku = Get-Prop (Get-Prop $site 'sku') 'name'
if ($sku -ne 'Free') {
    throw "Static Web App $Name is on the '$sku' plan, which can cost money. Nothing was deployed. Switch it to Free (portal > the app > Hosting plan > Free) or delete it with -Remove, then run this again."
}
$hostName  = Get-Prop $site 'defaultHostname'
$publicUrl = "https://$hostName"
$acsUrl    = "$publicUrl/api/saml/acs"
Write-Host "Static Web App: $publicUrl (Free plan)" -ForegroundColor Green

# ---------------------------------------------------------------- 3. reply URL on LAB-TestApp-SAML (LAB tenant, still signed in from step 1)
$ctx = Get-MgContext
if (-not $ctx -or $ctx.TenantId -ne $TenantId) { Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All' -NoWelcome }
$samlApp = (Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq 'LAB-TestApp-SAML'&`$select=id,web").value | Select-Object -First 1
if ($samlApp) {
    $uris = @(Get-Prop (Get-Prop $samlApp 'web') 'redirectUris')
    if ($uris -notcontains $acsUrl) {
        $body = @{ web = @{ redirectUris = @($uris + $acsUrl | Where-Object { $_ }) } } | ConvertTo-Json -Depth 5
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$(Get-Prop $samlApp 'id')" -Body $body -ContentType 'application/json' | Out-Null
        Write-Host "Added reply URL $acsUrl to LAB-TestApp-SAML." -ForegroundColor Green
    } else {
        Write-Host "LAB-TestApp-SAML already has reply URL $acsUrl." -ForegroundColor Green
    }
} else {
    Write-Warning 'LAB-TestApp-SAML was not found, so the SAML test stays off. Run the lab workflow with action "apply", then this script again.'
}

if (-not $SkipGitHubVariable) {
    if (Get-Command gh -ErrorAction SilentlyContinue) {
        & gh variable set LAB_TESTAPP_CLOUD_ACS --body $acsUrl --repo $Repo
        if ($LASTEXITCODE -eq 0) { Write-Host "GitHub variable LAB_TESTAPP_CLOUD_ACS = $acsUrl (the lab workflow keeps the reply URL on every apply)." -ForegroundColor Green }
        else { Write-Warning "Couldn't set the GitHub variable. Set it yourself, or the next lab apply removes the Azure reply URL: gh variable set LAB_TESTAPP_CLOUD_ACS --body $acsUrl --repo $Repo" }
    } else {
        Write-Warning "GitHub CLI (gh) not found. Set this variable, or the next lab apply removes the Azure reply URL: https://github.com/$Repo/settings/variables/actions  name LAB_TESTAPP_CLOUD_ACS  value $acsUrl"
    }
}

# ---------------------------------------------------------------- 4. app settings (lab IDs, plus the LAB-Daemon certificate and key)
$cloudConfig = [ordered]@{
    tenantId  = $labConfig.tenantId
    f360Url   = $F360Url.TrimEnd('/')
    publicUrl = $publicUrl
    labUsers  = @($labConfig.labUsers | Where-Object { $_ })
}
foreach ($k in 'saml', 'liveTest', 'api') { if ($labConfig.ContainsKey($k)) { $cloudConfig[$k] = $labConfig[$k] } }
$keyFile  = Join-Path $localDir 'daemon-key.pem'
$certFile = Join-Path $localDir 'daemon-cert.pem'
$withDaemon = $labConfig.ContainsKey('daemon') -and (Test-Path $keyFile) -and (Test-Path $certFile)
if ($withDaemon) { $cloudConfig.daemon = @{ clientId = $labConfig.daemon.clientId } }

# One setting per call keeps each command line short (az on Windows runs through cmd.exe).
Invoke-Az staticwebapp appsettings set --name $Name --resource-group $ResourceGroup --setting-names "F360_TESTAPP_CONFIG=$(To-Base64 ($cloudConfig | ConvertTo-Json -Depth 5 -Compress))" | Out-Null
if ($withDaemon) {
    Invoke-Az staticwebapp appsettings set --name $Name --resource-group $ResourceGroup --setting-names "F360_DAEMON_KEY=$(To-Base64 (Get-Content $keyFile -Raw))" | Out-Null
    Invoke-Az staticwebapp appsettings set --name $Name --resource-group $ResourceGroup --setting-names "F360_DAEMON_CERT=$(To-Base64 (Get-Content $certFile -Raw))" | Out-Null
    Write-Host 'Copied the lab settings and the LAB-Daemon certificate to the site.' -ForegroundColor Green
} else {
    Write-Host 'Copied the lab settings to the site (no LAB-Daemon certificate, so client credentials stays off).' -ForegroundColor Yellow
}

# ---------------------------------------------------------------- 5. deploy (Static Web Apps CLI in Docker)
Write-Host 'Deploying the site (takes a minute or two) ...' -ForegroundColor Cyan
$token = (Invoke-Az staticwebapp secrets list --name $Name --resource-group $ResourceGroup).properties.apiKey
if (-not $token) { throw "Couldn't read the deployment token for $Name." }
$env:SWA_CLI_DEPLOYMENT_TOKEN = $token
try {
    docker run --rm -e SWA_CLI_DEPLOYMENT_TOKEN -e SWA_CLI_APP_TELEMETRY=false -v "${repoRoot}:/src:ro" -w /tmp node:22 sh -c "node /src/lab/testapp/azure/stage.mjs /tmp/site && npx -y $swaCli deploy /tmp/site/app --api-location /tmp/site/api --api-language node --api-version 22 --env production"
    if ($LASTEXITCODE -ne 0) { throw 'The deployment failed (see the output above).' }
} finally {
    Remove-Item Env:SWA_CLI_DEPLOYMENT_TOKEN -ErrorAction SilentlyContinue
}

$healthy = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $h = Invoke-RestMethod "$publicUrl/api/health" -TimeoutSec 10
        if ($h.ok -and $h.configured) { $healthy = $true; break }
    } catch { }
    Start-Sleep -Seconds 5
}
if (-not $healthy) { throw "The site didn't answer on $publicUrl/api/health within 2.5 minutes. Open that address in a browser; if it still fails, run this script again." }

# ---------------------------------------------------------------- 6. done
$open = "$($F360Url.TrimEnd('/'))/?testapp=$([uri]::EscapeDataString($publicUrl))#livetest"
Write-Host ''
Write-Host 'The test app is running on Azure Static Web Apps (Free plan).' -ForegroundColor Green
Write-Host "  Site:                    $publicUrl"
Write-Host "  SAML test:               $(if ($samlApp -and $labConfig.ContainsKey('saml')) { 'ready' } else { 'off (LAB-TestApp-SAML missing)' })"
Write-Host "  OIDC test:               $(if ($labConfig.ContainsKey('liveTest') -and $labConfig.ContainsKey('api')) { 'ready' } else { 'off (F360-LiveTest or LAB-API missing)' })"
Write-Host "  Client credentials test: $(if ($withDaemon -and $labConfig.ContainsKey('api')) { 'ready' } else { 'off (LAB-Daemon or LAB-API missing)' })"
Write-Host ''
Write-Host 'Federation 360 must be running on your PC (docker compose up -d dev). Then paste this into the address bar:' -ForegroundColor Cyan
Write-Host "  $open"
$labUsers = @($labConfig.labUsers | Where-Object { $_ })
$signInAs = if ($labUsers.Count) { $labUsers[0] } else { 'a lab user' }
Write-Host "When Microsoft asks, sign in as $signInAs (use an InPrivate window)."

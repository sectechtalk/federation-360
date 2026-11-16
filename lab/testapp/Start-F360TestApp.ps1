<#
.SYNOPSIS
  Sets up and starts the Federation 360 lab test app, so the Live test page can run real SAML, OpenID Connect
  and client credentials sign-ins against your lab tenant.

.DESCRIPTION
  Everything here is free: the lab apps are free on Entra ID Free, and the test app runs in Docker on your PC.
  No tunnel is needed, because Entra sends SAML responses and codes back through your browser to localhost.

  Each run:
    1. Signs in to the lab tenant (Microsoft Graph, Application.ReadWrite.All and User.Read.All), lists the
       lab.user* test accounts so the Live test page can show who to sign in as, and finds the lab apps that the
       lab workflow created: LAB-TestApp-SAML, F360-LiveTest, LAB-API and LAB-Daemon.
    2. For the client credentials test, makes a certificate for LAB-Daemon the first time (or when it is close to
       expiring, or with -NewCertificate). The private key is saved in lab/testapp/.local, which git ignores,
       and only the public certificate is uploaded to LAB-Daemon. No client secret is created.
    3. Writes lab/testapp/.local/config.json (IDs only, nothing secret).
    4. Starts the test app container on http://localhost:5174, and Federation 360 on http://localhost:5173
       if it isn't running already.

  Then open http://localhost:5173/#livetest and click a test.

.EXAMPLE
  cd $HOME\federation-360
  ./lab/testapp/Start-F360TestApp.ps1

.EXAMPLE
  # Replace the LAB-Daemon certificate with a new one.
  ./lab/testapp/Start-F360TestApp.ps1 -NewCertificate

.EXAMPLE
  # Point the SAML test at an enterprise app you built by hand (the Learn page's lifecycle walkthrough).
  # Run it again without -SamlApp to go back to LAB-TestApp-SAML.
  ./lab/testapp/Start-F360TestApp.ps1 -SamlApp PRAC-Expenses-SAML

.EXAMPLE
  # Stop the test app container.
  ./lab/testapp/Start-F360TestApp.ps1 -Stop

.EXAMPLE
  # Only refresh the settings and certificate (no Docker). The Azure deploy script runs it this way.
  ./lab/testapp/Start-F360TestApp.ps1 -TenantId <lab tenant ID> -SkipContainers
#>
#Requires -Version 7.3
#Requires -Modules Microsoft.Graph.Authentication
[CmdletBinding()]
param(
    # Lab tenant ID. Read from lab/lab-values.json when omitted.
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    # Make a new LAB-Daemon certificate even if the current one is still good.
    [switch]$NewCertificate,

    # How long a new certificate is valid.
    [ValidateRange(7, 365)]
    [int]$CertificateDays = 90,

    # The SAML enterprise app the SAML test signs in to. Its app registration must have the Identifier
    # (entity ID) set and http://localhost:5174/saml/acs as a Reply URL.
    [ValidateNotNullOrEmpty()]
    [string]$SamlApp = 'LAB-TestApp-SAML',

    # Stop the test app container and exit.
    [switch]$Stop,

    # Write the settings and certificate only; don't start containers. Used by azure/Deploy-F360TestAppAzure.ps1.
    [switch]$SkipContainers
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here      = $PSScriptRoot
$repoRoot  = Split-Path (Split-Path $here)
$localDir  = Join-Path $here '.local'
$keyFile   = Join-Path $localDir 'daemon-key.pem'
$certFile  = Join-Path $localDir 'daemon-cert.pem'
$certName  = 'CN=F360 TestApp Daemon'
$testAppUrl = 'http://localhost:5174'
$f360Url    = 'http://localhost:5173'

Set-Location $repoRoot

function Invoke-Graph {
    param([string]$Uri, [string]$Method = 'GET', $Body)
    $params = @{ Method = $Method; Uri = "https://graph.microsoft.com/v1.0/$Uri"; OutputType = 'PSObject' }
    if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 20); $params.ContentType = 'application/json' }
    Invoke-MgGraphRequest @params
}

function Get-Prop($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) { return $obj[$name] }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { $p.Value } else { $null }
}

function Get-LabApp([string]$name) {
    $select = 'id,appId,displayName,identifierUris,keyCredentials,requiredResourceAccess'
    (Invoke-Graph "applications?`$filter=displayName eq '$name'&`$select=$select").value | Select-Object -First 1
}

function Assert-Docker {
    docker info --format '{{.ServerVersion}}' *> $null
    if ($LASTEXITCODE -ne 0) { throw 'Docker is not running. Start Docker Desktop, wait until it says "Engine running", then run this again.' }
}

# ---------------------------------------------------------------- stop
if ($Stop) {
    Assert-Docker
    docker compose --profile testapp stop testapp
    Write-Host 'Test app stopped.' -ForegroundColor Green
    return
}

if (-not $SkipContainers) { Assert-Docker }

# ---------------------------------------------------------------- tenant
if (-not $TenantId) {
    $valuesFile = Join-Path $repoRoot 'lab/lab-values.json'
    if (Test-Path $valuesFile) { $TenantId = (Get-Content $valuesFile -Raw | ConvertFrom-Json).tenantId }
}
if (-not $TenantId) { throw 'Pass -TenantId <your lab tenant ID> (lab/lab-values.json was not found).' }

# Windows' account broker (WAM) can hide the sign-in window; the browser sign-in is reliable.
try { Set-MgGraphOption -DisableLoginByWAM $true } catch { }
Write-Host "Signing in to lab tenant $TenantId ..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All', 'User.Read.All' -NoWelcome

# ---------------------------------------------------------------- lab users (shown on the Live test page so you know who to sign in as)
$labUsers = @((Invoke-Graph "users?`$filter=startswith(userPrincipalName,'lab.user')&`$select=userPrincipalName").value |
    ForEach-Object { Get-Prop $_ 'userPrincipalName' } | Sort-Object)
if (-not $labUsers.Count) { Write-Warning 'No lab.user* accounts found in the lab tenant. The bootstrap script creates them (lab/bootstrap/New-F360LabBootstrap.ps1).' }

# ---------------------------------------------------------------- lab apps
$saml     = Get-LabApp $SamlApp
$liveTest = Get-LabApp 'F360-LiveTest'
$api      = Get-LabApp 'LAB-API'
$daemon   = Get-LabApp 'LAB-Daemon'

$missing = @(
    if (-not $saml) { $SamlApp }
    if (-not $liveTest) { 'F360-LiveTest' }
    if (-not $api) { 'LAB-API' }
    if (-not $daemon) { 'LAB-Daemon' }
)
if ($missing.Count -eq 4) {
    throw 'None of the lab apps were found. Run the lab workflow first: ./lab/Invoke-F360Lab.ps1 -Action apply'
}
if ($saml -and @(@(Get-Prop $saml 'identifierUris') | Where-Object { $_ }).Count -eq 0) {
    Write-Warning "$SamlApp has no Identifier (Entity ID) yet, so the SAML test stays off. Set it under Single sign-on > Basic SAML Configuration."
    $saml = $null
}
if ($missing.Count) {
    Write-Warning "Not found: $($missing -join ', '). Those tests stay switched off. Run the lab workflow to create them: ./lab/Invoke-F360Lab.ps1 -Action apply"
}
if ($liveTest -and $api) {
    $apiAppId = Get-Prop $api 'appId'
    $hasApi = @(Get-Prop $liveTest 'requiredResourceAccess') | Where-Object { (Get-Prop $_ 'resourceAppId') -eq $apiAppId }
    if (-not $hasApi) {
        Write-Warning 'F360-LiveTest does not have the LAB-API permission yet, so the OIDC test will fail. Run the lab workflow with action "apply" to add it.'
    }
}

# ---------------------------------------------------------------- LAB-Daemon certificate (client credentials)
New-Item -ItemType Directory -Force -Path $localDir | Out-Null
if ($daemon) {
    $current = $null
    if ((Test-Path $keyFile) -and (Test-Path $certFile) -and -not $NewCertificate) {
        $current = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem((Get-Content $certFile -Raw))
        $thumbB64 = [Convert]::ToBase64String($current.GetCertHash())
        $endDay   = $current.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd')
        $uploaded = @(Get-Prop $daemon 'keyCredentials') | Where-Object {
            (Get-Prop $_ 'customKeyIdentifier') -eq $thumbB64 -or
            ((Get-Prop $_ 'displayName') -eq $certName -and ([datetime](Get-Prop $_ 'endDateTime')).ToUniversalTime().ToString('yyyy-MM-dd') -eq $endDay)
        }
        if (-not $uploaded) { Write-Host 'The saved certificate is not on LAB-Daemon any more; making a new one.' -ForegroundColor Yellow; $current = $null }
        elseif ($current.NotAfter -lt (Get-Date).AddDays(7)) { Write-Host "The certificate expires $($current.NotAfter); making a new one." -ForegroundColor Yellow; $current = $null }
    }
    if ($current) {
        Write-Host "Using the LAB-Daemon certificate $($current.Thumbprint) (expires $($current.NotAfter.ToString('yyyy-MM-dd')))." -ForegroundColor Green
    } else {
        Write-Host 'Creating a certificate for LAB-Daemon ...' -ForegroundColor Cyan
        $rsa  = [System.Security.Cryptography.RSA]::Create(2048)
        $req  = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $certName, $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays($CertificateDays))
        Set-Content -Path $keyFile -Value $rsa.ExportPkcs8PrivateKeyPem() -NoNewline
        Set-Content -Path $certFile -Value $cert.ExportCertificatePem() -NoNewline
        # Replaces the certificates on LAB-Daemon (a lab-only app with no other credentials) with this one.
        Invoke-Graph "applications/$(Get-Prop $daemon 'id')" -Method PATCH -Body @{
            keyCredentials = @(@{
                type        = 'AsymmetricX509Cert'
                usage       = 'Verify'
                key         = [Convert]::ToBase64String($cert.RawData)
                displayName = $certName
            })
        } | Out-Null
        Write-Host "Uploaded certificate $($cert.Thumbprint) to LAB-Daemon (valid $CertificateDays days). Entra can take a minute to start accepting it." -ForegroundColor Green
    }
}

# ---------------------------------------------------------------- config
$config = [ordered]@{
    tenantId  = $TenantId
    f360Url   = $f360Url
    publicUrl = $testAppUrl
    labUsers  = $labUsers
}
if ($saml)     { $config.saml     = [ordered]@{ entityId = @(Get-Prop $saml 'identifierUris')[0]; appId = Get-Prop $saml 'appId' } }
if ($liveTest) { $config.liveTest = [ordered]@{ clientId = Get-Prop $liveTest 'appId' } }
if ($api)      { $config.api      = [ordered]@{ clientId = Get-Prop $api 'appId'; scope = 'Jobs.Read'; role = 'Jobs.Read.All' } }
if ($daemon)   { $config.daemon   = [ordered]@{ clientId = Get-Prop $daemon 'appId'; keyFile = 'daemon-key.pem'; certFile = 'daemon-cert.pem' } }
$config | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $localDir 'config.json')

if ($SkipContainers) {
    Write-Host "Lab settings written to $(Join-Path $localDir 'config.json') (containers not started)." -ForegroundColor Green
    return
}

# ---------------------------------------------------------------- containers
Write-Host 'Starting the test app (and Federation 360 if it is not running) ...' -ForegroundColor Cyan
docker compose up -d dev
if ($LASTEXITCODE -ne 0) { throw 'docker compose could not start Federation 360 (service dev).' }
docker compose --profile testapp up -d --force-recreate testapp
if ($LASTEXITCODE -ne 0) { throw 'docker compose could not start the test app.' }

$healthy = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $h = Invoke-RestMethod "$testAppUrl/api/health" -TimeoutSec 2
        if ($h.ok) { $healthy = $true; break }
    } catch { }
    Start-Sleep -Seconds 1
}
if (-not $healthy) { throw "The test app didn't answer on $testAppUrl. See why with: docker compose --profile testapp logs testapp" }

Write-Host ''
Write-Host 'Test app is running.' -ForegroundColor Green
Write-Host "  SAML test:               $(if ($saml) { "ready ($SamlApp)" } else { "off ($SamlApp missing or has no Identifier)" })"
Write-Host "  OIDC test:               $(if ($liveTest -and $api) { 'ready' } else { 'off (F360-LiveTest or LAB-API missing)' })"
Write-Host "  Client credentials test: $(if ($daemon -and $api) { 'ready' } else { 'off (LAB-Daemon or LAB-API missing)' })"
Write-Host ''
$signInAs = if ($labUsers.Count) { $labUsers[0] } else { 'a lab user' }
Write-Host "Open $f360Url/#livetest and, when Microsoft asks, sign in as $signInAs (use an InPrivate window)." -ForegroundColor Cyan
Write-Host 'Lost the password? Reset it at https://entra.microsoft.com > Users > All users > the user > Reset password.'
Write-Host 'Stop it later with: ./lab/testapp/Start-F360TestApp.ps1 -Stop'

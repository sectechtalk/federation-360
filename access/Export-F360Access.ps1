<#
.SYNOPSIS
  Reads how access ends for each enterprise app, read-only. Saves f360-access.json for Federation 360's
  "How access ends" page.

.DESCRIPTION
  Signs you in with the Microsoft Graph PowerShell SDK and asks for three read-only delegated
  permissions: Application.Read.All, Policy.Read.All and Synchronization.Read.All. It only sends GET
  requests.

  It reads:
    - token lifetime policies and which apps they are assigned to
    - Conditional Access policies: which apps they cover and their session controls (sign-in
      frequency, persistent browser, continuous access evaluation). Needs Entra ID P1; on a Free
      tenant this part is skipped with a warning and the page shows Entra's defaults.
    - each enterprise app's provisioning (SCIM) job: schedule, status, last cycle, quarantine

  Federation 360 turns the raw Graph objects into plain words when you load the file. Nothing is
  changed in the tenant. Sign in as Global Reader, Security Reader or higher.

.EXAMPLE
  cd $HOME\Downloads
  ./Export-F360Access.ps1 -TenantId 00000000-0000-0000-0000-000000000000

.EXAMPLE
  # No browser window appeared? Sign in with a device code instead
  ./Export-F360Access.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -UseDeviceCode
#>
#Requires -Version 7.2
[CmdletBinding()]
param(
    # Directory (tenant) ID. Read from lab/lab-values.json in the current folder when omitted.
    [string]$TenantId,

    [string]$OutFile = (Join-Path (Get-Location) 'f360-access.json'),

    # Sign in with a code at https://microsoft.com/devicelogin instead of a browser window.
    [switch]$UseDeviceCode,

    # Keep the Graph sign-in for this PowerShell window afterwards.
    [switch]$StayConnected
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$microsoftTenant = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'

if (-not $TenantId) {
    $valuesPath = Join-Path (Get-Location) 'lab' 'lab-values.json'
    if (Test-Path $valuesPath) { $TenantId = (Get-Content -Raw $valuesPath | ConvertFrom-Json -AsHashtable)['tenantId'] }
}
if ($TenantId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
    throw 'Pass -TenantId with your Directory (tenant) ID (a GUID). Find it in the Entra admin center under Entra ID > Overview.'
}

if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    Write-Host 'Installing the Microsoft.Graph.Authentication module for your user (one time)...' -ForegroundColor Cyan
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.Graph.Authentication
if (Get-Command Set-MgGraphOption -ErrorAction SilentlyContinue) {
    try { Set-MgGraphOption -DisableLoginByWAM $true } catch { Write-Verbose "Could not turn off WAM: $_" }
}

$scopes = @('Application.Read.All', 'Policy.Read.All', 'Synchronization.Read.All')
$connect = @{ TenantId = $TenantId; Scopes = $scopes; NoWelcome = $true; ContextScope = 'Process' }
if ($UseDeviceCode) { $connect['UseDeviceCode'] = $true }

Write-Host "Signing in to tenant $TenantId (read-only: $($scopes -join ', '))..." -ForegroundColor Cyan
if ($UseDeviceCode) { Write-Host 'Open https://microsoft.com/devicelogin and enter the code shown below.' }
else { Write-Host 'A browser tab opens for sign-in. Use Global Reader, Security Reader or Global Administrator.' }
try { Connect-MgGraph @connect }
catch {
    Write-Host "Sign-in didn't finish: $($_.Exception.Message)" -ForegroundColor Yellow
    if (-not $UseDeviceCode) { Write-Host 'Run the same command again with -UseDeviceCode added.' -ForegroundColor Yellow }
    throw
}

function Get-Graph([string]$Uri) {
    Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType Json | ConvertFrom-Json -AsHashtable -Depth 50
}
function Get-GraphAll([string]$Uri) {
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Get-Graph $next
        if ($page['value']) { $items.AddRange([object[]]$page['value']) }
        $next = $page['@odata.nextLink']
    }
    , $items.ToArray()
}

$warnings = [System.Collections.Generic.List[string]]::new()
try {
    # The organisation read needs User.Read, which the scopes above don't include. It only supplies the tenant's
    # name and domain, so a 403 here is skipped and the export carries on.
    $org = @{}
    $domain = ''
    try {
        $org = (Get-Graph 'v1.0/organization?$select=id,displayName,verifiedDomains')['value'][0]
        $domain = ($org['verifiedDomains'] | Where-Object { $_['isDefault'] } | Select-Object -First 1)['name']
    } catch { Write-Verbose "Organisation name not read: $($_.Exception.Message)" }

    Write-Host 'Reading token lifetime policies...'
    $tokenPolicies = $null
    try {
        $tokenPolicies = @(foreach ($p in (Get-GraphAll 'v1.0/policies/tokenLifetimePolicies')) {
                $appliesTo = @()
                try { $appliesTo = @(Get-GraphAll "v1.0/policies/tokenLifetimePolicies/$($p['id'])/appliesTo" | ForEach-Object { $_['id']; if ($_['appId']) { $_['appId'] } }) }
                catch { $warnings.Add("Couldn't read which apps use the token lifetime policy '$($p['displayName'])': $($_.Exception.Message)") }
                [ordered]@{ policy = $p; appliesTo = $appliesTo }
            })
    }
    catch { $warnings.Add("Token lifetime policies couldn't be read: $($_.Exception.Message)") }

    Write-Host 'Reading Conditional Access policies (needs Entra ID P1)...'
    $caPolicies = $null
    $caNote = $null
    try { $caPolicies = @(Get-GraphAll 'v1.0/identity/conditionalAccess/policies') }
    catch { $caNote = "Conditional Access couldn't be read ($($_.Exception.Message)). It needs Entra ID P1 and Policy.Read.All. Entra's defaults are shown instead." }

    Write-Host 'Reading enterprise apps...'
    $sps = @(Get-GraphAll 'v1.0/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,preferredSingleSignOnMode,tags,servicePrincipalType&$top=999' | Where-Object {
            $_['servicePrincipalType'] -eq 'Application' -and "$($_['appOwnerOrganizationId'])" -ne $microsoftTenant -and
            (@($_['tags']) -contains 'WindowsAzureActiveDirectoryIntegratedApp' -or $_['preferredSingleSignOnMode'])
        })
    Write-Host "Reading provisioning jobs for $($sps.Count) apps..."
    $denied = 0
    $apps = @(foreach ($s in $sps) {
            $jobs = @()
            try { $jobs = @(Get-GraphAll "v1.0/servicePrincipals/$($s['id'])/synchronization/jobs") }
            catch {
                $code = 0
                try { $code = [int]$_.Exception.Response.StatusCode } catch { }
                if ($code -eq 403 -or $code -eq 401) { $denied++; $jobs = $null }
            }
            [ordered]@{ spId = $s['id']; appId = $s['appId']; name = $s['displayName']; ssoMode = "$($s['preferredSingleSignOnMode'])"; syncJobs = $jobs }
        })
    if ($denied) { $warnings.Add("Provisioning jobs couldn't be read for $denied apps (403). Make sure Synchronization.Read.All was consented.") }

    $snapshot = [ordered]@{
        format        = 'f360-access'
        version       = 1
        rawGraph      = $true
        collectedAt   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        collector     = 'powershell'
        tenant        = [ordered]@{ id = $(if ($org['id']) { $org['id'] } else { $TenantId }); name = $org['displayName']; domain = $domain }
        tokenPolicies = $tokenPolicies
        caPolicies    = $caPolicies
        caNote        = $caNote
        apps          = $apps
        warnings      = @($warnings)
    }
    $snapshot | ConvertTo-Json -Depth 30 -Compress | Set-Content -Path $OutFile -Encoding utf8NoBOM
    Write-Host ''
    Write-Host "Saved $((Resolve-Path $OutFile).Path)" -ForegroundColor Green
    Write-Host "  $($apps.Count) enterprise apps, $(@($tokenPolicies).Count) token lifetime policies, $(if ($null -eq $caPolicies) { 'Conditional Access not read' } else { "$($caPolicies.Count) Conditional Access policies" })"
    foreach ($w in $warnings) { Write-Warning $w }
    if ($caNote) { Write-Warning $caNote }
    Write-Host 'Next: Federation 360 > How access ends > choose file under "Then load the file it saves", and pick this file.'
}
finally {
    if (-not $StayConnected) { Disconnect-MgGraph | Out-Null }
}

<#
.SYNOPSIS
  Reads everything one person can reach in Entra, read-only, and saves f360-user-access-<name>.json for
  Federation 360's User lookup page.

.DESCRIPTION
  Signs you in with the Microsoft Graph PowerShell SDK and asks for two read-only delegated permissions:
  Directory.Read.All and AuditLog.Read.All. It only sends GET requests.

  It reads, for the one user you name:
    - the account: enabled or disabled, when sessions were last revoked (signInSessionsValidFromDateTime),
      last password change, and last sign-in times (signInActivity, needs Entra ID P1; skipped without it)
    - app assignments made directly and through every group they are in (nested groups included)
    - delegated consent grants (apps they consented to, and admin consent that covers them)
    - devices registered to or owned by them

  Run it again after offboarding to check the result. Sign in as Global Reader, Security Reader or higher.

.EXAMPLE
  cd $HOME\Downloads
  ./Export-F360UserAccess.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -User someone@contoso.com
#>
#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$TenantId,

    # The person's user principal name (sign-in name) or object ID.
    [Parameter(Mandatory)]
    [string]$User,

    [string]$OutFile,
    [switch]$UseDeviceCode,
    [switch]$StayConnected
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $TenantId) {
    $valuesPath = Join-Path (Get-Location) 'lab' 'lab-values.json'
    if (Test-Path $valuesPath) { $TenantId = (Get-Content -Raw $valuesPath | ConvertFrom-Json -AsHashtable)['tenantId'] }
}
if ($TenantId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
    throw 'Pass -TenantId with your Directory (tenant) ID (a GUID). Find it in the Entra admin center under Entra ID > Overview.'
}
if ($User -notmatch '^[^@\s'']+@[^@\s'']+$' -and $User -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
    throw 'Pass -User as a sign-in name (someone@contoso.com) or an object ID.'
}
if (-not $OutFile) { $OutFile = Join-Path (Get-Location) ("f360-user-access-{0}.json" -f ($User -replace '[^A-Za-z0-9._-]', '_')) }

if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    Write-Host 'Installing the Microsoft.Graph.Authentication module for your user (one time)...' -ForegroundColor Cyan
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.Graph.Authentication
if (Get-Command Set-MgGraphOption -ErrorAction SilentlyContinue) {
    try { Set-MgGraphOption -DisableLoginByWAM $true } catch { Write-Verbose "Could not turn off WAM: $_" }
}

$scopes = @('Directory.Read.All', 'AuditLog.Read.All')
$connect = @{ TenantId = $TenantId; Scopes = $scopes; NoWelcome = $true; ContextScope = 'Process' }
if ($UseDeviceCode) { $connect['UseDeviceCode'] = $true }
Write-Host "Signing in to tenant $TenantId (read-only: $($scopes -join ', '))..." -ForegroundColor Cyan
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
    $id = [uri]::EscapeDataString($User)
    $select = 'id,displayName,userPrincipalName,accountEnabled,signInSessionsValidFromDateTime,lastPasswordChangeDateTime'
    try { $u = Get-Graph "v1.0/users/$id`?`$select=$select,signInActivity" }
    catch {
        $warnings.Add('Last sign-in times (signInActivity) need Entra ID P1 and were skipped.')
        $u = Get-Graph "v1.0/users/$id`?`$select=$select"
    }
    Write-Host "Reading $($u['userPrincipalName'])..."

    $assignments = [System.Collections.Generic.List[object]]::new()
    foreach ($a in (Get-GraphAll "v1.0/users/$($u['id'])/appRoleAssignments")) {
        $assignments.Add([ordered]@{ spId = $a['resourceId']; app = $a['resourceDisplayName']; via = 'direct'; roleId = $a['appRoleId']; created = $a['createdDateTime'] })
    }
    $groups = Get-GraphAll "v1.0/users/$($u['id'])/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName&`$top=999"
    Write-Host "Reading app assignments for $($groups.Count) groups..."
    foreach ($g in $groups) {
        foreach ($a in (Get-GraphAll "v1.0/groups/$($g['id'])/appRoleAssignments")) {
            $assignments.Add([ordered]@{ spId = $a['resourceId']; app = $a['resourceDisplayName']; via = 'group'; group = $g['displayName']; roleId = $a['appRoleId']; created = $a['createdDateTime'] })
        }
    }

    $grants = @(Get-GraphAll "v1.0/users/$($u['id'])/oauth2PermissionGrants" | ForEach-Object {
            [ordered]@{ spId = $_['clientId']; app = $_['clientId']; scope = "$($_['scope'])".Trim(); consentType = if ($_['consentType'] -eq 'AllPrincipals') { 'AllPrincipals' } else { 'Principal' } }
        })

    $appIds = [ordered]@{}
    $names = @{}
    foreach ($spId in (@($assignments | ForEach-Object { $_['spId'] }) + @($grants | ForEach-Object { $_['spId'] }) | Select-Object -Unique)) {
        try { $sp = Get-Graph "v1.0/servicePrincipals/$spId`?`$select=id,appId,displayName"; $appIds[$spId] = $sp['appId']; $names[$spId] = $sp['displayName'] } catch { }
    }
    foreach ($g in $grants) { if ($names.ContainsKey($g['spId'])) { $g['app'] = $names[$g['spId']] } }

    $devices = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    foreach ($rel in @('registeredDevices', 'ownedDevices')) {
        try {
            foreach ($d in (Get-GraphAll "v1.0/users/$($u['id'])/$rel`?`$select=id,displayName,operatingSystem,trustType,accountEnabled")) {
                if ($seen.ContainsKey($d['id'])) { continue }
                $seen[$d['id']] = $true
                $devices.Add([ordered]@{ id = $d['id']; name = $d['displayName']; os = "$($d['operatingSystem'])"; trustType = "$($d['trustType'])"; enabled = $d['accountEnabled'] -ne $false })
            }
        }
        catch { $warnings.Add("Devices ($rel) couldn't be read: $($_.Exception.Message)") }
    }

    $signIn = if ($u.ContainsKey('signInActivity')) { $u['signInActivity'] } else { $null }
    $snapshot = [ordered]@{
        format      = 'f360-user-access'
        version     = 1
        collectedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        collector   = 'powershell'
        user        = [ordered]@{
            id                 = $u['id']
            upn                = $u['userPrincipalName']
            name               = $u['displayName']
            enabled            = $u['accountEnabled'] -ne $false
            sessionsValidFrom  = $u['signInSessionsValidFromDateTime']
            lastPasswordChange = $u['lastPasswordChangeDateTime']
            lastSignIn         = if ($signIn) { $signIn['lastSignInDateTime'] } else { $null }
            lastNonInteractive = if ($signIn) { $signIn['lastNonInteractiveSignInDateTime'] } else { $null }
        }
        assignments = @($assignments)
        grants      = $grants
        devices     = @($devices)
        appIds      = $appIds
        warnings    = @($warnings)
    }
    $snapshot | ConvertTo-Json -Depth 20 -Compress | Set-Content -Path $OutFile -Encoding utf8NoBOM
    Write-Host ''
    Write-Host "Saved $((Resolve-Path $OutFile).Path)" -ForegroundColor Green
    Write-Host "  $($assignments.Count) app assignments, $($grants.Count) consent grants, $($devices.Count) devices. Account enabled: $($u['accountEnabled'] -ne $false)"
    foreach ($w in $warnings) { Write-Warning $w }
    Write-Host 'Next: Federation 360 > User lookup > choose file, and pick this file.'
}
finally {
    if (-not $StayConnected) { Disconnect-MgGraph | Out-Null }
}

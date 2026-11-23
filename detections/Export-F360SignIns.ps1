<#
.SYNOPSIS
  Saves Entra sign-in logs (interactive and non-interactive) and the audit events Federation 360's
  Detections page uses, read-only, as one f360-signins.json file.

.DESCRIPTION
  Signs you in with the Microsoft Graph PowerShell SDK and asks for two read-only delegated
  permissions: AuditLog.Read.All and Directory.Read.All. It only sends GET requests.

  Sign-ins come from the Graph beta endpoint because it includes the session ID the stolen-token
  rule needs. Reading sign-in logs through Graph needs Entra ID P1 or higher; on a Free tenant the
  script still saves the audit events and tells you to download sign-ins from the admin center
  (Sign-in logs > Download > Download JSON), which Free tenants can do for the last 7 days.

  Sign in as Reports Reader, Security Reader, Global Reader or higher.

.EXAMPLE
  ./Export-F360SignIns.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -Days 7
#>
#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$TenantId,

    # How many days back to read (Entra keeps 7 days on Free, 30 on P1 and P2).
    [ValidateRange(1, 30)]
    [int]$Days = 7,

    # Stop after this many sign-ins of each kind, so a big tenant doesn't run for hours.
    [int]$MaxSignIns = 50000,

    [string]$OutFile = (Join-Path (Get-Location) 'f360-signins.json'),

    [switch]$UseDeviceCode,

    [switch]$StayConnected
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The audit activities the rules read. Everything else is left out of the file.
$auditActivities = @(
    'User registered security info', 'Admin registered security info', 'User changed default security info',
    'User deleted security info', 'Admin deleted security info', 'Consent to application'
)

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

$scopes = @('AuditLog.Read.All', 'Directory.Read.All')
$connect = @{ TenantId = $TenantId; Scopes = $scopes; NoWelcome = $true; ContextScope = 'Process' }
if ($UseDeviceCode) { $connect['UseDeviceCode'] = $true }
Write-Host "Signing in to tenant $TenantId (read-only: $($scopes -join ', '))..." -ForegroundColor Cyan
try { Connect-MgGraph @connect }
catch {
    Write-Host "Sign-in didn't finish: $($_.Exception.Message)" -ForegroundColor Yellow
    if (-not $UseDeviceCode) { Write-Host 'Run the same command again with -UseDeviceCode added.' -ForegroundColor Yellow }
    throw
}

function Get-GraphAll([string]$Uri, [int]$Max = [int]::MaxValue) {
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next -and $items.Count -lt $Max) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Json | ConvertFrom-Json -AsHashtable -Depth 50
        if ($page['value']) { $items.AddRange([object[]]$page['value']) }
        $next = $page['@odata.nextLink']
        Write-Host "  $($items.Count) so far..."
    }
    , $items.ToArray()
}

$since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
$warnings = [System.Collections.Generic.List[string]]::new()
try {
    $signIns = @()
    try {
        Write-Host "Reading interactive sign-ins since $since..."
        $interactive = Get-GraphAll "beta/auditLogs/signIns?`$filter=createdDateTime ge $since&`$top=1000" $MaxSignIns
        Write-Host 'Reading non-interactive sign-ins (tokens being reused)...'
        $nonInteractive = Get-GraphAll "beta/auditLogs/signIns?`$filter=createdDateTime ge $since and signInEventTypes/any(t: t eq 'nonInteractiveUser')&`$top=1000" $MaxSignIns
        $signIns = @($interactive) + @($nonInteractive)
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'premium|license|Authentication_RequestFromNonPremiumTenantOrB2CTenant') {
            $warnings.Add('Sign-in logs through Graph need Entra ID P1. Download them instead: Entra admin center > Sign-in logs > Download > Download JSON, and load that file next to this one.')
        }
        else { throw }
    }

    Write-Host "Reading audit events since $since..."
    $audits = @(Get-GraphAll "v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $since&`$top=1000" |
            Where-Object { $auditActivities -contains $_['activityDisplayName'] })

    $file = [ordered]@{
        format      = 'f360-signins'
        version     = 1
        collectedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        collector   = 'powershell'
        tenantId    = $TenantId
        days        = $Days
        signIns     = $signIns
        audits      = $audits
        warnings    = @($warnings)
    }
    $file | ConvertTo-Json -Depth 30 -Compress | Set-Content -Path $OutFile -Encoding utf8NoBOM
    Write-Host ''
    Write-Host "Saved $((Resolve-Path $OutFile).Path)" -ForegroundColor Green
    Write-Host "  $($signIns.Count) sign-ins, $($audits.Count) audit events"
    foreach ($w in $warnings) { Write-Warning $w }
    Write-Host 'Next: Federation 360 > Detections > Load one or more JSON files, and pick this file.'
}
finally {
    if (-not $StayConnected) { Disconnect-MgGraph | Out-Null }
}

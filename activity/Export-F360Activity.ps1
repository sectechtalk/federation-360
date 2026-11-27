<#
.SYNOPSIS
  Saves Entra sign-in activity (all four sign-in tabs), provisioning (SCIM) events and the audit events that matter
  when someone leaves, read-only, as one f360-activity.json file for Federation 360's Activity page.

.DESCRIPTION
  Signs you in with the Microsoft Graph PowerShell SDK and asks for two read-only delegated permissions:
  AuditLog.Read.All and Directory.Read.All. It only sends GET requests.

  It reads, for the last -Days days:
    - interactive user sign-ins
    - non-interactive user sign-ins (silent token refreshes; this is how Federation 360 measures how often each app
      goes back to Entra)
    - service principal and managed identity sign-ins
    - provisioning logs (every SCIM create, update and disable)
    - audit events: account disabled or enabled, sessions revoked, password reset, app assignment removed, consent

  Sign-in and provisioning logs through Graph need Entra ID P1 or higher. On a Free tenant the script still saves the
  audit events and tells you to download each sign-in tab from the admin center (Sign-in logs > Download >
  Download JSON), which Free tenants can do for the last 7 days; drop those files on the Activity page too.
  Sign in as Reports Reader, Security Reader, Global Reader or higher.

.EXAMPLE
  cd $HOME\Downloads
  ./Export-F360Activity.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -Days 7

.EXAMPLE
  # Only one person, faster on a big tenant
  ./Export-F360Activity.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -User someone@contoso.com
#>
#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$TenantId,

    # How many days back to read (Entra keeps 7 days on Free, 30 on P1 and P2).
    [ValidateRange(1, 30)]
    [int]$Days = 7,

    # Read only this person's sign-ins and audit events (their UPN). Provisioning is read for everyone.
    [string]$User,

    # Stop after this many rows of each kind.
    [int]$MaxRows = 50000,

    [string]$OutFile = (Join-Path (Get-Location) 'f360-activity.json'),
    [switch]$UseDeviceCode,
    [switch]$StayConnected
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$auditActivities = @(
    'Disable account', 'Enable account', 'Update user', 'Revoke sign-in sessions', 'Invalidate all refresh tokens for user',
    'Reset user password', 'Change user password', 'Remove app role assignment from user', 'Consent to application'
)

if (-not $TenantId) {
    $valuesPath = Join-Path (Get-Location) 'lab' 'lab-values.json'
    if (Test-Path $valuesPath) { $TenantId = (Get-Content -Raw $valuesPath | ConvertFrom-Json -AsHashtable)['tenantId'] }
}
if ($TenantId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
    throw 'Pass -TenantId with your Directory (tenant) ID (a GUID). Find it in the Entra admin center under Entra ID > Overview.'
}
if ($User -and $User -notmatch '^[^@\s'']+@[^@\s'']+$') { throw 'Pass -User as a user principal name, for example someone@contoso.com.' }

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
if ($UseDeviceCode) { Write-Host 'Open https://microsoft.com/devicelogin and enter the code shown below.' }
else { Write-Host 'A browser tab opens for sign-in. Use Reports Reader, Security Reader, Global Reader or higher.' }
try { Connect-MgGraph @connect }
catch {
    Write-Host "Sign-in didn't finish: $($_.Exception.Message)" -ForegroundColor Yellow
    if (-not $UseDeviceCode) { Write-Host 'Run the same command again with -UseDeviceCode added.' -ForegroundColor Yellow }
    throw
}

function Get-Graph([string]$Uri) {
    Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType Json | ConvertFrom-Json -AsHashtable -Depth 50
}
function Get-GraphAll([string]$Uri, [string]$What) {
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next -and $items.Count -lt $MaxRows) {
        $page = Get-Graph $next
        if ($page['value']) { $items.AddRange([object[]]$page['value']) }
        $next = $page['@odata.nextLink']
        Write-Progress -Activity "Reading $What" -Status "$($items.Count) so far"
    }
    Write-Progress -Activity "Reading $What" -Completed
    if ($next) { $script:warnings.Add("Stopped at $MaxRows $What. Use -Days or -User to read less, or -MaxRows to read more.") }
    , $items.ToArray()
}

$script:warnings = [System.Collections.Generic.List[string]]::new()
$since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
$userFilter = if ($User) { " and userPrincipalName eq '$User'" } else { '' }
$result = [ordered]@{
    format = 'f360-activity-export'; version = 1; collector = 'powershell'
    collectedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); days = $Days
    signIns = @(); nonInteractive = @(); servicePrincipal = @(); managedIdentity = @(); provisioning = @(); audits = @()
}
try {
    $licensed = $true
    foreach ($pair in @(@('signIns', 'interactiveUser'), @('nonInteractive', 'nonInteractiveUser'), @('servicePrincipal', 'servicePrincipal'), @('managedIdentity', 'managedIdentity'))) {
        if (-not $licensed) { break }
        if ($User -and $pair[1] -in @('servicePrincipal', 'managedIdentity')) { continue }
        $filter = [uri]::EscapeDataString("createdDateTime ge $since and signInEventTypes/any(t: t eq '$($pair[1])')$userFilter")
        Write-Host "Reading $($pair[1]) sign-ins..."
        try { $result[$pair[0]] = Get-GraphAll "beta/auditLogs/signIns?`$filter=$filter&`$top=999" "$($pair[1]) sign-ins" }
        catch {
            if ("$($_.Exception.Message)" -match '403|Forbidden|license|premium') {
                $licensed = $false
                $script:warnings.Add('Sign-in logs need Entra ID P1 to read through Graph. In the Entra admin center open Sign-in logs, pick each tab, then Download > Download JSON, and drop those files on the Activity page.')
            }
            else { $script:warnings.Add("$($pair[1]) sign-ins couldn't be read: $($_.Exception.Message)") }
        }
    }

    Write-Host 'Reading provisioning logs...'
    try { $result['provisioning'] = Get-GraphAll "v1.0/auditLogs/provisioning?`$filter=$([uri]::EscapeDataString("activityDateTime ge $since"))&`$top=999" 'provisioning events' }
    catch { $script:warnings.Add("Provisioning logs couldn't be read (they need Entra ID P1): $($_.Exception.Message)") }

    Write-Host 'Reading audit events...'
    $acts = ($auditActivities | ForEach-Object { "activityDisplayName eq '$_'" }) -join ' or '
    $auditFilter = "activityDateTime ge $since and ($acts)"
    if ($User) { $auditFilter += " and targetResources/any(t: t/userPrincipalName eq '$User')" }
    try { $result['audits'] = Get-GraphAll "v1.0/auditLogs/directoryAudits?`$filter=$([uri]::EscapeDataString($auditFilter))&`$top=999" 'audit events' }
    catch { $script:warnings.Add("Audit events couldn't be read: $($_.Exception.Message)") }

    $result['warnings'] = @($script:warnings)
    $result | ConvertTo-Json -Depth 30 -Compress | Set-Content -Path $OutFile -Encoding utf8NoBOM
    Write-Host ''
    Write-Host "Saved $((Resolve-Path $OutFile).Path)" -ForegroundColor Green
    Write-Host "  $(@($result['signIns']).Count) interactive, $(@($result['nonInteractive']).Count) non-interactive, $(@($result['servicePrincipal']).Count) service principal, $(@($result['managedIdentity']).Count) managed identity sign-ins"
    Write-Host "  $(@($result['provisioning']).Count) provisioning events, $(@($result['audits']).Count) audit events"
    foreach ($w in $script:warnings) { Write-Warning $w }
    Write-Host 'Next: Federation 360 > Activity > choose files, and pick this file.'
}
finally {
    if (-not $StayConnected) { Disconnect-MgGraph | Out-Null }
}

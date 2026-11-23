<#
.SYNOPSIS
  Reads how far an Entra tenant is from phishing-resistant MFA, and which enterprise apps require
  assignment, read-only. Saves f360-posture.json for Federation 360's "MFA and SSO coverage" page.

.DESCRIPTION
  Signs you in with the Microsoft Graph PowerShell SDK and asks for four read-only delegated
  permissions: Application.Read.All, Directory.Read.All, UserAuthenticationMethod.Read.All and
  Policy.Read.All. It only sends GET requests (method lists go through Graph $batch, which is a POST
  carrying GETs).

  It reads:
    - security defaults (on or off)
    - the authentication methods policy (which methods are on, and for whom)
    - directory roles and their members (to find admins)
    - every user and the TYPES of sign-in method each has registered (for example fido2, phone).
      Phone numbers, device names and keys are dropped before the file is written.
    - enterprise apps: single sign-on mode and whether assignment is required

  Works on Entra ID Free. Sign in as Global Reader, Authentication Administrator or Global Administrator.

.EXAMPLE
  cd $HOME\Downloads
  ./Export-F360Posture.ps1 -TenantId 00000000-0000-0000-0000-000000000000

.EXAMPLE
  # No browser window appeared? Sign in with a device code instead
  ./Export-F360Posture.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -UseDeviceCode
#>
#Requires -Version 7.2
[CmdletBinding()]
param(
    # Directory (tenant) ID. Read from lab/lab-values.json in the current folder when omitted.
    [string]$TenantId,

    [string]$OutFile = (Join-Path (Get-Location) 'f360-posture.json'),

    # Sign in with a code at https://microsoft.com/devicelogin instead of a browser window.
    [switch]$UseDeviceCode,

    # Keep the Graph sign-in for this PowerShell window afterwards.
    [switch]$StayConnected
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$microsoftTenant = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
$methodIds = @('Fido2', 'MicrosoftAuthenticator', 'Sms', 'Voice', 'SoftwareOath', 'HardwareOath', 'TemporaryAccessPass', 'Email', 'X509Certificate')

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
# WAM's sign-in window often opens hidden behind the terminal; a browser tab is more reliable.
if (Get-Command Set-MgGraphOption -ErrorAction SilentlyContinue) {
    try { Set-MgGraphOption -DisableLoginByWAM $true } catch { Write-Verbose "Could not turn off WAM: $_" }
}

$scopes = @('Application.Read.All', 'Directory.Read.All', 'UserAuthenticationMethod.Read.All', 'Policy.Read.All')
$connect = @{ TenantId = $TenantId; Scopes = $scopes; NoWelcome = $true; ContextScope = 'Process' }
if ($UseDeviceCode) { $connect['UseDeviceCode'] = $true }

Write-Host "Signing in to tenant $TenantId (read-only: $($scopes -join ', '))..." -ForegroundColor Cyan
if ($UseDeviceCode) { Write-Host 'Open https://microsoft.com/devicelogin and enter the code shown below.' }
else { Write-Host 'A browser tab opens for sign-in. Use Global Reader, Authentication Administrator or Global Administrator.' }
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
# GETs through $batch, 20 per request. One result per URL; $null and a warning when a call failed.
function Invoke-GraphBatch([string[]]$Urls) {
    $results = [object[]]::new($Urls.Count)
    for ($i = 0; $i -lt $Urls.Count; $i += 20) {
        $chunk = $Urls[$i..([Math]::Min($i + 19, $Urls.Count - 1))]
        $requests = for ($k = 0; $k -lt $chunk.Count; $k++) { @{ id = "$k"; method = 'GET'; url = $chunk[$k] } }
        $body = @{ requests = @($requests) } | ConvertTo-Json -Depth 5
        $resp = Invoke-MgGraphRequest -Method POST -Uri 'v1.0/$batch' -Body $body -ContentType 'application/json' -OutputType Json |
            ConvertFrom-Json -AsHashtable -Depth 50
        foreach ($r in $resp['responses']) {
            if ($r['status'] -eq 200) { $results[$i + [int]$r['id']] = , $r['body']['value'] }
            elseif ($r['status'] -eq 429) { $script:throttled++ }
            else { $script:denied++ }
        }
    }
    , $results
}

$warnings = [System.Collections.Generic.List[string]]::new()
$script:denied = 0
$script:throttled = 0
try {
    $org = (Get-Graph 'v1.0/organization?$select=id,displayName,verifiedDomains')['value'][0]
    $domain = ($org['verifiedDomains'] | Where-Object { $_['isDefault'] } | Select-Object -First 1)['name']

    Write-Host 'Reading security defaults and the authentication methods policy...'
    $securityDefaults = $null
    try { $securityDefaults = [bool](Get-Graph 'v1.0/policies/identitySecurityDefaultsEnforcementPolicy')['isEnabled'] }
    catch { $warnings.Add("Security defaults couldn't be read: $($_.Exception.Message)") }

    $methodsPolicy = $null
    try {
        $policy = Get-Graph 'v1.0/policies/authenticationMethodsPolicy'
        $configs = @($policy['authenticationMethodConfigurations'])
        if (-not $policy['authenticationMethodConfigurations']) {
            $configs = foreach ($id in $methodIds) {
                try { Get-Graph "v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$id" } catch { }
            }
        }
        $methodsPolicy = @($configs | Where-Object { $_ } | ForEach-Object {
                [ordered]@{
                    id      = $_['id']
                    state   = if ($_['state'] -eq 'enabled') { 'enabled' } else { 'disabled' }
                    targets = @($_['includeTargets'] | Where-Object { $_ } | ForEach-Object { "$($_['id'])" })
                }
            })
    }
    catch { $warnings.Add("The authentication methods policy couldn't be read: $($_.Exception.Message)") }

    Write-Host 'Reading admin roles...'
    $roles = @{}
    foreach ($r in (Get-GraphAll 'v1.0/directoryRoles?$select=id,displayName&$expand=members($select=id)')) {
        foreach ($m in @($r['members'])) {
            if (-not $m) { continue }
            if (-not $roles.ContainsKey($m['id'])) { $roles[$m['id']] = [System.Collections.Generic.List[string]]::new() }
            $roles[$m['id']].Add($r['displayName'])
        }
    }

    Write-Host 'Reading users...'
    $rawUsers = Get-GraphAll 'v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,userType&$top=999'
    Write-Host "Reading sign-in method types for $($rawUsers.Count) users (names of method types only)..."
    $methodLists = Invoke-GraphBatch @($rawUsers | ForEach-Object { "/users/$($_['id'])/authentication/methods" })
    $users = for ($i = 0; $i -lt $rawUsers.Count; $i++) {
        $u = $rawUsers[$i]
        $types = @($methodLists[$i] | Where-Object { $_ } | ForEach-Object { ($_['@odata.type'] -replace '^#?microsoft\.graph\.', '') -replace 'AuthenticationMethod$', '' } | Select-Object -Unique)
        [ordered]@{
            id      = $u['id']
            upn     = $u['userPrincipalName']
            name    = $u['displayName']
            enabled = $u['accountEnabled'] -ne $false
            guest   = $u['userType'] -eq 'Guest'
            roles   = @(if ($roles.ContainsKey($u['id'])) { $roles[$u['id']] })
            methods = $types
        }
    }
    if ($script:throttled) { $warnings.Add("Graph throttled $($script:throttled) method reads, so those users show no methods. Run the script again in a few minutes.") }
    if ($script:denied) { $warnings.Add("$($script:denied) users' sign-in methods couldn't be read. Sign in with Authentication Administrator, Global Reader or higher.") }

    Write-Host 'Reading enterprise apps...'
    $sps = Get-GraphAll 'v1.0/servicePrincipals?$select=id,appId,displayName,accountEnabled,appOwnerOrganizationId,preferredSingleSignOnMode,appRoleAssignmentRequired,tags,servicePrincipalType&$top=999'
    $apps = @($sps | Where-Object {
            $_['servicePrincipalType'] -eq 'Application' -and @($_['tags']) -contains 'WindowsAzureActiveDirectoryIntegratedApp' -and "$($_['appOwnerOrganizationId'])" -ne $microsoftTenant
        } | ForEach-Object {
            [ordered]@{
                appId              = $_['appId']
                spId               = $_['id']
                name               = $_['displayName']
                ssoMode            = "$($_['preferredSingleSignOnMode'])"
                assignmentRequired = [bool]$_['appRoleAssignmentRequired']
                thirdParty         = [bool]$_['appOwnerOrganizationId'] -and "$($_['appOwnerOrganizationId'])" -ne $org['id']
                enabled            = $_['accountEnabled'] -ne $false
            }
        })

    $snapshot = [ordered]@{
        format           = 'f360-posture'
        version          = 1
        collectedAt      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        collector        = 'powershell'
        tenant           = [ordered]@{ id = $org['id']; name = $org['displayName']; domain = $domain }
        securityDefaults = $securityDefaults
        methodsPolicy    = $methodsPolicy
        users            = @($users)
        apps             = $apps
        warnings         = @($warnings)
    }
    $snapshot | ConvertTo-Json -Depth 20 -Compress | Set-Content -Path $OutFile -Encoding utf8NoBOM
    Write-Host ''
    Write-Host "Saved $((Resolve-Path $OutFile).Path)" -ForegroundColor Green
    Write-Host "  $(@($users).Count) users, $($apps.Count) enterprise apps"
    foreach ($w in $warnings) { Write-Warning $w }
    Write-Host 'Next: Federation 360 > MFA and SSO coverage > Load posture file, and pick this file.'
}
finally {
    if (-not $StayConnected) { Disconnect-MgGraph | Out-Null }
}

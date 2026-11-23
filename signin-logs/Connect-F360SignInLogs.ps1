<#
.SYNOPSIS
    One-time setup so Federation 360's Flow tracer can show Entra's verdict (the sign-in log entry) beside each sign-in.

.DESCRIPTION
    Read-only for the sign-in logs. In the tenant you name, this script:
      1. Checks the tenant has Entra ID P1 or higher. Microsoft serves sign-in logs to apps only then. On Entra ID Free
         it stops, changes nothing, and tells Federation 360 so it can point you to the Entra admin center instead.
      2. Creates (or updates) a single-page-app registration named "Federation 360 sign-in logs" with redirect URIs for
         Federation 360 on this PC, and the delegated Microsoft Graph permissions AuditLog.Read.All,
         Directory.Read.All and Policy.Read.ConditionalAccess. It has no secret or certificate.
      3. Grants admin consent for those permissions, for the whole tenant. Delegated means the app can only ever read
         what the signed-in person's own role allows.
      4. Opens Federation 360's Flow tracer, connected to this tenant.

    Run it as a Global Administrator or Privileged Role Administrator (activate the role in Privileged Identity
    Management first if it's eligible). Needs PowerShell 7 and the Microsoft.Graph.Authentication module.

    People who read sign-in logs in Flow tracer also need a role that can read them. Security Reader shows everything,
    including Conditional Access policy names. Reports Reader shows everything except the policy names.

    Run it again any time; it only changes what's missing. -Remove deletes the app registration.

.EXAMPLE
    ./signin-logs/Connect-F360SignInLogs.ps1 -TenantId contoso.onmicrosoft.com
#>
[CmdletBinding()]
param(
    # Tenant ID or a verified domain of the tenant whose sign-in logs Flow tracer should read.
    [Parameter(Mandatory)]
    [string]$TenantId,

    # Where Federation 360 runs. Each address is added as a redirect URI; the first one is opened at the end.
    [string[]]$Address = @('http://localhost:5173/', 'http://localhost:8080/'),

    # Delete the app registration instead.
    [switch]$Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AppName = 'Federation 360 sign-in logs'
$GraphAppId = '00000003-0000-0000-c000-000000000000'
$Scopes = @('AuditLog.Read.All', 'Directory.Read.All', 'Policy.Read.ConditionalAccess', 'User.Read', 'openid', 'profile', 'offline_access')

if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    throw 'The Microsoft Graph PowerShell module is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser   then run this script again.'
}

function Invoke-Graph {
    param([string]$Uri, [string]$Method = 'GET', $Body)
    $params = @{ Method = $Method; Uri = "https://graph.microsoft.com/v1.0/$Uri"; OutputType = 'PSObject' }
    if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 20); $params.ContentType = 'application/json' }
    Invoke-MgGraphRequest @params
}

function Open-FlowTracer([string]$suffix) {
    $url = $Address[0].TrimEnd('/') + '/#flowtracer&f360logs=' + $suffix
    Write-Host "Opening $url" -ForegroundColor Cyan
    try { Start-Process $url } catch { Write-Host "Open this address in your browser: $url" }
}

# Windows' account broker (WAM) can hide the sign-in window; the browser sign-in is reliable.
try { Set-MgGraphOption -DisableLoginByWAM $true } catch { }
Write-Host "Signing in to tenant $TenantId ..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All', 'Organization.Read.All' -NoWelcome
$tid = (Get-MgContext).TenantId
$org = (Invoke-Graph 'organization?$select=displayName').value | Select-Object -First 1
$orgName = if ($org) { $org.displayName } else { $tid }
Write-Host "Connected to $orgName ($tid)." -ForegroundColor Green

$existing = (Invoke-Graph "applications?`$filter=displayName eq '$AppName'&`$select=id,appId,spa,requiredResourceAccess").value | Select-Object -First 1

if ($Remove) {
    if ($existing) {
        Invoke-Graph "applications/$($existing.id)" -Method DELETE | Out-Null
        Write-Host "Deleted the app registration '$AppName'. Flow tracer can no longer read sign-in logs in $orgName." -ForegroundColor Green
    } else { Write-Host "No app registration named '$AppName' in $orgName. Nothing to delete." }
    return
}

# ---------------------------------------------------------------- 1. license
$premium = @((Invoke-Graph 'subscribedSkus?$select=skuPartNumber,capabilityStatus,servicePlans').value | Where-Object {
    $_.capabilityStatus -eq 'Enabled' -and @($_.servicePlans | Where-Object { $_.servicePlanName -match '^AAD_PREMIUM' -and $_.provisioningStatus -ne 'Disabled' }).Count
})
if (-not $premium.Count) {
    Write-Host ''
    Write-Host "$orgName is on Entra ID Free. Microsoft serves sign-in logs to apps only on Entra ID P1 or higher, so there's nothing for Flow tracer to read here." -ForegroundColor Yellow
    Write-Host 'Nothing was changed. Flow tracer will show where to find each sign-in in the Entra admin center instead.' -ForegroundColor Yellow
    Open-FlowTracer "$tid.free.$([uri]::EscapeDataString($orgName))"
    return
}
Write-Host "License OK: $(@($premium.skuPartNumber) -join ', ')." -ForegroundColor Green

# ---------------------------------------------------------------- 2. app registration
$graphSp = (Invoke-Graph "servicePrincipals?`$filter=appId eq '$GraphAppId'&`$select=id,oauth2PermissionScopes").value | Select-Object -First 1
$access = foreach ($s in $Scopes) {
    $scope = $graphSp.oauth2PermissionScopes | Where-Object value -eq $s | Select-Object -First 1
    if (-not $scope) { throw "Microsoft Graph has no delegated permission named $s in this tenant." }
    @{ id = $scope.id; type = 'Scope' }
}
$redirects = @($Address | ForEach-Object { if ($_ -match '/$') { $_ } else { "$_/" } })

if ($existing) {
    $have = @($existing.spa.redirectUris)
    $body = @{
        spa                    = @{ redirectUris = @(($have + $redirects) | Select-Object -Unique) }
        requiredResourceAccess = @(@{ resourceAppId = $GraphAppId; resourceAccess = @($access) })
    }
    Invoke-Graph "applications/$($existing.id)" -Method PATCH -Body $body | Out-Null
    $app = $existing
    Write-Host "Updated the app registration '$AppName' ($($app.appId))." -ForegroundColor Green
} else {
    $app = Invoke-Graph 'applications' -Method POST -Body @{
        displayName            = $AppName
        description            = 'Federation 360 Flow tracer: reads sign-in logs (delegated, read-only) to explain sign-ins. Created by Connect-F360SignInLogs.ps1.'
        signInAudience         = 'AzureADMyOrg'
        spa                    = @{ redirectUris = $redirects }
        requiredResourceAccess = @(@{ resourceAppId = $GraphAppId; resourceAccess = @($access) })
    }
    Write-Host "Created the app registration '$AppName' ($($app.appId))." -ForegroundColor Green
}

# ---------------------------------------------------------------- 3. admin consent
$sp = $null
for ($i = 0; $i -lt 10 -and -not $sp; $i++) {
    $sp = (Invoke-Graph "servicePrincipals?`$filter=appId eq '$($app.appId)'&`$select=id").value | Select-Object -First 1
    if (-not $sp) {
        try { $sp = Invoke-Graph 'servicePrincipals' -Method POST -Body @{ appId = $app.appId } } catch { Start-Sleep -Seconds 3 }
    }
}
if (-not $sp) { throw 'The app registration was created but its enterprise app did not appear. Wait a minute and run this script again.' }

$scopeText = $Scopes -join ' '
$grant = (Invoke-Graph "oauth2PermissionGrants?`$filter=clientId eq '$($sp.id)' and resourceId eq '$($graphSp.id)' and consentType eq 'AllPrincipals'").value | Select-Object -First 1
if ($grant) {
    Invoke-Graph "oauth2PermissionGrants/$($grant.id)" -Method PATCH -Body @{ scope = $scopeText } | Out-Null
} else {
    Invoke-Graph 'oauth2PermissionGrants' -Method POST -Body @{ clientId = $sp.id; consentType = 'AllPrincipals'; resourceId = $graphSp.id; scope = $scopeText } | Out-Null
}
Write-Host "Admin consent granted: $($Scopes[0..2] -join ', ') (delegated, read-only)." -ForegroundColor Green

# ---------------------------------------------------------------- 4. done
Write-Host ''
Write-Host 'Done. Anyone who reads sign-in logs in Flow tracer needs the Security Reader role (or Reports Reader, without policy names).' -ForegroundColor Green
Open-FlowTracer "$tid.$($app.appId).$([uri]::EscapeDataString($orgName))"

<#
.SYNOPSIS
  Starts the Federation 360 lab SCIM app, opens a free public tunnel to it, and points
  Microsoft Entra provisioning at it. Stops everything when you press Enter.

.DESCRIPTION
  Everything here is free: Entra ID Free includes automatic user provisioning, the SCIM app runs on
  your own PC with Node.js, and Cloudflare's quick tunnel needs no account.

  Each run:
    1. Makes a new random secret token. It stays in this PowerShell session and in Entra; it is never
       written to disk or printed.
    2. Starts lab/scim/server.mjs on http://127.0.0.1:8787 and a Cloudflare quick tunnel to it
       (a new https://<random>.trycloudflare.com address every run).
    3. Signs in to the lab tenant and, the first time, creates the enterprise app "F360-ScimApp"
       from the non-gallery template and assigns ONE test user to it (lab.user1 by default).
       The other test users stay unassigned, so you can see what "not provisioned" looks like.
    4. Creates the provisioning job if needed, saves the tunnel address and token as the
       Tenant URL and Secret Token, and runs "Test connection".
    5. Provisions the assigned user on demand, so you don't wait for the 40-minute cycle.
    6. Waits. Every request Entra sends is shown here and saved in lab/scim/logs.
       Press Enter to stop the app and the tunnel.

  Why isn't this in Terraform? The provisioning job needs a secret token and a tunnel address that
  changes every run. Keeping them out of Terraform keeps the state file free of secrets.

.EXAMPLE
  cd $HOME\federation-360
  ./lab/scim/Start-F360ScimLab.ps1

.EXAMPLE
  # Make every Users/Groups call fail with 401 and watch how Entra reacts.
  ./lab/scim/Start-F360ScimLab.ps1 -Fault 401

.EXAMPLE
  # Remove the SCIM enterprise app from the lab tenant.
  ./lab/scim/Start-F360ScimLab.ps1 -Remove
#>
#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication
[CmdletBinding(SupportsShouldProcess)]
param(
    # Lab tenant ID. Read from lab/lab-values.json when omitted.
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    # User to assign and provision. Defaults to lab.user1@<the tenant's onmicrosoft.com domain>.
    [string]$AssignUpn,

    [ValidateRange(1024, 65535)]
    [int]$Port = 8787,

    # Make the SCIM app answer every Users/Groups call with this HTTP status (401, 403, 404, 409, 429, 500 ...).
    [ValidateRange(400, 599)]
    [int]$Fault,

    # Start the scheduled provisioning cycle (every ~40 minutes) as well. It is paused again when you stop.
    [switch]$StartCycle,

    # Skip the on-demand provisioning step.
    [switch]$NoOnDemand,

    # Forget every user and group the SCIM app has stored.
    [switch]$Reset,

    # Delete the F360-ScimApp enterprise app from the lab tenant and exit.
    [switch]$Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$appName        = 'F360-ScimApp'
$customTemplate = '8adf8e6e-67b2-4cf2-a259-e3dc5476c621'   # "Non-gallery application" template
$here           = $PSScriptRoot
$repoRoot       = Split-Path (Split-Path $here)
$logDir         = Join-Path $here 'logs'

function Invoke-Graph {
    param([string]$Uri, [string]$Method = 'GET', $Body)
    $params = @{ Method = $Method; Uri = "https://graph.microsoft.com/beta/$Uri"; OutputType = 'PSObject' }
    if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 20); $params.ContentType = 'application/json' }
    Invoke-MgGraphRequest @params
}

function Get-Prop($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) { return $obj[$name] }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { $p.Value } else { $null }
}

# New apps take a few seconds (sometimes a minute) to become readable everywhere in Entra.
function Find-ScimServicePrincipal([string]$appId) {
    $filter = if ($appId) { "appId eq '$appId'" } else { "displayName eq '$appName'" }
    for ($i = 0; $i -lt 24; $i++) {
        $found = (Invoke-Graph "servicePrincipals?`$filter=$filter").value | Select-Object -First 1
        if ($found -and (Get-Prop $found 'id')) { return $found }
        Start-Sleep -Seconds 5
    }
    $null
}

function Get-GraphErrorText($err) {
    $text = $err.ErrorDetails.Message
    if (-not $text) { $text = $err.Exception.Message }
    try { $j = $text | ConvertFrom-Json; if ($j.error.message) { return $j.error.message } } catch { }
    $text
}

# ---------------------------------------------------------------- tenant
if (-not $TenantId) {
    $valuesFile = Join-Path $repoRoot 'lab/lab-values.json'
    if (Test-Path $valuesFile) { $TenantId = (Get-Content $valuesFile -Raw | ConvertFrom-Json).tenantId }
}
if (-not $TenantId) { throw 'Pass -TenantId <your lab tenant ID> (lab/lab-values.json was not found).' }

$scopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Synchronization.ReadWrite.All', 'User.Read.All')
Write-Host "Signing in to lab tenant $TenantId ..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome
if ((Get-MgContext).TenantId -ne $TenantId) { throw "Signed in to tenant $((Get-MgContext).TenantId), expected $TenantId. Run Disconnect-MgGraph and try again." }

$sp = (Invoke-Graph "servicePrincipals?`$filter=displayName eq '$appName'").value | Select-Object -First 1

if ($Remove) {
    if (-not $sp) { Write-Host "$appName is not in this tenant. Nothing to remove."; return }
    $app = (Invoke-Graph "applications?`$filter=appId eq '$($sp.appId)'").value | Select-Object -First 1
    if ($app -and $PSCmdlet.ShouldProcess($appName, 'Delete enterprise app and its app registration')) {
        $null = Invoke-Graph "applications/$($app.id)" -Method DELETE
        Write-Host "Deleted $appName. Entra keeps deleted apps for 30 days under App registrations > Deleted applications." -ForegroundColor Green
    }
    return
}

# ---------------------------------------------------------------- tools
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Node.js is not installed. Run: winget install --id OpenJS.NodeJS.LTS   then open a new PowerShell window.' }
$cloudflared = Get-Command cloudflared -ErrorAction SilentlyContinue
if (-not $cloudflared) {
    $guess = Join-Path ${env:ProgramFiles(x86)} 'cloudflared\cloudflared.exe'
    if (Test-Path $guess) { $cloudflared = Get-Item $guess } else {
        throw 'cloudflared is not installed. Run: winget install --id Cloudflare.cloudflared   then open a new PowerShell window.'
    }
}
$cloudflaredPath = if ($cloudflared -is [System.Management.Automation.CommandInfo]) { $cloudflared.Source } else { $cloudflared.FullName }

# ---------------------------------------------------------------- enterprise app and assignment
$org    = (Invoke-Graph 'organization').value[0]
$domain = ($org.verifiedDomains | Where-Object { $_.isInitial }).name
if (-not $AssignUpn) { $AssignUpn = "lab.user1@$domain" }
$user = (Invoke-Graph "users?`$filter=userPrincipalName eq '$AssignUpn'&`$select=id,userPrincipalName,displayName").value | Select-Object -First 1
if (-not $user) { throw "User $AssignUpn was not found in the lab tenant. Pass -AssignUpn with a test user's UPN." }

if (-not $sp) {
    # An earlier run may have created the app registration before its enterprise app (service principal)
    # was visible. Reuse it rather than making a second F360-ScimApp.
    $existingApp = (Invoke-Graph "applications?`$filter=displayName eq '$appName'").value | Select-Object -First 1
    $appId = Get-Prop $existingApp 'appId'
    if (-not $appId) {
        if (-not $PSCmdlet.ShouldProcess($appName, 'Create enterprise app from the non-gallery template')) { return }
        $made = Invoke-Graph "applicationTemplates/$customTemplate/instantiate" -Method POST -Body @{ displayName = $appName }
        $appId = Get-Prop (Get-Prop $made 'servicePrincipal') 'appId'
        if (-not $appId) { $appId = Get-Prop (Get-Prop $made 'application') 'appId' }
        Write-Host "Created enterprise app $appName" -ForegroundColor Green
    }
    $sp = Find-ScimServicePrincipal $appId
    if (-not $sp -and $appId) {
        # The app registration exists but its enterprise app never appeared: create it.
        try { $null = Invoke-Graph 'servicePrincipals' -Method POST -Body @{ appId = $appId } } catch { }
        $sp = Find-ScimServicePrincipal $appId
    }
    if (-not $sp) { throw "$appName was created but Entra has not finished setting it up. Wait one minute and run the same command again; it will reuse the app." }
}
if (@((Invoke-Graph "servicePrincipals?`$filter=displayName eq '$appName'").value).Count -gt 1) {
    Write-Warning "There is more than one enterprise app named $appName. Using $($sp.id). Delete the extras in Enterprise apps."
}

# Provisioning skips users assigned the "Default Access" role (all-zero appRoleId) with
# "NotEffectivelyEntitled". Assign a real app role, normally the one called "User".
$defaultAccess = '00000000-0000-0000-0000-000000000000'
$userRoles = @(Get-Prop $sp 'appRoles') | Where-Object { $_ -and (Get-Prop $_ 'isEnabled') -and (@(Get-Prop $_ 'allowedMemberTypes') -contains 'User') }
$role = $userRoles | Where-Object { (Get-Prop $_ 'displayName') -eq 'User' -or (Get-Prop $_ 'value') -eq 'User' } | Select-Object -First 1
if (-not $role) { $role = $userRoles | Where-Object { (Get-Prop $_ 'displayName') -ne 'msiam_access' } | Select-Object -First 1 }
if (-not $role) { $role = $userRoles | Select-Object -First 1 }
if (-not $role) {
    throw "$appName has no app role that users can be assigned to, so Entra would skip every user. In the Entra admin center open App registrations > $appName > App roles, create a role named User (allowed member types: Users/Groups), then run this again."
}
$roleName = Get-Prop $role 'displayName'

$assignments = @((Invoke-Graph "servicePrincipals/$($sp.id)/appRoleAssignedTo").value | Where-Object { $_ -and $_.principalId -eq $user.id })
foreach ($a in $assignments | Where-Object { $_.appRoleId -ne $role.id }) {
    if ($PSCmdlet.ShouldProcess($AssignUpn, "Remove assignment with role $($a.appRoleId) from $appName")) {
        $null = Invoke-Graph "servicePrincipals/$($sp.id)/appRoleAssignedTo/$($a.id)" -Method DELETE
        $what = if ($a.appRoleId -eq $defaultAccess) { 'Default Access (never provisioned)' } else { $a.appRoleId }
        Write-Host "Removed $AssignUpn's assignment with role $what" -ForegroundColor Yellow
    }
}
$newAssignment = $false
if (-not ($assignments | Where-Object { $_.appRoleId -eq $role.id }) -and $PSCmdlet.ShouldProcess($AssignUpn, "Assign to $appName with role $roleName")) {
    $null = Invoke-Graph "servicePrincipals/$($sp.id)/appRoleAssignedTo" -Method POST -Body @{ principalId = $user.id; resourceId = $sp.id; appRoleId = $role.id }
    $newAssignment = $true
    Write-Host "Assigned $AssignUpn to $appName with role $roleName (direct assignment; group assignment needs Entra ID P1)" -ForegroundColor Green
} else {
    Write-Host "$AssignUpn is assigned to $appName with role $roleName"
}

# ---------------------------------------------------------------- provisioning job
$job = (Invoke-Graph "servicePrincipals/$($sp.id)/synchronization/jobs").value | Select-Object -First 1
if (-not $job) {
    $templates = (Invoke-Graph "servicePrincipals/$($sp.id)/synchronization/templates").value
    $templateId = ($templates | Where-Object { $_.factoryTag -eq 'scim' -or $_.id -eq 'scim' } | Select-Object -First 1).id
    if (-not $templateId) { $templateId = ($templates | Select-Object -First 1).id }
    if (-not $templateId) { $templateId = 'scim' }
    if (-not $PSCmdlet.ShouldProcess($appName, "Create provisioning job from template $templateId")) { return }
    try {
        $job = Invoke-Graph "servicePrincipals/$($sp.id)/synchronization/jobs" -Method POST -Body @{ templateId = $templateId }
    } catch {
        throw "Entra would not create the provisioning job: $(Get-GraphErrorText $_)"
    }
    Write-Host "Created provisioning job $($job.id)" -ForegroundColor Green
}

# ---------------------------------------------------------------- start the SCIM app and the tunnel
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')

$nodeArgs = @((Join-Path $here 'server.mjs'), '--port', $Port)
if ($Fault)  { $nodeArgs += @('--fault', $Fault) }
if ($Reset)  { $nodeArgs += '--reset' }

$env:F360_SCIM_TOKEN = $token
$server = Start-Process -FilePath 'node' -ArgumentList $nodeArgs -NoNewWindow -PassThru
Remove-Item Env:F360_SCIM_TOKEN

$tunnelLog = Join-Path $logDir 'tunnel.log'
Remove-Item $tunnelLog -ErrorAction SilentlyContinue
$tunnel = Start-Process -FilePath $cloudflaredPath -ArgumentList @('tunnel', '--no-autoupdate', '--url', "http://127.0.0.1:$Port") `
    -RedirectStandardError $tunnelLog -RedirectStandardOutput (Join-Path $logDir 'tunnel.out.log') -WindowStyle Hidden -PassThru

function Stop-Lab {
    foreach ($p in @($tunnel, $server)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
}

try {
    Write-Host 'Opening a Cloudflare quick tunnel (free, no account) ...' -ForegroundColor Cyan
    $publicUrl = $null
    for ($i = 0; $i -lt 60 -and -not $publicUrl; $i++) {
        Start-Sleep -Seconds 1
        if ($tunnel.HasExited) { throw "cloudflared stopped. See $tunnelLog" }
        if (Test-Path $tunnelLog) {
            $m = Select-String -Path $tunnelLog -Pattern 'https://[a-z0-9-]+\.trycloudflare\.com' | Select-Object -First 1
            if ($m) { $publicUrl = $m.Matches[0].Value }
        }
    }
    if (-not $publicUrl) { throw "No tunnel address after 60 seconds. See $tunnelLog" }
    $tenantUrl = "$publicUrl/scim"
    # The tunnel can take a few seconds to answer after its address is printed.
    for ($i = 0; $i -lt 20; $i++) {
        try { $null = Invoke-WebRequest "$tenantUrl/ServiceProviderConfig" -Headers @{ Authorization = "Bearer $token" } -SkipHttpErrorCheck -TimeoutSec 5; break } catch { Start-Sleep -Seconds 2 }
    }

    # ------------------------------------------------------------ Tenant URL and Secret Token
    $credentials = @(
        @{ key = 'BaseAddress'; value = $tenantUrl },
        @{ key = 'SecretToken'; value = $token }
    )
    $null = Invoke-Graph "servicePrincipals/$($sp.id)/synchronization/secrets" -Method PUT -Body @{ value = $credentials }
    Write-Host "Tenant URL set to $tenantUrl" -ForegroundColor Green

    Write-Host 'Test connection ...' -ForegroundColor Cyan
    try {
        $null = Invoke-Graph "servicePrincipals/$($sp.id)/synchronization/jobs/$($job.id)/validateCredentials" -Method POST -Body @{ useSavedCredentials = $true }
        Write-Host 'Test connection passed.' -ForegroundColor Green
    } catch {
        Write-Warning "Test connection failed: $(Get-GraphErrorText $_)"
    }

    # ------------------------------------------------------------ provision on demand
    if (-not $NoOnDemand) {
        $schema = Invoke-Graph "servicePrincipals/$($sp.id)/synchronization/jobs/$($job.id)/schema"
        $rules = @(Get-Prop $schema 'synchronizationRules')
        $rule = $rules | Where-Object { @(Get-Prop $_ 'objectMappings') | Where-Object { (Get-Prop $_ 'sourceObjectName') -eq 'User' } } | Select-Object -First 1
        if (-not $rule) { $rule = $rules | Select-Object -First 1 }
        if ($newAssignment) {
            # The provisioning service reads assignments from a copy that can lag a minute behind.
            Write-Host 'Waiting 60 seconds for the new assignment to reach the provisioning service ...' -ForegroundColor Cyan
            Start-Sleep -Seconds 60
        }
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            Write-Host "Provisioning $AssignUpn on demand ..." -ForegroundColor Cyan
            $skipReason = $null
            try {
                $result = Invoke-Graph "servicePrincipals/$($sp.id)/synchronization/jobs/$($job.id)/provisionOnDemand" -Method POST -Body @{
                    parameters = @(@{ ruleId = (Get-Prop $rule 'id'); subjects = @(@{ objectId = $user.id; objectTypeName = 'User' }) })
                }
                $entries = $null
                try { $entries = @((Get-Prop $result 'value') | ConvertFrom-Json) } catch { }
                if ($entries) {
                    foreach ($entry in $entries) {
                        foreach ($step in @(Get-Prop $entry 'provisioningSteps')) {
                            $desc = ((Get-Prop $step 'description') -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
                            Write-Host ("  {0,-8} {1,-26} {2}" -f (Get-Prop $step 'status'), (Get-Prop $step 'name'), $desc)
                        }
                        $info = Get-Prop $entry 'statusInfo'
                        $status = Get-Prop $info 'status'
                        $skipReason = Get-Prop $info 'reason'
                        $color = if ($status -eq 'Success') { 'Green' } else { 'Yellow' }
                        Write-Host ("  Result: {0}{1}" -f $status, $(if ($skipReason) { " ($skipReason)" } else { '' })) -ForegroundColor $color
                    }
                } else {
                    Write-Host '  Entra returned:'
                    Write-Host ($result | ConvertTo-Json -Depth 8)
                }
            } catch {
                Write-Warning "On-demand provisioning failed: $(Get-GraphErrorText $_)"
            }
            if ($skipReason -ne 'NotEffectivelyEntitled' -or $attempt -eq 3) { break }
            Write-Host 'Entra has not seen the assignment yet. Trying again in 60 seconds ...' -ForegroundColor Cyan
            Start-Sleep -Seconds 60
        }
    }

    if ($StartCycle) {
        $null = Invoke-Graph "servicePrincipals/$($sp.id)/synchronization/jobs/$($job.id)/start" -Method POST
        Write-Host 'Scheduled provisioning cycle started (first run within minutes, then about every 40 minutes).' -ForegroundColor Green
    }

    Write-Host ''
    Write-Host "SCIM app is live at $tenantUrl" -ForegroundColor Green
    Write-Host "Request logs: $logDir   (open one and paste its request or response into Federation 360 > SCIM checker)"
    Write-Host "Entra admin center: Enterprise apps > $appName > Provisioning   (Provision on demand works there too)"
    Write-Host ''
    Read-Host 'Press Enter to stop the SCIM app and the tunnel'
}
finally {
    if ($StartCycle -and $job) {
        try { $null = Invoke-Graph "servicePrincipals/$($sp.id)/synchronization/jobs/$($job.id)/pause" -Method POST; Write-Host 'Provisioning cycle paused.' } catch { }
    }
    Stop-Lab
    $token = $null
    Write-Host 'Stopped. Users the SCIM app received are kept in lab/scim/data (use -Reset to clear them).'
}

<#
.SYNOPSIS
  One-time setup of a Federation 360 LAB tenant: test users and a secret-less deploy identity for Terraform.

.DESCRIPTION
  Run once, signed in as a Global Administrator of the LAB tenant. It:
    1. Creates test users (lab.user1, lab.user2, ...) with one-time passwords shown once on screen.
    2. Creates the app registration "f360-lab-deployer" and grants it the Microsoft Graph application
       permissions Terraform needs, with admin consent.
    3. Adds a federated credential so GitHub Actions in YOUR repository can sign in as that identity
       through OIDC. No client secret is created or stored anywhere.

  Safe to re-run: existing objects are reused.

  Do NOT run this against a production tenant. The deploy identity can create and change
  applications, users and groups tenant-wide.

.EXAMPLE
  ./New-F360LabBootstrap.ps1 -TenantId 8f2b6c1e-0d4a-4a7e-9a51-3c0d2e7b9f10 -GitHubRepository yourname/federation-360
#>
#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    # owner/repo of the repository whose GitHub Actions will run Terraform. Omit to skip CI setup.
    [ValidatePattern('^[^/\s]+/[^/\s]+$')]
    [string]$GitHubRepository,

    # GitHub environment the workflow runs in. Add required reviewers to it for an approval gate.
    [string]$GitHubEnvironment = 'lab',

    # Numeric GitHub IDs of the repository owner and the repository. Looked up with the GitHub CLI
    # (gh) when omitted. Find them yourself with:  gh api repos/OWNER/REPO --jq '.owner.id, .id'
    [ValidateRange(1, [long]::MaxValue)]
    [long]$GitHubOwnerId,
    [ValidateRange(1, [long]::MaxValue)]
    [long]$GitHubRepositoryId,

    # Trust the older name-based subject (repo:owner/repo:...). Only for a repository created before
    # 2026-07-15 that has never been renamed, transferred or opted in to immutable subjects.
    [switch]$NameBasedSubject,

    [ValidateRange(0, 10)]
    [int]$TestUserCount = 2,

    # Required confirmation that this is a lab tenant.
    [switch]$IUnderstandThisIsALabTenant
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IUnderstandThisIsALabTenant) {
    throw 'Add -IUnderstandThisIsALabTenant to confirm this tenant is a lab, not production.'
}

$deployerName = 'f360-lab-deployer'
$graphAppId   = '00000003-0000-0000-c000-000000000000'
$deployerRoles = @(
    'Application.ReadWrite.All'            # app registrations and enterprise apps
    'Group.ReadWrite.All'                  # lab groups
    'User.Read.All'                        # look up test users
    'AppRoleAssignment.ReadWrite.All'      # assign users to apps, grant application permissions
    'DelegatedPermissionGrant.ReadWrite.All' # admin consent for delegated scopes
)

function Invoke-Graph {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body)
    $params = @{ Method = $Method; Uri = "https://graph.microsoft.com/v1.0/$Uri" }
    if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 10); $params.ContentType = 'application/json' }
    Invoke-MgGraphRequest @params
}

# GitHub puts a "subject" in the token it gives a workflow, and Entra only accepts the token when the
# subject matches the federated credential exactly. Repositories created, renamed or transferred on or
# after 2026-07-15 use the immutable form with numeric IDs: repo:owner@123/repo@456:environment:lab
function Get-GitHubSubject {
    $suffix = "environment:$GitHubEnvironment"
    if ($NameBasedSubject) { return "repo:${GitHubRepository}:$suffix" }
    $owner, $repo = $GitHubRepository -split '/', 2
    $ownerId = $GitHubOwnerId; $repoId = $GitHubRepositoryId
    if (-not ($ownerId -and $repoId)) {
        if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
            throw "Cannot look up GitHub IDs because the GitHub CLI (gh) is not installed. Install it and run 'gh auth login', or pass -GitHubOwnerId and -GitHubRepositoryId."
        }
        $json = & gh api "repos/$GitHubRepository" 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $json) {
            throw "Could not read $GitHubRepository with the GitHub CLI. Run 'gh auth login', or pass -GitHubOwnerId and -GitHubRepositoryId."
        }
        # -AsHashtable keeps created_at as text instead of converting it to a local date.
        $info = $json | ConvertFrom-Json -AsHashtable
        $ownerId = [long]$info.owner.id; $repoId = [long]$info.id
        $created = [datetimeoffset]::Parse([string]$info.created_at, [cultureinfo]::InvariantCulture)
        if ($created -lt [datetimeoffset]'2026-07-15T00:00:00Z') {
            Write-Warning "$GitHubRepository was created before 2026-07-15, so GitHub may still issue the name-based subject. If the workflow sign-in fails with AADSTS700213, re-run with -NameBasedSubject."
        }
    }
    "repo:$owner@$ownerId/$repo@${repoId}:$suffix"
}

function New-OneTimePassword {
    $chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'.ToCharArray()
    $bytes = [byte[]]::new(20)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] }) + '!7a'
}

$gitHubSubject = if ($GitHubRepository) { Get-GitHubSubject }

Write-Host "Signing in to tenant $TenantId ..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -NoWelcome -Scopes @(
    'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'User.ReadWrite.All', 'Organization.Read.All'
)

$context = Get-MgContext
if ($context.TenantId -ne $TenantId) { throw "Signed in to tenant $($context.TenantId), expected $TenantId." }

$org    = (Invoke-Graph -Uri 'organization').value[0]
$domain = ($org.verifiedDomains | Where-Object { $_.isInitial }).name
Write-Host "Tenant: $($org.displayName) ($domain)" -ForegroundColor Cyan

# ---------------------------------------------------------------- 1. test users
$upns = @()
for ($i = 1; $i -le $TestUserCount; $i++) {
    $upn = "lab.user$i@$domain"
    $upns += $upn
    $existing = (Invoke-Graph -Uri "users?`$filter=userPrincipalName eq '$upn'").value
    if ($existing) { Write-Host "User exists: $upn"; continue }
    if ($PSCmdlet.ShouldProcess($upn, 'Create test user')) {
        $password = New-OneTimePassword
        $null = Invoke-Graph -Method POST -Uri 'users' -Body @{
            accountEnabled    = $true
            displayName       = "Lab User $i"
            mailNickname      = "lab.user$i"
            userPrincipalName = $upn
            usageLocation     = 'US'
            passwordProfile   = @{ password = $password; forceChangePasswordNextSignIn = $true }
        }
        Write-Host "Created $upn   one-time password: $password" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------- 2. deploy identity
$app = (Invoke-Graph -Uri "applications?`$filter=displayName eq '$deployerName'").value | Select-Object -First 1
if (-not $app -and $PSCmdlet.ShouldProcess($deployerName, 'Create app registration')) {
    $app = Invoke-Graph -Method POST -Uri 'applications' -Body @{ displayName = $deployerName; signInAudience = 'AzureADMyOrg' }
    Write-Host "Created app registration $deployerName"
}

if ($app) {
    $sp = (Invoke-Graph -Uri "servicePrincipals?`$filter=appId eq '$($app.appId)'").value | Select-Object -First 1
    if (-not $sp -and $PSCmdlet.ShouldProcess($deployerName, 'Create service principal')) {
        $sp = Invoke-Graph -Method POST -Uri 'servicePrincipals' -Body @{ appId = $app.appId }
    }
    if (-not $sp) { return } # -WhatIf run: nothing further can be evaluated

    $graphSp  = (Invoke-Graph -Uri "servicePrincipals?`$filter=appId eq '$graphAppId'").value[0]
    $assigned = (Invoke-Graph -Uri "servicePrincipals/$($sp.id)/appRoleAssignments").value
    foreach ($roleName in $deployerRoles) {
        $role = $graphSp.appRoles | Where-Object { $_.value -eq $roleName -and $_.allowedMemberTypes -contains 'Application' }
        if (-not $role) { throw "Microsoft Graph has no application permission named $roleName." }
        if ($assigned | Where-Object { $_.appRoleId -eq $role.id }) { continue }
        if ($PSCmdlet.ShouldProcess($roleName, 'Grant application permission with admin consent')) {
            $null = Invoke-Graph -Method POST -Uri "servicePrincipals/$($sp.id)/appRoleAssignments" -Body @{
                principalId = $sp.id; resourceId = $graphSp.id; appRoleId = $role.id
            }
            Write-Host "Granted $roleName"
        }
    }

    # ------------------------------------------------------------ 3. GitHub OIDC trust (no secret)
    if ($GitHubRepository) {
        $subject  = $gitHubSubject
        $existing = (Invoke-Graph -Uri "applications/$($app.id)/federatedIdentityCredentials").value
        if (-not ($existing | Where-Object { $_.subject -eq $subject })) {
            if ($PSCmdlet.ShouldProcess($subject, 'Add federated credential')) {
                $null = Invoke-Graph -Method POST -Uri "applications/$($app.id)/federatedIdentityCredentials" -Body @{
                    name        = "github-$GitHubEnvironment-" + ($NameBasedSubject ? 'named' : 'immutable')
                    issuer      = 'https://token.actions.githubusercontent.com'
                    subject     = $subject
                    audiences   = @('api://AzureADTokenExchange')
                    description = 'GitHub Actions runs Terraform for the Federation 360 lab.'
                }
                Write-Host "Trusted GitHub Actions: $subject"
            }
        }
    }

    Write-Host ''
    Write-Host 'Done. Use these values:' -ForegroundColor Green
    Write-Host "  LAB_TENANT_ID   = $TenantId"
    Write-Host "  LAB_CLIENT_ID   = $($app.appId)"
    Write-Host "  LAB_USER_UPNS   = $(ConvertTo-Json -Compress -InputObject @($upns))"

    # Saved for lab/Connect-F360LabPipeline.ps1 so nothing has to be copied by hand. No secrets in it.
    $valuesPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'lab-values.json'
    [ordered]@{
        tenantId          = $TenantId
        clientId          = $app.appId
        userUpns          = @($upns)
        gitHubRepository  = $GitHubRepository
        gitHubEnvironment = $GitHubEnvironment
    } | ConvertTo-Json | Set-Content -Path $valuesPath -Encoding utf8
    Write-Host "Saved to $valuesPath (not committed to git)."
}

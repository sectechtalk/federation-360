<#
.SYNOPSIS
  Connects your GitHub repository to the lab: Terraform state storage and the GitHub settings the
  "Lab tenant (Terraform)" workflow needs.

.DESCRIPTION
  Run once after lab/bootstrap/New-F360LabBootstrap.ps1. It:
    1. Asks for your HCP Terraform API token (typed hidden, never written to disk).
    2. Makes sure your HCP Terraform organization runs Terraform in Local execution mode.
    3. Creates the workspace that stores the Terraform state (default name f360-lab).
    4. Creates the GitHub environment "lab".
    5. Sets the GitHub variables LAB_TENANT_ID, LAB_CLIENT_ID, LAB_USER_UPNS and TF_CLOUD_ORGANIZATION.
    6. Stores the token as the GitHub secret TF_API_TOKEN.

  The lab values come from lab/lab-values.json, which the bootstrap script writes. Safe to re-run,
  for example with a new token after the old one expires.

  Needs: PowerShell 7.2+, the GitHub CLI signed in (gh auth login), and a free HCP Terraform account
  with a confirmed email (https://app.terraform.io).

.EXAMPLE
  ./lab/Connect-F360LabPipeline.ps1 -TerraformOrganization yourname-f360

.EXAMPLE
  # Also create the HCP Terraform organization if it does not exist yet
  ./lab/Connect-F360LabPipeline.ps1 -TerraformOrganization yourname-f360 -TerraformEmail you@example.com
#>
#Requires -Version 7.2
[CmdletBinding(SupportsShouldProcess)]
param(
    # Name of your HCP Terraform organization.
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [string]$TerraformOrganization,

    # Only needed to create the organization when it does not exist: its notification email address.
    [string]$TerraformEmail,

    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [string]$Workspace = 'f360-lab',

    # File written by the bootstrap script.
    [string]$ValuesPath = (Join-Path $PSScriptRoot 'lab-values.json'),

    # Use these instead of the values file.
    [string]$GitHubRepository,
    [string]$TenantId,
    [string]$ClientId,
    [string[]]$UserUpns,
    [string]$GitHubEnvironment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------ lab values
$values = @{}
if (Test-Path $ValuesPath) { $values = Get-Content -Raw $ValuesPath | ConvertFrom-Json -AsHashtable }
if (-not $GitHubRepository)  { $GitHubRepository  = $values['gitHubRepository'] }
if (-not $TenantId)          { $TenantId          = $values['tenantId'] }
if (-not $ClientId)          { $ClientId          = $values['clientId'] }
if (-not $UserUpns)          { $UserUpns          = @($values['userUpns']) | Where-Object { $_ } }
if (-not $GitHubEnvironment) { $GitHubEnvironment = $values['gitHubEnvironment'] ?? 'lab' }

$missing = @(
    if (-not $GitHubRepository) { '-GitHubRepository' }
    if (-not $TenantId)         { '-TenantId' }
    if (-not $ClientId)         { '-ClientId' }
)
if ($missing) {
    throw "Missing $($missing -join ', '). Run lab/bootstrap/New-F360LabBootstrap.ps1 first (it writes $ValuesPath), or pass the values as parameters."
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "The GitHub CLI (gh) is not installed. Install it, run 'gh auth login', and try again."
}

function Invoke-Gh {
    # Runs gh and stops the script when it fails. Pipeline input is passed on to gh.
    $input | & gh @args
    if ($LASTEXITCODE -ne 0) { throw "gh $($args -join ' ') failed (exit code $LASTEXITCODE)." }
}

# ------------------------------------------------------------------ HCP Terraform
$secure = if ($env:TF_API_TOKEN) {
    ConvertTo-SecureString $env:TF_API_TOKEN -AsPlainText -Force
} else {
    Write-Host 'Create a token at https://app.terraform.io/app/settings/tokens (Create an API token), then paste it here.' -ForegroundColor Cyan
    Read-Host -AsSecureString 'HCP Terraform API token (hidden)'
}
$token = [System.Net.NetworkCredential]::new('', $secure).Password.Trim()
if (-not $token) { throw 'No token entered.' }

$tfApi = 'https://app.terraform.io/api/v2'
function Invoke-Tf {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Path, $Body)
    $params = @{
        Method               = $Method
        Uri                  = "$tfApi/$Path"
        Headers              = @{ Authorization = "Bearer $token" }
        ContentType          = 'application/vnd.api+json'
        SkipHttpErrorCheck   = $true
        StatusCodeVariable   = 'status'
    }
    if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 10) }
    $response = Invoke-RestMethod @params
    [pscustomobject]@{ Status = [int]$status; Body = $response }
}
function Get-TfError($result) {
    "HTTP $($result.Status) $($result.Body | ConvertTo-Json -Depth 6 -Compress)"
}

Write-Host "Checking HCP Terraform organization $TerraformOrganization ..." -ForegroundColor Cyan
$org = Invoke-Tf -Path "organizations/$TerraformOrganization"
if ($org.Status -eq 401) { throw 'HCP Terraform rejected the token. Create a new one and run this again.' }
if ($org.Status -eq 404) {
    if (-not $TerraformEmail) {
        throw "HCP Terraform has no organization named $TerraformOrganization that this token can see. Create it at https://app.terraform.io/app/organizations/new (choose Personal), or re-run with -TerraformEmail to create it here."
    }
    if ($PSCmdlet.ShouldProcess($TerraformOrganization, 'Create HCP Terraform organization')) {
        $org = Invoke-Tf -Method POST -Path 'organizations' -Body @{
            data = @{ type = 'organizations'; attributes = @{ name = $TerraformOrganization; email = $TerraformEmail } }
        }
        if ($org.Status -ge 300) { throw "Could not create the organization: $(Get-TfError $org). Create it at https://app.terraform.io/app/organizations/new instead, then run this again." }
        Write-Host "Created organization $TerraformOrganization"
    }
} elseif ($org.Status -ge 300) {
    throw "HCP Terraform returned an error for the organization: $(Get-TfError $org)"
}

# Local execution: Terraform runs on the GitHub runner, which is what holds the trust with your tenant.
if ($org.Status -lt 300 -and $org.Body.data.attributes.'default-execution-mode' -ne 'local') {
    if ($PSCmdlet.ShouldProcess($TerraformOrganization, 'Set default execution mode to Local')) {
        $r = Invoke-Tf -Method PATCH -Path "organizations/$TerraformOrganization" -Body @{
            data = @{ type = 'organizations'; attributes = @{ 'default-execution-mode' = 'local' } }
        }
        if ($r.Status -ge 300) { throw "Could not set Local execution mode: $(Get-TfError $r)" }
        Write-Host 'Default execution mode set to Local'
    }
}

$ws = Invoke-Tf -Path "organizations/$TerraformOrganization/workspaces/$Workspace"
if ($ws.Status -eq 404) {
    if ($PSCmdlet.ShouldProcess($Workspace, 'Create HCP Terraform workspace (Local execution)')) {
        $r = Invoke-Tf -Method POST -Path "organizations/$TerraformOrganization/workspaces" -Body @{
            data = @{ type = 'workspaces'; attributes = @{ name = $Workspace; 'execution-mode' = 'local' } }
        }
        if ($r.Status -ge 300) { throw "Could not create workspace ${Workspace}: $(Get-TfError $r)" }
        Write-Host "Created workspace $Workspace"
    }
} elseif ($ws.Status -ge 300) {
    throw "HCP Terraform returned an error for workspace ${Workspace}: $(Get-TfError $ws)"
} else {
    $mode = $ws.Body.data.attributes.'execution-mode'
    if ($mode -ne 'local') {
        if ($PSCmdlet.ShouldProcess($Workspace, "Change execution mode from $mode to Local")) {
            $r = Invoke-Tf -Method PATCH -Path "organizations/$TerraformOrganization/workspaces/$Workspace" -Body @{
                data = @{ type = 'workspaces'; attributes = @{ 'execution-mode' = 'local' } }
            }
            if ($r.Status -ge 300) { throw "Could not set workspace ${Workspace} to Local: $(Get-TfError $r)" }
        }
    }
    Write-Host "Workspace $Workspace exists (execution mode: local)"
}

# ------------------------------------------------------------------ GitHub
Write-Host "Configuring GitHub repository $GitHubRepository ..." -ForegroundColor Cyan
if ($PSCmdlet.ShouldProcess($GitHubEnvironment, 'Create GitHub environment')) {
    $null = Invoke-Gh api -X PUT "repos/$GitHubRepository/environments/$GitHubEnvironment"
    Write-Host "Environment $GitHubEnvironment ready"
}

$variables = [ordered]@{
    LAB_TENANT_ID         = $TenantId
    LAB_CLIENT_ID         = $ClientId
    LAB_USER_UPNS         = ConvertTo-Json -Compress -InputObject @($UserUpns)
    TF_CLOUD_ORGANIZATION = $TerraformOrganization
}
foreach ($name in $variables.Keys) {
    if ($PSCmdlet.ShouldProcess($name, 'Set GitHub variable')) {
        # Sent through the pipeline so quotes in the JSON list survive on Windows.
        $variables[$name] | Invoke-Gh variable set $name --repo $GitHubRepository
    }
}
if ($PSCmdlet.ShouldProcess('TF_API_TOKEN', 'Set GitHub secret')) {
    $token | Invoke-Gh secret set TF_API_TOKEN --repo $GitHubRepository
}
$token = $null

Write-Host ''
Write-Host 'Done. Next:' -ForegroundColor Green
Write-Host '  ./lab/Invoke-F360Lab.ps1 -Action plan'
Write-Host '  ./lab/Invoke-F360Lab.ps1 -Action apply'

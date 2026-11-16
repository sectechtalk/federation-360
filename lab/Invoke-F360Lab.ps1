<#
.SYNOPSIS
  Runs the "Lab tenant (Terraform)" workflow in GitHub Actions and waits for the result.

.DESCRIPTION
  plan     previews what Terraform would change. Nothing is changed.
  apply    builds or updates the lab, then prints the inventory JSON and test links.
  destroy  removes everything Terraform built. Test users and the deploy identity stay.

  Every run is recorded under the repository's Actions tab.

.EXAMPLE
  ./lab/Invoke-F360Lab.ps1 -Action plan

.EXAMPLE
  ./lab/Invoke-F360Lab.ps1 -Action apply -Open
#>
#Requires -Version 7.2
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('plan', 'apply', 'destroy')]
    [string]$Action,

    # owner/repo. Read from lab/lab-values.json when omitted.
    [string]$GitHubRepository,

    # Open the finished run in the browser.
    [switch]$Open
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workflow = 'lab.yml'

if (-not $GitHubRepository) {
    $valuesPath = Join-Path $PSScriptRoot 'lab-values.json'
    if (Test-Path $valuesPath) { $GitHubRepository = (Get-Content -Raw $valuesPath | ConvertFrom-Json -AsHashtable)['gitHubRepository'] }
}
if (-not $GitHubRepository) { throw 'Pass -GitHubRepository owner/repo (lab/lab-values.json was not found).' }
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw "The GitHub CLI (gh) is not installed. Install it and run 'gh auth login'." }

function Get-LatestRunId {
    $id = & gh run list --repo $GitHubRepository --workflow $workflow --limit 1 --json databaseId --jq '.[0].databaseId'
    if ($LASTEXITCODE -ne 0) { throw 'Could not list workflow runs with gh.' }
    "$id".Trim()
}

if ($Action -eq 'destroy' -and -not $PSCmdlet.ShouldContinue("Remove every lab app and group Terraform built in the tenant behind $GitHubRepository?", 'Destroy the lab')) {
    return
}
if (-not $PSCmdlet.ShouldProcess($GitHubRepository, "Run Terraform $Action in GitHub Actions")) { return }

$before = Get-LatestRunId
& gh workflow run $workflow --repo $GitHubRepository -f "action=$Action" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not start the workflow.' }

# GitHub takes a few seconds to list the new run.
$run = $null
foreach ($attempt in 1..20) {
    Start-Sleep -Seconds 3
    $latest = Get-LatestRunId
    if ($latest -and $latest -ne $before) { $run = $latest; break }
}
if (-not $run) { throw "The workflow was started but the run did not appear. Check https://github.com/$GitHubRepository/actions" }

Write-Host "Run: https://github.com/$GitHubRepository/actions/runs/$run" -ForegroundColor Cyan
& gh run watch $run --repo $GitHubRepository --exit-status
$succeeded = $LASTEXITCODE -eq 0

# Strip colour codes and the "job <tab> step <tab> timestamp" prefix from the log lines.
$log = @(& gh run view $run --repo $GitHubRepository --log 2>$null |
    ForEach-Object { ($_ -replace '\x1b\[[0-9;]*m', '') -replace '^[^\t]*\t[^\t]*\t\S+\s?', '' })

Write-Host ''
if (-not $succeeded) {
    Write-Host "Terraform $Action FAILED." -ForegroundColor Red
    $log | Select-String -Pattern 'Error:|AADSTS|##\[error\]' -Context 0, 6 | Select-Object -First 8 | ForEach-Object { $_.ToString() }
    Write-Host "Full log: gh run view $run --repo $GitHubRepository --log-failed"
    exit 1
}

Write-Host "Terraform $Action succeeded." -ForegroundColor Green
$log | Select-String -Pattern '^(Plan:|No changes\.|Apply complete!|Destroy complete!)' | ForEach-Object { $_.Line }

if ($Action -eq 'apply') {
    # The workflow prints the inventory and test links between these two markers.
    $start = [array]::IndexOf($log, '### Import into Federation 360')
    $end   = [array]::IndexOf($log, '### End of lab outputs')
    $result = if ($start -ge 0 -and $end -gt $start) { $log[$start..($end - 1)] }
    if ($result) {
        Write-Host ''
        $result
    } else {
        Write-Host "Open the run for the inventory JSON and test links: gh run view $run --repo $GitHubRepository --web"
    }
}
if ($Open) { & gh run view $run --repo $GitHubRepository --web }

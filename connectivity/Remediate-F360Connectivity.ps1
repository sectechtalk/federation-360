<#
.SYNOPSIS
    Federation 360 connectivity test: no remediation.
.DESCRIPTION
    The connectivity test only reports. Intune Remediations needs a remediation script, so this one exists,
    changes nothing on the device and exits 0. Leave "Run remediation script" off in Remediation 360.
#>
Write-Output 'F360|v1|remediation=none'
exit 0

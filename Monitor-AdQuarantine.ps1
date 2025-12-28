<#
.SYNOPSIS
Scans a quarantine OU for newly created computer objects and emails the AD Ops team.

.DESCRIPTION
Use this script to poll a designated Active Directory OU (for example, a quarantine container)
for computer accounts created since the previous run. Any newly detected objects are reported
via email so the AD Ops team can move them to the correct OU. The script keeps a lightweight
state file containing the last run timestamp to avoid duplicate alerts.

.PARAMETER QuarantineOU
Distinguished name of the OU or container holding quarantined computer accounts.

.PARAMETER MailFrom
SMTP sender address.

.PARAMETER MailTo
One or more recipient addresses.

.PARAMETER SmtpServer
SMTP relay host.

.PARAMETER SmtpPort
SMTP port (defaults to 25).

.PARAMETER UseSsl
Enable if the SMTP relay requires TLS.

.PARAMETER SmtpCredential
Credential object used for authenticated SMTP servers.

.PARAMETER LookbackMinutes
How far back to search when no state file is present. Defaults to 60 minutes.

.PARAMETER StatePath
Path to the JSON state file that stores the last run timestamp. Defaults to a file named
`quarantine-state.json` in the same directory as the script.

.PARAMETER Subject
Subject line for the notification email.

.EXAMPLE
# Search the quarantine OU every 15 minutes via Task Scheduler and send a summary email
powershell.exe -File "C:\Scripts\Monitor-AdQuarantine.ps1" `
  -QuarantineOU "OU=Computer Quarantine,DC=example,DC=com" `
  -MailFrom "quarantine-monitor@example.com" `
  -MailTo "adops@example.com" `
  -SmtpServer "smtp.example.com" `
  -LookbackMinutes 15

.NOTES
Requires the ActiveDirectory module (for example, RSAT on Windows Server/Windows 10+).
Run this script with appropriate permissions to read the target OU.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$QuarantineOU,

    [Parameter(Mandatory = $true)]
    [string]$MailFrom,

    [Parameter(Mandatory = $true)]
    [string[]]$MailTo,

    [Parameter(Mandatory = $true)]
    [string]$SmtpServer,

    [Parameter()]
    [int]$SmtpPort = 25,

    [Parameter()]
    [switch]$UseSsl,

    [Parameter()]
    [System.Management.Automation.PSCredential]$SmtpCredential,

    [Parameter()]
    [int]$LookbackMinutes = 60,

    [Parameter()]
    [string]$StatePath = (Join-Path -Path $PSScriptRoot -ChildPath 'quarantine-state.json'),

    [Parameter()]
    [string]$Subject = 'New quarantine computer objects detected'
)

function Get-LastRunTime {
    param(
        [string]$Path,
        [int]$FallbackMinutes
    )

    if (-not (Test-Path -Path $Path)) {
        return (Get-Date).AddMinutes(-1 * $FallbackMinutes)
    }

    try {
        $content = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        $parsed = $null
        if ($null -ne $content.LastRun -and [DateTime]::TryParse($content.LastRun, [ref]$parsed)) {
            return [DateTime]$parsed
        }
    }
    catch {
        Write-Warning "Unable to parse state file at '$Path'. Using fallback lookback window."
    }

    return (Get-Date).AddMinutes(-1 * $FallbackMinutes)
}

function Save-LastRunTime {
    param(
        [string]$Path,
        [DateTime]$Timestamp
    )

    $directory = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    @{ LastRun = $Timestamp } | ConvertTo-Json | Set-Content -LiteralPath $Path -Encoding UTF8
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Error 'ActiveDirectory module is required. Install RSAT or run on a domain-joined host.'
    exit 1
}

$now = Get-Date
$since = Get-LastRunTime -Path $StatePath -FallbackMinutes $LookbackMinutes

$computers = Get-ADComputer -SearchBase $QuarantineOU -Filter { whenCreated -ge $since } -Properties whenCreated, distinguishedName, operatingSystem |
    Sort-Object -Property whenCreated

if (-not $computers) {
    Write-Host "No new computer objects found since $($since.ToString('s'))."
    Save-LastRunTime -Path $StatePath -Timestamp $now
    return
}

$rows = $computers | ForEach-Object {
    $created = $_.whenCreated.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $dn = $_.distinguishedName
    $os = if ($_.operatingSystem) { $_.operatingSystem } else { 'Unknown' }

    "<tr><td>$($_.Name)</td><td>$created</td><td>$os</td><td>$dn</td></tr>"
} -join "`n"

$emailBody = @"
<html>
<head>
<style>
table { border-collapse: collapse; font-family: Segoe UI, Arial, sans-serif; }
th, td { border: 1px solid #cccccc; padding: 6px 8px; text-align: left; }
th { background-color: #f2f2f2; }
</style>
</head>
<body>
<p>The following computer objects were created in the quarantine OU since <strong>$($since.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss'))</strong>:</p>
<table>
<thead><tr><th>Name</th><th>Created</th><th>Operating System</th><th>Distinguished Name</th></tr></thead>
<tbody>
$rows
</tbody>
</table>
<p>Please review and move these objects to their correct OUs.</p>
</body>
</html>
"@

$mailParams = @{
    From       = $MailFrom
    To         = $MailTo
    Subject    = $Subject
    Body       = $emailBody
    SmtpServer = $SmtpServer
    Port       = $SmtpPort
    BodyAsHtml = $true
}

if ($UseSsl) { $mailParams.UseSsl = $true }
if ($null -ne $SmtpCredential) { $mailParams.Credential = $SmtpCredential }

Send-MailMessage @mailParams
Save-LastRunTime -Path $StatePath -Timestamp $now

Write-Host "Sent notification for $($computers.Count) computer object(s)."

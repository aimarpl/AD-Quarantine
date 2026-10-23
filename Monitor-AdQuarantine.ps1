<#
.SYNOPSIS
Reports computer objects newly created in an Active Directory quarantine OU by email.

.DESCRIPTION
Polls an Active Directory OU or container (for example, the default computer container redirected
with redircmp.exe) for computer accounts created since the previous run and sends an HTML summary
to administrators, so the objects can be reviewed and moved to their correct OUs.

The script keeps a small JSON state file with the last successful run time and the objects that were
already reported. Each run re-queries a short overlap window to tolerate replication delay; objects
that were already reported are skipped. The state is only updated after the notification has been
sent, so a failed run is retried on the next execution.

.PARAMETER QuarantineOU
Distinguished name of the OU or container holding quarantined computer accounts.

.PARAMETER MailFrom
SMTP sender address.

.PARAMETER MailTo
One or more recipient addresses. A single comma- or semicolon-separated string is also accepted,
which is useful when the script is started with powershell.exe -File.

.PARAMETER SmtpServer
SMTP relay host.

.PARAMETER SmtpPort
SMTP port. Defaults to 25.

.PARAMETER UseSsl
Enable if the SMTP relay requires TLS.

.PARAMETER SmtpCredential
Credential object used for authenticated SMTP relays.

.PARAMETER Server
Domain controller to query. Defaults to the PDC emulator of the current domain, so every run reads
from the same domain controller.

.PARAMETER LookbackMinutes
How far back to search when no usable state file exists (for example, on the first run).
Defaults to 60 minutes.

.PARAMETER OverlapMinutes
Minutes re-queried before the last run time to catch objects that replicated to the queried domain
controller late. Already reported objects are not reported again. Defaults to 15 minutes.

.PARAMETER StatePath
Path to the JSON state file. Defaults to quarantine-state.json in the script directory.

.PARAMETER Subject
Subject line of the notification email.

.EXAMPLE
# Run every 15 minutes from Task Scheduler and notify two mailboxes
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Monitor-AdQuarantine.ps1" `
  -QuarantineOU "OU=Computer Quarantine,DC=example,DC=com" `
  -MailFrom "quarantine-monitor@example.com" `
  -MailTo "ad-admins@example.com,servicedesk@example.com" `
  -SmtpServer "smtp.example.com"

.EXAMPLE
# Query a specific domain controller and use an authenticated TLS relay
$cred = Get-Credential
.\Monitor-AdQuarantine.ps1 -QuarantineOU "OU=Computer Quarantine,DC=example,DC=com" `
  -MailFrom "quarantine-monitor@example.com" -MailTo "ad-admins@example.com" `
  -SmtpServer "smtp.example.com" -SmtpPort 587 -UseSsl -SmtpCredential $cred `
  -Server "dc01.example.com" -Verbose

.NOTES
Author : Łukasz Ślemp (https://github.com/aimarpl)
Version: 1.1.0
License: MIT

Requirements:
- Windows PowerShell 5.1 or PowerShell 7 with the ActiveDirectory module (RSAT).
- Read access to the quarantine OU and permission to relay mail through the SMTP server.

Send-MailMessage is marked obsolete by Microsoft because it cannot guarantee a secure connection.
It still works with internal SMTP relays; use -UseSsl where the relay supports TLS.

Exit codes: 0 = success (with or without new objects), 1 = failure (state not updated).

Version history:
1.1.0 - State file stored as ISO 8601 UTC and read reliably on Windows PowerShell 5.1.
        Failed queries or emails no longer advance the state; the script exits with code 1.
        HTML-encode all directory values in the email body.
        Culture-independent LDAP filter on whenCreated.
        Query a fixed domain controller (PDC emulator by default) with an overlap window and
        de-duplication of already reported objects.
        Accept comma- or semicolon-separated recipients; parameter validation; no Write-Host.
1.0.0 - Initial release.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$QuarantineOU,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$MailFrom,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$MailTo,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SmtpServer,

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$SmtpPort = 25,

    [Parameter()]
    [switch]$UseSsl,

    [Parameter()]
    [System.Management.Automation.PSCredential]$SmtpCredential,

    [Parameter()]
    [string]$Server,

    [Parameter()]
    [ValidateRange(1, 525600)]
    [int]$LookbackMinutes = 60,

    [Parameter()]
    [ValidateRange(0, 1440)]
    [int]$OverlapMinutes = 15,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$StatePath = (Join-Path -Path $PSScriptRoot -ChildPath 'quarantine-state.json'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Subject = 'New quarantine computer objects detected'
)

$ErrorActionPreference = 'Stop'
$invariant = [System.Globalization.CultureInfo]::InvariantCulture

function ConvertTo-UtcDateTime {
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Utc) { return $Value }
        return $Value.ToUniversalTime()
    }

    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Value, $invariant, $styles, [ref]$parsed)) {
        return $parsed
    }

    return $null
}

function ConvertTo-LocalDisplayTime {
    param([datetime]$Value)

    if ($Value.Kind -eq [System.DateTimeKind]::Utc) { $Value = $Value.ToLocalTime() }
    return $Value.ToString('yyyy-MM-dd HH:mm:ss', $invariant)
}

function ConvertTo-HtmlText {
    param([object]$Value)

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Read-QuarantineState {
    param([string]$Path)

    $state = [pscustomobject]@{
        LastRunUtc = $null
        Reported   = @()
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return $state
    }

    try {
        $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        $state.LastRunUtc = ConvertTo-UtcDateTime -Value $json.LastRun

        if ($json.PSObject.Properties['Reported']) {
            $state.Reported = @(
                foreach ($entry in @($json.Reported)) {
                    if ($null -eq $entry -or -not $entry.ObjectGuid) { continue }
                    $whenCreatedUtc = ConvertTo-UtcDateTime -Value $entry.WhenCreated
                    if ($null -eq $whenCreatedUtc) { continue }
                    [pscustomobject]@{
                        ObjectGuid     = [string]$entry.ObjectGuid
                        WhenCreatedUtc = $whenCreatedUtc
                    }
                }
            )
        }
    }
    catch {
        Write-Warning "State file '$Path' could not be read ($($_.Exception.Message)). Using the lookback window."
        $state.LastRunUtc = $null
        $state.Reported = @()
        return $state
    }

    if ($null -eq $state.LastRunUtc) {
        Write-Warning "State file '$Path' has no valid LastRun value. Using the lookback window."
    }

    return $state
}

function Save-QuarantineState {
    param(
        [string]$Path,
        [datetime]$LastRunUtc,
        [object[]]$Reported
    )

    $directory = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $data = [ordered]@{
        LastRun  = $LastRunUtc.ToString('o', $invariant)
        Reported = @(
            foreach ($entry in @($Reported)) {
                if ($null -eq $entry) { continue }
                [ordered]@{
                    ObjectGuid  = $entry.ObjectGuid
                    WhenCreated = $entry.WhenCreatedUtc.ToString('o', $invariant)
                }
            }
        )
    }

    # Write to a temporary file first so an interrupted run cannot leave a truncated state file.
    $tempPath = "$Path.tmp"
    $data | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $tempPath -Encoding UTF8
    Move-Item -LiteralPath $tempPath -Destination $Path -Force
}

try {
    try {
        Import-Module -Name ActiveDirectory -ErrorAction Stop -Verbose:$false
    }
    catch {
        throw "The ActiveDirectory module is required (install RSAT or run on a domain controller). $($_.Exception.Message)"
    }

    $recipients = @($MailTo -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($recipients.Count -eq 0) {
        throw 'MailTo does not contain any recipient address.'
    }

    if ([string]::IsNullOrWhiteSpace($Server)) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    Write-Verbose "Querying domain controller '$Server'."

    $nowUtc = (Get-Date).ToUniversalTime()
    $state = Read-QuarantineState -Path $StatePath

    if ($null -ne $state.LastRunUtc) {
        $sinceUtc = $state.LastRunUtc
    }
    else {
        $sinceUtc = $nowUtc.AddMinutes(-1 * $LookbackMinutes)
    }

    $queryFromUtc = $sinceUtc.AddMinutes(-1 * $OverlapMinutes)
    $ldapFilter = '(whenCreated>={0})' -f $queryFromUtc.ToString('yyyyMMddHHmmss.0Z', $invariant)
    Write-Verbose "Searching '$QuarantineOU' with LDAP filter $ldapFilter."

    $reportedGuids = @{}
    foreach ($entry in $state.Reported) {
        $reportedGuids[$entry.ObjectGuid] = $true
    }

    $found = @(
        Get-ADComputer -Server $Server -SearchBase $QuarantineOU -SearchScope Subtree `
            -LDAPFilter $ldapFilter -Properties whenCreated, operatingSystem
    )

    $newComputers = @(
        $found |
            Where-Object { -not $reportedGuids.ContainsKey($_.ObjectGUID.ToString()) } |
            Sort-Object -Property whenCreated
    )

    # Keep only entries that the next run's overlap window can return again.
    $keepFromUtc = $nowUtc.AddMinutes(-1 * $OverlapMinutes)
    $reported = @($state.Reported | Where-Object { $_.WhenCreatedUtc -ge $keepFromUtc })

    if ($newComputers.Count -eq 0) {
        Save-QuarantineState -Path $StatePath -LastRunUtc $nowUtc -Reported $reported
        Write-Output "No new computer objects found since $(ConvertTo-LocalDisplayTime -Value $sinceUtc)."
        exit 0
    }

    $rows = foreach ($computer in $newComputers) {
        $os = if ($computer.operatingSystem) { $computer.operatingSystem } else { 'Unknown' }
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f `
            (ConvertTo-HtmlText -Value $computer.Name),
            (ConvertTo-HtmlText -Value (ConvertTo-LocalDisplayTime -Value $computer.whenCreated)),
            (ConvertTo-HtmlText -Value $os),
            (ConvertTo-HtmlText -Value $computer.DistinguishedName)
    }

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
<p>The following computer objects were created in <strong>$(ConvertTo-HtmlText -Value $QuarantineOU)</strong>
since <strong>$(ConvertTo-LocalDisplayTime -Value $sinceUtc)</strong>:</p>
<table>
<thead><tr><th>Name</th><th>Created</th><th>Operating System</th><th>Distinguished Name</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody>
</table>
<p>Please review these objects and move them to their correct OUs.</p>
</body>
</html>
"@

    $mailParams = @{
        From       = $MailFrom
        To         = $recipients
        Subject    = $Subject
        Body       = $emailBody
        BodyAsHtml = $true
        Encoding   = [System.Text.Encoding]::UTF8
        SmtpServer = $SmtpServer
        Port       = $SmtpPort
    }

    if ($UseSsl) { $mailParams.UseSsl = $true }
    if ($null -ne $SmtpCredential) { $mailParams.Credential = $SmtpCredential }

    Send-MailMessage @mailParams

    foreach ($computer in $newComputers) {
        $reported += [pscustomobject]@{
            ObjectGuid     = $computer.ObjectGUID.ToString()
            WhenCreatedUtc = ConvertTo-UtcDateTime -Value $computer.whenCreated
        }
    }

    Save-QuarantineState -Path $StatePath -LastRunUtc $nowUtc -Reported $reported
    Write-Output "Sent notification for $($newComputers.Count) computer object(s) to $($recipients -join ', ')."
    exit 0
}
catch {
    Write-Error -Message "Quarantine monitor failed; state was not updated. $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}

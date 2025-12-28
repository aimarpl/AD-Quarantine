# AD Quarantine Monitor

`Monitor-AdQuarantine.ps1` polls a designated Active Directory quarantine OU for newly created
computer objects and emails the AD Ops team so they can relocate the objects to their proper
OUs.

## Requirements
- PowerShell 5.1+ (or PowerShell 7 with compatibility for the ActiveDirectory module)
- ActiveDirectory PowerShell module (part of RSAT or a domain controller install)
- Permission to read the target OU and to relay mail through your SMTP server

## Usage
Run the script on a schedule (for example, Task Scheduler) with an account that can read the
quarantine OU and send mail. On the first run, the script looks back `LookbackMinutes` (default
60) to find recent computer objects. After each run it stores the last-run timestamp in a JSON
state file so only new objects trigger alerts.

```powershell
powershell.exe -File "C:\Scripts\Monitor-AdQuarantine.ps1" `
  -QuarantineOU "OU=Computer Quarantine,DC=example,DC=com" `
  -MailFrom "quarantine-monitor@example.com" `
  -MailTo "adops@example.com" `
  -SmtpServer "smtp.example.com" `
  -LookbackMinutes 15
```

### Optional parameters
- `-StatePath` — custom location for the JSON state file
- `-SmtpPort` — SMTP port (default 25)
- `-UseSsl` — enable TLS for SMTP
- `-SmtpCredential` — credentials for authenticated SMTP relays
- `-Subject` — custom email subject line

### Notes
- If the state file is missing or unreadable, the script falls back to the `LookbackMinutes`
  window.
- The email body lists computer name, creation time (local), operating system, and distinguished
  name for easy triage by AD Ops.

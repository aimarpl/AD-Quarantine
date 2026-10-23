# AD Quarantine Monitor

`Monitor-AdQuarantine.ps1` polls an Active Directory quarantine OU for newly created computer
objects and emails administrators, so the objects can be reviewed and moved to their proper OUs.

A typical setup redirects the default computer container to a dedicated OU with `redircmp.exe`
and runs this script on a schedule to report every new computer account that lands there.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- ActiveDirectory PowerShell module (RSAT or a domain controller installation)
- Permission to read the target OU and to relay mail through your SMTP server

## Usage

Run the script on a schedule (for example, Task Scheduler) with an account that can read the
quarantine OU and send mail.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Monitor-AdQuarantine.ps1" `
  -QuarantineOU "OU=Computer Quarantine,DC=example,DC=com" `
  -MailFrom "quarantine-monitor@example.com" `
  -MailTo "ad-admins@example.com,servicedesk@example.com" `
  -SmtpServer "smtp.example.com"
```

`-MailTo` accepts an array or a single comma- or semicolon-separated string. The string form is
needed with `powershell.exe -File`, which cannot pass PowerShell arrays.

### Optional parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `-Server` | PDC emulator | Domain controller to query; using one fixed DC keeps runs consistent |
| `-LookbackMinutes` | 60 | Search window when no usable state file exists (first run) |
| `-OverlapMinutes` | 15 | Extra window re-queried each run to catch late-replicated objects |
| `-StatePath` | `quarantine-state.json` next to the script | Location of the JSON state file |
| `-SmtpPort` | 25 | SMTP port |
| `-UseSsl` | off | Enable TLS for SMTP |
| `-SmtpCredential` | none | Credentials for authenticated SMTP relays |
| `-Subject` | `New quarantine computer objects detected` | Email subject line |

## How it works

- Each run searches the OU with a culture-independent LDAP filter on `whenCreated`, starting
  `OverlapMinutes` before the last successful run.
- Objects already reported (tracked by `objectGUID` in the state file) are skipped, so the overlap
  window does not cause duplicate alerts.
- The state file is updated only after the email has been sent. If the directory query or the email
  fails, the script exits with code 1 and the same objects are reported on the next run.
- All directory values are HTML-encoded in the email body.
- If the state file is missing or unreadable, the script falls back to the `LookbackMinutes`
  window.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success, with or without new objects |
| 1 | Failure; state was not updated |

### Notes

- `Send-MailMessage` is marked obsolete by Microsoft because it cannot guarantee a secure
  connection. It works with internal SMTP relays; use `-UseSsl` where the relay supports TLS.
- Objects that replicate to the queried domain controller later than `OverlapMinutes` after their
  creation can be missed; increase `-OverlapMinutes` in environments with long replication delays.

## License

[MIT](LICENSE)

# Encoded PowerShell Incident

## Summary

Microsoft Sentinel generated a High severity incident after detecting PowerShell execution with encoded command parameters.

---

## Alert Triggered

- Encoded PowerShell Execution

---

## Evidence Observed

- powershell.exe launched with -EncodedCommand
- Sysmon Event ID 1 collected
- Process execution visible in Sentinel incident timeline

---

## Investigation Steps

1. Reviewed process command line
2. Validated parent process
3. Confirmed encoded PowerShell execution
4. Checked for persistence or lateral movement behavior

---

## Outcome

Incident confirmed as simulated malicious activity generated during lab testing.

---

## Related Screenshots

- `screenshots/encoded-powershell-incident-details.png`
- `screenshots/advanced-hunting-encoded-powershell.png`

# Suspicious PowerShell Execution

## Objective

Detect potentially malicious PowerShell execution behavior that may indicate attacker activity.

---

## MITRE ATT&CK Mapping

- T1059.001 – PowerShell

---

## Severity

Medium

---

## Detection Logic

```kusto
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "powershell.exe"
| project TimeGenerated, Computer, RenderedDescription
```

---

## Data Source

- Sysmon Event ID 1
- Windows Security Events via AMA

---

## Trigger Condition

Alert triggers when PowerShell execution activity matches suspicious execution criteria.

---

## Investigation Notes

- Review executed PowerShell commands
- Validate user and process lineage
- Determine whether execution was administrative or malicious
- Check for encoded or obfuscated command usage

---

## Detection Result

Microsoft Sentinel generated a Medium severity incident after detecting suspicious PowerShell execution activity.

---

## Related Screenshots

- `screenshots/advanced-hunting-encoded-powershell.png`
- `screenshots/encoded-powershell-incident-details.png`

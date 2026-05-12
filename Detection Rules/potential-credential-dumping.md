# Potential Credential Dumping

## Objective

Detect suspicious process execution behavior associated with credential dumping techniques.

---

## MITRE ATT&CK Mapping

- T1003 – OS Credential Dumping

---

## Severity

High

---

## Detection Logic

```kusto
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "procdump"
   or RenderedDescription has "lsass"
| project TimeGenerated, Computer, RenderedDescription
```

---

## Data Source

- Sysmon Event ID 1
- Windows Security Events via AMA

---

## Trigger Condition

Alert triggers when processes associated with LSASS access or credential dumping are detected.

---

## Investigation Notes

- Verify legitimacy of process execution
- Review command-line arguments
- Identify affected host and user account
- Check for persistence or privilege escalation activity

---

## Detection Result

Microsoft Sentinel generated a High severity incident after detecting suspicious credential dumping behavior.

---

## Related Screenshots

- `screenshots/analytics-rules-overview.png`
- `screenshots/incidents-dashboard.png`

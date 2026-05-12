# Remote Service Creation Detection

## Objective

Detect remote service creation activity commonly associated with lateral movement techniques.

---

## MITRE ATT&CK Mapping

- T1021 – Remote Services

---

## Severity

High

---

## Detection Logic

```kusto
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "sc.exe"
   or RenderedDescription has "CreateService"
| project TimeGenerated, Computer, RenderedDescription
```


---

## Data Source

- Sysmon Event ID 1
- Windows Security Events via AMA

---

## Trigger Condition

Alert triggers when suspicious service creation activity is detected on monitored systems.

---

## Investigation Notes

- Review parent and child processes
- Identify initiating user account
- Validate whether service creation was authorized
- Check for additional lateral movement behavior

---

## Detection Result

Microsoft Sentinel generated a High severity incident after detecting remote service creation activity associated with lateral movement.

---

## Related Screenshots

- `screenshots/remote-service-incident.png`
- `screenshots/incidents-dashboard.png`

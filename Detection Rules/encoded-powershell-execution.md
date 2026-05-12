# Encoded PowerShell Execution

## Objective

Detect PowerShell launched with encoded commands commonly used to obfuscate malicious activity.

---

## MITRE ATT&CK Mapping

- T1059.001 – PowerShell
- T1027 – Obfuscated Files or Information

---

## Severity

High

---

## Detection Logic

```kusto
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "-EncodedCommand"
   or RenderedDescription has "-enc"
| project TimeGenerated, Computer, RenderedDescription
```

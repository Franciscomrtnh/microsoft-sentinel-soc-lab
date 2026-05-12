# Microsoft Sentinel SOC Lab

---

## Telemetry Collected

- Windows Security Events
- Sysmon Process Creation Events
- PowerShell Execution
- Failed Login Attempts
- Service Creation Events

---

## Detections Built

### 1. Excessive Failed Logins

Detects multiple failed login attempts.

MITRE ATT&CK:
- Credential Access

---

### 2. Encoded PowerShell Execution

Detects PowerShell launched using encoded commands.

MITRE ATT&CK:
- Execution
- PowerShell
- Defense Evasion
- Obfuscated Files or Information (T1027)

---

### 3. Remote Service Creation Detection

Detects suspicious service creation activity associated with lateral movement.

MITRE ATT&CK:
- Lateral Movement

---

### 4. Potential Credential Dumping

Detects suspicious access patterns associated with credential dumping.

MITRE ATT&CK:
- Credential Access

---

## Threat Hunting Queries

### Encoded PowerShell Detection

```kusto
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "-EncodedCommand"
   or RenderedDescription has "-enc"
| project TimeGenerated, Computer, RenderedDescription
```

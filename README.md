# Microsoft Sentinel SOC Lab

A cloud-based Security Operations Center (SOC) lab built using Microsoft Sentinel, Azure Monitor Agent (AMA), Sysmon, and Windows event telemetry to simulate real-world detection engineering, threat hunting, and incident investigation workflows.

---

# Lab Overview

This project demonstrates:

- Microsoft Sentinel deployment and configuration
- Windows telemetry ingestion using AMA + DCR
- Sysmon event collection and monitoring
- Custom analytics rule development
- Threat hunting with KQL
- MITRE ATT&CK mapped detections
- Incident generation and investigation
- SOC workflow simulation

---

# Environment Architecture

## Infrastructure

| Component | Purpose |
|---|---|
| Microsoft Sentinel | SIEM & Incident Management |
| Log Analytics Workspace | Centralized log storage |
| Azure Monitor Agent (AMA) | Telemetry collection |
| Data Collection Rule (DCR) | Event filtering and routing |
| Sysmon | Advanced Windows event logging |
| Windows Server (DC01) | Domain Controller |
| Windows Workstation (WS01) | User endpoint |

---

# Telemetry Collected

The lab collects and analyzes:

- Windows Security Events
- Sysmon Process Creation Events
- PowerShell Execution Activity
- Failed Login Attempts
- Service Creation Events
- Registry Modification Events
- Authentication Logs
- Process Execution Metadata

---

# Data Collection Pipeline

1. Sysmon installed on Windows endpoints
2. Azure Monitor Agent deployed
3. Data Collection Rules configured
4. Events forwarded to Log Analytics Workspace
5. Microsoft Sentinel connected to workspace
6. Analytics rules generate incidents automatically

---

# Microsoft Sentinel Configuration

## Configured Components

- Windows Security Events via AMA connector
- Data Collection Rules (DCR)
- Log Analytics Workspace
- Scheduled Analytics Rules
- Incident Creation Rules
- MITRE ATT&CK Mapping
- Advanced Hunting Queries

---

# Detection Rules Built

## 1. Excessive Failed Logins

Detects multiple failed authentication attempts that may indicate password spraying or brute force activity.

### MITRE ATT&CK
- Credential Access
- T1110 — Brute Force

### Severity
Medium

---

## 2. Encoded PowerShell Execution

Detects PowerShell executions using encoded commands commonly associated with obfuscation and malware execution.

### MITRE ATT&CK
- Execution
- Defense Evasion
- T1059.001 — PowerShell
- T1027 — Obfuscated Files or Information

### Severity
High

### Detection Logic

```kusto
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has "-EncodedCommand"
   or RenderedDescription has "-enc"
| project TimeGenerated, Computer, RenderedDescription
```

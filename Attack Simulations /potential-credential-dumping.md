## Objective

Simulate behavior associated with credential dumping and sensitive process access.

## Attack Technique

Attackers attempt to access credential material from LSASS memory to obtain account passwords and NTLM hashes.

## MITRE ATT&CK

- T1003 — OS Credential Dumping

## Simulation Performed

Suspicious process execution patterns related to credential dumping behavior were generated to validate detection logic.

## Detection Result

Microsoft Sentinel generated a High severity incident associated with credential access activity.

## Detection Triggered

- Potential Credential Dumping

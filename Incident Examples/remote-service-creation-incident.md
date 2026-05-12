# Remote Service Creation Incident

## Summary

Microsoft Sentinel generated a High severity incident after detecting suspicious remote service creation activity associated with lateral movement behavior.

---

## Alert Triggered

- Remote Service Creation Detection

---

## Evidence Observed

- Service creation activity detected through Sysmon telemetry
- Process execution associated with service management utilities
- Activity observed across monitored endpoints

---

## Investigation Steps

1. Reviewed process execution details
2. Validated initiating user and host
3. Investigated service creation behavior
4. Checked for additional lateral movement activity
5. Confirmed telemetry originated from lab attack simulation

---

## Outcome

Incident confirmed as simulated lateral movement activity generated to validate Microsoft Sentinel analytics rules.

---

## Related Screenshots

- `screenshots/remote-service-incident.png`
- `screenshots/incidents-dashboard.png`

# Excessive Failed Logins

## Objective

Detect repeated failed authentication attempts that may indicate brute-force or password spraying activity.

---

## MITRE ATT&CK Mapping

- T1110 – Brute Force

---

## Severity

Medium

---

## Detection Logic

```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account
| where FailedAttempts >= 5
```
```

---

## Data Source

- Windows Security Events via AMA
- Event ID 4625

---

## Trigger Condition

Alert triggers when multiple failed login attempts exceed the configured threshold.

---

## Investigation Notes

- Identify targeted accounts
- Review source host activity
- Check for successful logins following failures
- Validate if activity is expected administrative behavior

---

## Detection Result

Microsoft Sentinel generated a Medium severity incident after detecting excessive failed login attempts against a domain account.

---

## Related Screenshots

- `screenshots/excessive-failed-logins-incident.png`
- `screenshots/incidents-dashboard.png`

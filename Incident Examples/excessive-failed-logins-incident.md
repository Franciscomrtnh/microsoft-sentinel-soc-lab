# Excessive Failed Logins Incident

## Summary

Microsoft Sentinel generated a Medium severity incident after detecting multiple failed authentication attempts against a domain account.

---

## Alert Triggered

- Excessive Failed Logins

---

## Evidence Observed

- Multiple Windows Security Event ID 4625 logs detected
- Repeated failed authentication attempts against a domain user
- Activity exceeded the configured detection threshold

---

## Investigation Steps

1. Reviewed targeted user account
2. Checked failed authentication count
3. Verified source system activity
4. Investigated for successful logins following failed attempts
5. Confirmed activity was generated during attack simulation testing

---

## Outcome

Incident confirmed as simulated brute-force/password spraying activity performed during lab validation.

---

## Related Screenshots

- `screenshots/excessive-failed-logins-incident.png`
- `screenshots/incidents-dashboard.png`

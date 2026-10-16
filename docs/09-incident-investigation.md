# Incident Investigation

## Report structure

1. Alert summary and scope
2. Detection logic and triggering evidence
3. Timeline in UTC
4. Affected users, hosts, and services
5. Supporting queries
6. Findings and confidence
7. Containment or remediation recommendations
8. False-positive assessment
9. Lessons and detection improvements

Store only sanitized reports in `reports/`. Do not publish credentials, tokens, personal data or operational secrets. Synthetic or isolated RFC1918 lab addresses may remain when needed to explain evidence; redact real organizational topology and sensitive identifiers.

## Completed Investigation — SOC-WIN-001

### Investigation Summary

| Attribute | Finding |
|---|---|
| Investigation ID | SOC-WIN-001 |
| Title | Multiple Failed Windows Logon Attempts |
| Date | 15 October 2026 |
| Detection platform | Elastic Security 9.5.5 |
| Endpoint | windows-client |
| Windows Event ID | 4625 |
| Severity | Medium |
| MITRE ATT&CK | Credential Access (TA0006), Brute Force (T1110) |
| Classification | Benign Positive — Authorized Security Testing |
| Status | Closed |

### Detection and Validation

The investigation examined repeated failed Windows authentication
attempts generated during authorized laboratory testing.

The detection rule was configured to generate an alert when five
or more matching authentication failures targeted the same username
within the rule's search window.

Two controlled test scenarios produced alerts:

| Test | Target Username | Matching Events | Result |
|---|---|---|---|
| 1 | SOC-Test-Invalid | 5 | Alert generated |
| 2 | SOC-Test-Invalid_2 | 6 | Alert generated |

### Key Investigation Findings

The second test confirmed:

- Event ID: 4625 — Failed Windows authentication.
- Target username: SOC-Test-Invalid_2.
- Logon Type: 2 — Interactive.
- Source IP: ::1 — IPv6 loopback.
- Authentication process: seclogo.
- Authentication status: 0xC000006D.
- Authentication substatus: 0xC0000064.

The evidence was consistent with the authorized local authentication
tests. No malicious activity was established.

### Investigation Disposition

**Classification:** Benign Positive — Authorized Security Testing.

**Containment:** Not required.

**Remediation:** Not required for the simulated activity.

**Outcome:** Detection successfully validated against controlled local
authentication failures.

The investigated alert was closed after its findings were documented.

### Investigation Limitations

The exercise did not validate remote brute-force attacks.

Remote authentication testing from Kali Linux remains pending.

The original Windows Security events retained source IP information,
but the aggregated threshold alert did not preserve every source-event
field.

The source events remain available through Kibana Discover.

### Supporting Documentation

- [SOC-WIN-001 Detection Rule](../detection-rules/SOC-WIN-001.md)
- [SOC-WIN-001 Investigation Report](../reports/SOC-WIN-001-investigation.md)

### Next Investigation Objective

Conduct controlled remote authentication testing from Kali Linux.

Examine source IP attribution, Windows authentication event types,
threshold aggregation, and detection behavior across multiple accounts.

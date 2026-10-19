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

SOC-WIN-001 was validated using local authentication failures.

Remote authentication testing was outside the scope of this
investigation. That capability was subsequently validated
through SOC-WIN-002.

The original Windows Security events retained source IP information,
but the aggregated threshold alert did not preserve every source-event
field.

The source events remain available through Kibana Discover.

### Supporting Documentation

- [SOC-WIN-001 Detection Rule](../detection-rules/SOC-WIN-001.md)
- [SOC-WIN-001 Investigation Report](../reports/SOC-WIN-001-investigation.md)

## Completed Investigation — SOC-WIN-002

### Investigation Summary

| Attribute | Finding |
|---|---|
| Investigation ID | SOC-WIN-002 |
| Title | Multiple Remote Failed Logon Attempts |
| Date | 17 October 2026 |
| Detection platform | Elastic Security 9.5.5 |
| Source host | kali-linux |
| Source IP | 192.168.100.245 |
| Destination host | windows-client |
| Destination IP | 192.168.100.183 |
| Windows Event ID | 4625 |
| Logon type | 3 — Network |
| Severity | Medium |
| Risk score | 47 |
| MITRE ATT&CK | Credential Access (TA0006), Brute Force (T1110) |
| Classification | Benign Positive — Authorized Security Testing |
| Status | Closed |

### Detection and Validation

SOC-WIN-002 detects repeated failed Windows network authentication
attempts originating from the same source IP.

The detection uses Windows Security Event ID 4625,
Logon Type 3, and groups matching events by `source.ip`.

The configured threshold is five matching events.

The rule executes every five minutes with an additional
one-minute look-back.

A controlled RDP/NLA authentication test was performed
from Kali Linux against the Windows client.

The test used a deliberately nonexistent username and
a disposable incorrect password.

Five authentication failures were generated.

### Investigation Timeline

The laboratory operates in West Africa Time (WAT, UTC+01:00).

| Local time (WAT) | UTC | Event |
|---|---|---|
| 2026-10-17 17:36:59 | 2026-10-17 16:36:59 | First failed authentication attempt |
| 2026-10-17 17:37:05 | 2026-10-17 16:37:05 | Second failed authentication attempt |
| 2026-10-17 17:37:10 | 2026-10-17 16:37:10 | Third failed authentication attempt |
| 2026-10-17 17:37:15 | 2026-10-17 16:37:15 | Fourth failed authentication attempt |
| 2026-10-17 17:37:21 | 2026-10-17 16:37:21 | Fifth failed authentication attempt |
| 2026-10-17 17:40:15 | 2026-10-17 16:40:15 | Elastic Security threshold alert generated |

The five authentication attempts occurred within approximately
22 seconds.

The alert was generated approximately three minutes after
the final authentication attempt.

These times represent this laboratory exercise and do not
establish a guaranteed production detection latency.

### Key Investigation Findings

The investigation established:

- Five failed RDP/NLA authentication attempts occurred.
- Windows Security Event ID 4625 was recorded.
- Logon Type 3 identified network authentication.
- The originating IP was `192.168.100.245`.
- Elastic Agent successfully forwarded the authentication telemetry.
- Elastic Security generated the SOC-WIN-002 threshold alert.
- The threshold result count was five.
- The alert grouping value was `192.168.100.245`.

### Successful Authentication Investigation

Windows Security Event ID 4624 was examined for:

- Source IP: `192.168.100.245`
- Logon Type: 3
- Local investigation window: 17:30–18:00 on 2026-10-17

No matching successful network logon events were found.

This conclusion applies only to the specified investigation
criteria and time window.

### Investigation Disposition

**Detection validity:** True Positive.

**Activity classification:** Benign Positive — Authorized Security Testing.

**Containment:** Not required.

**Remediation:** Not required for the simulated activity.

**Outcome:** SOC-WIN-002 successfully detected repeated
remote authentication failures from the same source IP.

The alert was closed after the investigation notes were recorded.

### Investigation Limitations

- Windows Logon Type 3 is not exclusive to RDP.
- Source-IP grouping may combine clients behind shared NAT.
- Distributed attacks across several IPs may evade the threshold.
- Slow authentication attempts may fall outside the detection window.
- Production false-positive tuning has not been completed.
- The current detection query is restricted to `windows-client`.

### Supporting Documentation

- [SOC-WIN-002 Detection Rule](../detection-rules/SOC-WIN-002.md)
- [SOC-WIN-002 Investigation Report](../reports/SOC-WIN-002-investigation.md)

## Next Investigation Objectives

Future investigations will focus on:

1. Failed-to-successful authentication correlation.
2. Distributed password-spraying detection.
3. Linux SSH authentication monitoring.
4. Cross-host authentication analysis.
5. AI-assisted SOC alert triage.

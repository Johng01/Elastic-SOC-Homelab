# Investigation Evidence

Add sanitized alert timelines, supporting queries, findings, and response evidence using the convention in [the screenshot guide](../README.md).

## SOC-WIN-001 — Windows Authentication Investigation

This evidence documents the investigation of controlled Windows
authentication failures detected by SOC-WIN-001.

### Evidence Register

| Evidence | Description |
|---|---|
| [Windows authentication events](investigation-001-windows-4625-events.png) | Shows six Windows Security Event ID 4625 records associated with SOC-Test-Invalid_2. |
| [Source IP verification](investigation-002-source-ip.png) | Confirms the IPv6 loopback address ::1 in the source.ip field of an original Windows authentication event. |

### Investigation Summary

- Detection rule: SOC-WIN-001.
- Target account: SOC-Test-Invalid_2.
- Matching authentication events: Six.
- Windows event ID: 4625.
- Logon type: 2 — Interactive.
- Source IP: ::1 — IPv6 loopback.
- Authentication status: 0xC000006D.
- Authentication substatus: 0xC0000064.
- Classification: Benign Positive — Authorized Security Testing.
- Disposition: Investigated test alert closed.

### Evidence Interpretation

The screenshots demonstrate that Elasticsearch collected the original
Windows authentication events, including the source IP address.

The threshold detection alert aggregates matching authentication
events and does not necessarily retain every original event field.

The screenshots support controlled local authentication detection.
They do not demonstrate a remote brute-force attack.

### Supporting Documentation

- [Full Investigation Report](../../reports/SOC-WIN-001-investigation.md)
- [Detection Rule](../../detection-rules/SOC-WIN-001.md)
- [Detection Evidence](../05-detection/README.md)

## SOC-WIN-002 — Remote Authentication Investigation

This evidence documents controlled RDP/NLA authentication failures
originating from Kali Linux and detected by SOC-WIN-002.

### Evidence Register

| Evidence | Description |
|---|---|
| [Remote authentication event](investigation-003-soc-win-002-authentication.png) | Confirms Windows Event ID 4625, source IP 192.168.100.245, the test username, and Logon Type 3. |
| [Threshold detection alert](investigation-004-soc-win-002-threshold-alert.png) | Shows the SOC-WIN-002 alert, source IP, threshold count of five, and risk score of 47. |
| [Detection rule definition](investigation-005-soc-win-002-rule-definition.png) | Shows the detection query, threshold configuration, execution schedule, severity, and MITRE ATT&CK mapping. |

### Investigation Summary

- Detection rule: SOC-WIN-002.
- Source system: Kali Linux.
- Source IP: `192.168.100.245`.
- Destination: `windows-client` (`192.168.100.183`).
- Authentication method: RDP with Network Level Authentication.
- Windows Event ID: 4625.
- Logon Type: 3 — Network.
- Test username: `SOC-Test-Remote-Invalid`.
- Failed authentication attempts: Five.
- Threshold grouping field: `source.ip`.
- Alert threshold count: Five.
- Alert generated: 2026-10-17 17:40:15 WAT.
- Classification: True Positive Detection — Benign Positive Activity.
- Final disposition: Authorized Security Testing.
- Alert status: Closed.

### Evidence Interpretation

The authentication screenshot confirms that Windows recorded a
failed network authentication attempt originating from Kali Linux.

The threshold alert screenshot demonstrates that Elastic Security
detected five matching events grouped by source IP.

The rule-definition screenshot documents the KQL query, detection
threshold, scheduling, and MITRE ATT&CK mapping.

The threshold alert screenshot was captured while the alert was
still Open. Its subsequent closure is documented in the
investigation report and Elastic Security investigation notes.

A review of Windows Security Event ID 4624 found no matching
successful network logons from the test source during the
investigated 17:30–18:00 WAT window.

The activity was authorized laboratory testing, not a confirmed
malicious attack.

### Supporting Documentation

- [SOC-WIN-002 Investigation Report](../../reports/SOC-WIN-002-investigation.md)
- [SOC-WIN-002 Detection Rule](../../detection-rules/SOC-WIN-002.md)
- [Detection Engineering](../../docs/08-detection-engineering.md)

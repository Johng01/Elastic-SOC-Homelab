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

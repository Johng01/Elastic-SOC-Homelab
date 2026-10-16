# Investigation Reports

Store sanitized investigation reports here. Use the structure in [Incident Investigation](../docs/09-incident-investigation.md) and exclude secrets and personal data.

## Completed SOC Investigations

| Case ID | Investigation | Classification | Status |
|---|---|---|---|
| [SOC-WIN-001](SOC-WIN-001-investigation.md) | Multiple Failed Windows Logon Attempts | Benign Positive — Authorized Security Testing | Closed |

### SOC-WIN-001 — Multiple Failed Logon Attempts

**Investigation date:** 15 October 2026

**Detection platform:** Elastic Security 9.5.5

**Affected endpoint:** `windows-client`

**Detection rule:** `SOC-WIN-001`

**MITRE ATT&CK:** Credential Access (TA0006), Brute Force (T1110)

#### Investigation Summary

Elastic Security generated alerts after repeated failed Windows
authentication attempts were performed during authorized laboratory testing.

Two controlled tests were completed:

- Test 1: `SOC-Test-Invalid` — 5 matching events.
- Test 2: `SOC-Test-Invalid_2` — 6 matching events.

The investigation confirmed Windows Security Event ID 4625,
Logon Type 2, and the IPv6 loopback source address `::1`.

The activity was classified as authorized security testing.

No malicious activity was established.

The investigated alert was closed after documenting the findings.

#### Supporting Documentation

- [Full Investigation Report](SOC-WIN-001-investigation.md)
- [Detection Rule](../detection-rules/SOC-WIN-001.md)
- [Incident Investigation Methodology](../docs/09-incident-investigation.md)

#### Remaining Validation

Remote authentication testing from Kali Linux and source-IP-based
detection engineering remain pending.

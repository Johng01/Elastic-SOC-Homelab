# Elastic Detection Rules

Store exported or manually documented Elastic Security rules here. Each rule must include its purpose, data requirements, query, schedule, severity, MITRE ATT&CK mapping, test evidence, known false positives, and tuning history.

## Validated Detection Rules

| Rule ID | Detection | Platform | Status |
|---|---|---|---|
| [SOC-WIN-001](SOC-WIN-001.md) | Multiple Failed Logon Attempts | Windows | Validated — Local Authentication |

### SOC-WIN-001 — Multiple Failed Logon Attempts

**Detection objective:** Identify repeated Windows authentication failures against the same target username.

**Detection configuration:**

- Rule type: Threshold
- Data source: `logs-system.security-default`
- Windows Security Event ID: `4625`
- Threshold: Five or more matching events per target username
- Execution interval: Five minutes
- Additional look-back: One minute
- Severity: Medium
- MITRE ATT&CK: Credential Access (TA0006), Brute Force (T1110)

**Validation results:**

Two controlled local authentication tests successfully generated alerts.

- Test 1: `SOC-Test-Invalid` — 5 matching events.
- Test 2: `SOC-Test-Invalid_2` — 6 matching events.

The investigated activity was classified as authorized security testing.

**Limitations:** Remote authentication testing, source-IP-based detection,
and production-like false-positive tuning remain pending.

### Supporting Documentation

- [Detection Rule and Configuration](SOC-WIN-001.md)
- [SOC Investigation Report](../reports/SOC-WIN-001-investigation.md)
- [Detection Engineering Methodology](../docs/08-detection-engineering.md)
- [Incident Investigation Methodology](../docs/09-incident-investigation.md)

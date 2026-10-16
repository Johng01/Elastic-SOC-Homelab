# Detection Evidence

Add sanitized rule configuration, controlled test, alert, and tuning evidence using the convention in [the screenshot guide](../README.md).

## SOC-WIN-001 — Windows Failed Logon Detection

The following evidence supports the validation of SOC-WIN-001,
a threshold rule detecting repeated Windows Security Event ID 4625
authentication failures.

| Evidence | Description |
|---|---|
| [Detection rule configuration](detection-001-windows-4625-rule.png) | Shows the Security data stream, threshold rule type, username grouping, and threshold value of five. |
| [Successful rule execution](detection-002-rule-execution-success.png) | Shows successful scheduled executions and alert generation. |
| [Threshold alert](detection-003-threshold-alert.png) | Shows a generated Medium-severity alert grouped by the test username SOC-Test-Invalid. |

### Validation Summary

- Rule ID: SOC-WIN-001.
- Detection platform: Elastic Security 9.5.5.
- Event source: Windows Security Event ID 4625.
- Threshold: Five or more matching failed logons per target username.
- Validation: Successful controlled local authentication testing.
- Remote authentication testing: Pending.

### Related Documentation

- [Detection Rule](../../detection-rules/SOC-WIN-001.md)
- [Investigation Report](../../reports/SOC-WIN-001-investigation.md)
- [Investigation Evidence](../06-investigations/README.md)

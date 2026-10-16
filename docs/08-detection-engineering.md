# Detection Engineering

## Method

Every detection must document the hypothesis, required data, query,
threshold, look-back interval, severity, MITRE ATT&CK mapping,
expected false positives, test procedure, and tuning decision.

Detection validation must distinguish between local authentication
testing and remote attack simulation.

## Detection Backlog

| Use case | Primary signal | State |
|---|---|---|
| Windows failed-logon burst | Event ID 4625 | Validated — Local Authentication |
| Linux SSH brute force | Repeated authentication failures | Planned |
| Privilege escalation | Windows privilege events / Linux sudo | Planned |
| Suspicious process execution | Sysmon/process telemetry | Planned |
| Web reconnaissance | Repeated 4xx patterns and suspicious paths | Planned |

## Validated Detection Rules

### SOC-WIN-001 — Multiple Failed Logon Attempts

**Status:** Validated against controlled local authentication failures.

**Platform:** Windows Enterprise Evaluation.

**Detection engine:** Elastic Security 9.5.5.

**Data stream:** `logs-system.security-default`

**Event ID:** 4625.

**Rule type:** Threshold.

**Detection threshold:** Five or more failed authentication events
grouped by target username.

**Execution interval:** Five minutes.

**Additional look-back:** One minute.

**Severity:** Medium.

**MITRE ATT&CK:** Credential Access (TA0006), Brute Force (T1110).

### Validation Results

| Test | Target username | Matching events | Result |
|---|---|---|---|
| Test 1 | SOC-Test-Invalid | 5 | Alert generated |
| Test 2 | SOC-Test-Invalid_2 | 6 | Alert generated |

Both tests successfully generated threshold alerts.

The second investigation verified:

- Event ID 4625.
- Logon Type 2.
- Source IP `::1`.
- Authentication process `seclogo`.
- Status `0xC000006D`.
- Substatus `0xC0000064`.

The activity was classified as authorized security testing.

### Documentation

Detection rule:

[View SOC-WIN-001](../detection-rules/SOC-WIN-001.md)

Investigation report:

[View SOC-WIN-001 Investigation](../reports/SOC-WIN-001-investigation.md)

### Known Limitations

- Remote authentication testing from Kali Linux remains pending.
- The rule groups authentication failures by username, not source IP.
- Threshold alerts do not necessarily preserve all source-event fields.
- The original event documents retain source IP information.
- The five-minute execution interval and one-minute additional
  look-back do not constitute an exact five-minute sliding window.
- The current query is restricted to `windows-client`.

### Future Detection Engineering

SOC-WIN-002 will focus on remote Windows authentication failures,
source-IP correlation, and controlled testing originating from Kali Linux.

## Quality Gate

A rule is not "complete" merely because it saves successfully.

It must:

1. Fire on controlled test activity.
2. Avoid obvious benign noise.
3. Link to supporting evidence.
4. Include a response workflow.
5. Document known limitations.
6. Record the investigation outcome.
7. Identify remaining validation requirements.

SOC-WIN-001 has passed controlled local detection testing.

Remote attack simulation and production-like false-positive tuning
remain future validation activities.

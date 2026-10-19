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
| Windows remote failed-logon burst | Event ID 4625, Logon Type 3, source IP | Validated — Remote Authentication |
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

- SOC-WIN-001 was validated using local authentication; remote source-IP detection is covered separately by SOC-WIN-002.
- The rule groups authentication failures by username, not source IP.
- Threshold alerts do not necessarily preserve all source-event fields.
- The original event documents retain source IP information.
- The five-minute execution interval and one-minute additional
  look-back do not constitute an exact five-minute sliding window.
- The current query is restricted to `windows-client`.

## SOC-WIN-002 — Multiple Remote Failed Logon Attempts

**Status:** Validated against controlled remote RDP/NLA authentication failures.

**Platform:** Windows Enterprise Evaluation.

**Detection engine:** Elastic Security 9.5.5.

**Data stream:** `logs-system.security-default`

**Event ID:** 4625.

**Logon Type:** 3 — Network.

**Rule type:** Threshold.

**Detection threshold:** Five or more matching events grouped by `source.ip`.

**Execution interval:** Five minutes.

**Additional look-back:** One minute.

**Severity:** Medium.

**Risk score:** 47.

**MITRE ATT&CK:** Credential Access (TA0006), Brute Force (T1110).

### SOC-WIN-002 Validation Results

| Test | Source IP | Matching events | Result |
|---|---|---|---|
| Controlled RDP/NLA authentication failures | 192.168.100.245 | 5 | Alert generated |

The test generated five failed authentication attempts from Kali Linux
between approximately 17:36:59 and 17:37:21 on 2026-10-17.

Elastic Security generated the threshold alert at approximately 17:40:15.

The alert identified `192.168.100.245` as the originating IP address
and recorded a threshold count of five.

A review of Windows Event ID 4624 found no matching successful
network logons from this IP during 17:30–18:00.

**Final disposition:** True positive detection of benign,
authorized security-testing activity. Alert closed.

### SOC-WIN-002 Documentation

Detection rule:

[View SOC-WIN-002](../detection-rules/SOC-WIN-002.md)

Investigation report:

[View SOC-WIN-002 Investigation](../reports/SOC-WIN-002-investigation.md)

### SOC-WIN-002 Known Limitations

- Windows Logon Type 3 is not exclusive to RDP.
- Grouping by source IP may combine users behind a shared NAT address.
- Distributed authentication attempts across multiple source IPs may
  evade the per-IP threshold.
- Slow attempts outside the evaluation window may not trigger an alert.
- The current query is restricted to `windows-client`.
- Production false-positive tuning remains outstanding.

### Future Detection Engineering

Future work will investigate distributed password spraying,
failed-to-successful authentication correlation, additional Windows
endpoints, and AI-assisted SOC alert triage.

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

SOC-WIN-001 has passed controlled local authentication testing.

SOC-WIN-002 has passed controlled remote authentication testing
using Kali Linux and Windows RDP/NLA.

Production-like false-positive tuning and broader multi-host
validation remain future activities.

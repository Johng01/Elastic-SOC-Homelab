# Detection Engineering

## Method

Every detection must document the hypothesis, required data, query, threshold, look-back interval, severity, MITRE ATT&CK mapping, expected false positives, test procedure, and tuning decision.

## Initial backlog

| Use case | Primary signal | State |
|---|---|---|
| Windows failed-logon burst | Event ID 4625 | Planned |
| Linux SSH brute force | Repeated authentication failures | Planned |
| Privilege escalation | Windows privilege events / Linux sudo | Planned |
| Suspicious process execution | Sysmon/process telemetry | Planned |
| Web reconnaissance | Repeated 4xx patterns and suspicious paths | Planned |

## Quality gate

A rule is not “complete” merely because it saves successfully. It must fire on controlled test activity, avoid obvious benign noise, link to evidence, and include a response workflow.

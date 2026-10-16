# SOC-WIN-001 — Multiple Failed Logon Attempts

## 1. Detection Overview

| Attribute | Value |
|---|---|
| Rule ID | SOC-WIN-001 |
| Rule name | Multiple Failed Logon Attempts |
| Platform | Windows Enterprise Evaluation |
| Detection engine | Elastic Security 9.5.5 |
| Rule type | Threshold |
| Data source | Windows Security Event Log |
| Event ID | 4625 |
| Severity | Medium |
| Risk score | 47 |
| MITRE ATT&CK tactic | Credential Access (TA0006) |
| MITRE ATT&CK technique | Brute Force (T1110) |
| Validation status | Passed — controlled local authentication tests |

## 2. Detection Objective

Identify repeated failed Windows authentication attempts targeting the same username.

Five or more matching authentication failures within the configured rule search
window generate a detection alert.

This is a laboratory detection threshold, not a production baseline.

## 3. Data Source

Elasticsearch data stream: `logs-system.security-default`

Event provider: `Microsoft-Windows-Security-Auditing`

Windows Security Event ID: `4625 — An account failed to log on`

## 4. Detection Query

```kql
host.name : "windows-client" and
event.code : "4625" and
winlog.channel : "Security" and
winlog.provider_name : "Microsoft-Windows-Security-Auditing"
```

## 5. Threshold Configuration

| Setting | Value |
|---|---|
| Group by | winlog.event_data.TargetUserName |
| Threshold | 5 or more matching events |
| Count | All results |
| Unique values | Not configured |
| Execution interval | 5 minutes |
| Additional look-back | 1 minute |
| Alert suppression | Disabled |

The rule executes every five minutes with a one-minute additional look-back.

This produces an approximately six-minute query window, not an exact
five-minute sliding detection window.

## 6. Test Environment

| Component | Configuration |
|---|---|
| SIEM server | elastic-siem |
| Windows endpoint | windows-client |
| Windows IP | 192.168.100.183 during testing |
| Elasticsearch/Fleet Server IP | 192.168.100.104 during testing |
| Elastic Agent | 9.5.5 |
| Windows agent policy | windows-soc-policy |
| Network | Isolated lab-net |

## 7. Validation Procedure

Controlled failed authentication attempts were generated using:

```cmd
runas /user:windows-client\SOC-Test-Invalid cmd
```

The test was repeated using a second invalid username:

```cmd
runas /user:windows-client\SOC-Test-Invalid_2 cmd
```

Incorrect passwords were supplied interactively.

No password values are included in this repository.

## 8. Validation Results

| Test | Target account | Matching events | Result |
|---|---|---|---|
| Test 1 | SOC-Test-Invalid | 5 | Alert generated |
| Test 2 | SOC-Test-Invalid_2 | 6 | Alert generated |

Both tests confirmed that the rule detected repeated authentication failures
grouped by targeted username.

## 9. Investigation Findings

The second test produced Windows Security Event ID 4625 with:

| Field | Value |
|---|---|
| Target username | SOC-Test-Invalid_2 |
| Logon type | 2 — Interactive |
| Source IP | ::1 |
| Authentication package | Negotiate |
| Logon process | seclogo |
| Status | 0xC000006D |
| Substatus | 0xC0000064 |
| Failure reason | Unknown username or bad password |

The address `::1` identifies the IPv6 loopback interface.

This was a controlled local authentication simulation, not a remote brute-force attack.

## 10. Detection Limitations

1. The rule has been validated against local authentication failures only.
2. Remote authentication testing from Kali Linux remains pending.
3. Threshold alerts may not retain all original Windows Security event fields.
4. The underlying Elasticsearch events retain the source IP in `source.ip`.
5. The rule groups by target username rather than source IP.
6. Authentication failures across multiple usernames require additional detection logic.
7. The rule is currently restricted to `windows-client`.
8. The execution schedule does not implement an exact five-minute rolling window.

## 11. Investigation Disposition

Classification: Authorized Security Testing.

Outcome: Benign Positive.

No malicious activity was established.

The investigated test alert was closed after the findings were documented.

## 12. Future Improvements

- Validate remote authentication attempts originating from Kali Linux.
- Develop source-IP-based authentication detection.
- Compare local and remote Windows authentication events.
- Investigate source-IP aggregation and alert context.
- Evaluate detection thresholds against realistic background activity.
- Add screenshots and a formal investigation report.

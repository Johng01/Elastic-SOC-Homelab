# SOC Investigation Report — SOC-WIN-001

## 1. Case Information

| Field | Value |
|---|---|
| Case ID | SOC-WIN-001 |
| Investigation title | Multiple Failed Windows Logon Attempts |
| Investigation date | 15 October 2026 |
| Environment | Elastic SOC Homelab |
| Detection platform | Elastic Security 9.5.5 |
| Endpoint | windows-client |
| Detection severity | Medium |
| Risk score | 47 |
| MITRE ATT&CK | TA0006 — Credential Access |
| ATT&CK technique | T1110 — Brute Force |
| Final classification | Benign Positive — Authorized Security Testing |
| Investigation status | Closed |

## 2. Executive Summary

Elastic Security generated alerts after repeated Windows authentication
failures were recorded against deliberately invalid user accounts.

The activity was generated during authorized SOC homelab testing.

The Windows endpoint forwarded Security Event ID 4625 records through
Elastic Agent to Elasticsearch.

A threshold detection rule identified repeated authentication failures
against the same target username.

The investigation established that the activity originated locally
and did not represent a confirmed external attack.

No malicious activity was established.

## 3. Environment

| Component | Description |
|---|---|
| SIEM | Elasticsearch and Kibana |
| Fleet Server | elastic-siem |
| Windows endpoint | windows-client |
| Elastic Agent | Version 9.5.5 |
| Agent policy | windows-soc-policy |
| Security data stream | logs-system.security-default |
| Network | Isolated lab-net |

## 4. Detection Rule

Rule name:

SOC-WIN-001 — Multiple Failed Logon Attempts

Rule type:

Threshold

Detection query:

```kql
host.name : "windows-client" and
event.code : "4625" and
winlog.channel : "Security" and
winlog.provider_name : "Microsoft-Windows-Security-Auditing"
```

Threshold configuration:

| Setting | Value |
|---|---|
| Group by | winlog.event_data.TargetUserName |
| Minimum event count | 5 |
| Execution interval | 5 minutes |
| Additional look-back | 1 minute |
| Alert severity | Medium |
| Risk score | 47 |

## 5. Test Methodology

Two controlled authentication scenarios were executed on windows-client.

### Test 1

Target username:

SOC-Test-Invalid

Command:

```cmd
runas /user:windows-client\SOC-Test-Invalid cmd
```

Incorrect credentials were supplied interactively.

Result:

Five matching authentication failures were observed in the threshold
alert.

Elastic Security successfully generated an alert.

### Test 2

Target username:

SOC-Test-Invalid_2

Command:

```cmd
runas /user:windows-client\SOC-Test-Invalid_2 cmd
```

Incorrect credentials were supplied interactively.

Result:

Six matching authentication failures were observed.

The threshold alert and Kibana Discover both showed six matching events
for the test account.

The additional event was not independently attributed to a specific
command execution.

## 6. Windows Security Event Analysis

A Windows Security Event ID 4625 from the second test was inspected
directly using PowerShell.

Verified event information:

| Field | Observed Value |
|---|---|
| Event ID | 4625 |
| Computer | windows-client |
| Target username | SOC-Test-Invalid_2 |
| Initiating account | cybersafe |
| Logon type | 2 |
| Source network address | ::1 |
| Source port | 0 |
| Authentication package | Negotiate |
| Logon process | seclogo |
| Status | 0xC000006D |
| Substatus | 0xC0000064 |
| Caller process | C:\Windows\System32\svchost.exe |

### Interpretation

Event ID 4625 indicates failed authentication.

Logon Type 2 identifies an interactive authentication attempt.

The source address ::1 is the IPv6 loopback address, indicating
local-origin authentication activity.

Status 0xC000006D indicates authentication failure.

Substatus 0xC0000064 indicates that the specified username
does not exist.

These findings are consistent with the authorized runas tests.

## 7. Elasticsearch Evidence

Kibana Discover confirmed that Windows Security events were indexed
successfully.

The following fields were verified:

- host.name
- event.code
- winlog.channel
- winlog.provider_name
- winlog.event_data.TargetUserName
- source.ip

The source.ip field contained the IPv6 loopback address ::1.

The original Windows events retained authentication information
necessary for investigation.

## 8. Alert Analysis

Elastic Security generated threshold alerts for both test accounts.

| Test | Target account | Matching events | Alert generated |
|---|---|---|---|
| 1 | SOC-Test-Invalid | 5 | Yes |
| 2 | SOC-Test-Invalid_2 | 6 | Yes |

For the second test, the alert contained:

- kibana.alert.threshold_result.count: 6
- kibana.alert.threshold_result.terms.field:
  winlog.event_data.TargetUserName
- kibana.alert.threshold_result.terms.value:
  SOC-Test-Invalid_2

The threshold aggregation correctly identified the target username.

Some source-event fields, including source.ip, were not available
as individual fields in the threshold alert.

Those values remained accessible in Discover.

## 9. Scope and Limitations

The exercise validated local interactive authentication detection.

It did not validate:

- Remote brute-force authentication.
- Authentication originating from Kali Linux.
- Source-IP-based threshold detection.
- Password spraying across multiple usernames.
- Detection performance under realistic production traffic.

The threshold rule executes every five minutes with one additional
minute of look-back.

This should not be described as an exact five-minute sliding window.

The observed six-event count in Test 2 was confirmed in Elasticsearch,
but its precise cause was not independently established.

## 10. Final Assessment

The investigation identified repeated failed authentication attempts
generated during authorized laboratory testing.

The activity matched the configured threshold detection rule.

The evidence supports a benign-positive classification.

There is no evidence from this exercise of unauthorized access,
credential compromise, or a remote brute-force attack.

## 11. Disposition

Classification:

Benign Positive — Authorized Security Testing

Containment:

Not required.

Remediation:

Not required for the simulated activity.

Detection outcome:

Successful.

Investigation outcome:

Completed.

The investigated test alert was closed after the findings were
documented.

## 12. Recommendations

1. Preserve SOC-WIN-001 as the validated local authentication rule.
2. Test remote authentication activity from Kali Linux.
3. Create a separate source-IP-focused detection rule.
4. Compare Windows Logon Types 2, 3, and 10.
5. Investigate authentication failures involving multiple usernames.
6. Evaluate detection thresholds against realistic background activity.
7. Preserve sanitized screenshots of the detection and investigation.

## 13. Evidence Register

The following evidence should be retained in the repository:

| Evidence ID | Description |
|---|---|
| SOC-WIN-001-E01 | Detection rule configuration |
| SOC-WIN-001-E02 | Successful rule execution |
| SOC-WIN-001-E03 | First generated alert |
| SOC-WIN-001-E04 | Second generated alert |
| SOC-WIN-001-E05 | Threshold grouping and count |
| SOC-WIN-001-E06 | Discover authentication events |
| SOC-WIN-001-E07 | Original Windows Event ID 4625 |
| SOC-WIN-001-E08 | Investigation note and closed alert |

Evidence screenshots must be reviewed for passwords, tokens,
credentials, and other sensitive information before publication.

## 14. Conclusion

SOC-WIN-001 successfully demonstrated Windows authentication telemetry
collection, threshold detection, alert investigation, and incident
disposition within the Elastic SOC Homelab.

The next technical milestone is controlled remote authentication
testing from Kali Linux and source-IP-based detection engineering.

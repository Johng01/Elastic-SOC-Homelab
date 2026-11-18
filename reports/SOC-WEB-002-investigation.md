# SOC-WEB-002 — Repeated HTTP 404 Responses and Directory Enumeration

## 1. Executive Summary

**Investigation Date:** November 18, 2026

**Rule ID:** SOC-WEB-002

**Rule Name:** Repeated HTTP 404 Responses and Directory Enumeration

**Detection Type:** Threshold Rule with URL-Path Cardinality

**Classification:** True Positive — Benign

**Alert Disposition:** Closed

**Investigation Status:** Completed

SOC-WEB-002 successfully detected a controlled HTTP resource-enumeration simulation against the Ubuntu SOC Homelab Nginx web server.

The detection rule was designed to identify at least 10 HTTP 404 responses involving at least five distinct requested URL paths from the same source IP against the same monitored hostname within the configured evaluation window.

Two controlled validation scenarios were conducted.

The negative test generated 12 HTTP 404 responses involving one distinct URL path. Elasticsearch ingested all 12 events, but SOC-WEB-002 generated no alert during the relevant successful rule execution.

The positive test generated 12 HTTP 404 responses involving six distinct URL paths. Elasticsearch ingested the requests, and Elastic Security subsequently generated one threshold alert.

The generated alert independently reported:

- Matching event count: 12.
- Cardinality field: `url.path`.
- Cardinality value: 6.
- Source IP: `192.168.100.245`.
- Target hostname: `ubuntu-soc-target`.

The simulation originated from the authorized Kali Linux laboratory machine.

All tested resources returned HTTP `404 Not Found`.

No successful access to the requested resources or unauthorized compromise was established.

The alert was investigated, documented, classified as **True Positive — Benign**, and closed.

**Final validation result: PASSED for the tested laboratory scenarios.**

---

## 2. Laboratory Environment

| Component | Configuration |
|---|---|
| SIEM | Elastic Security |
| Elasticsearch | 9.5.5 |
| Target hostname | ubuntu-soc-target |
| Target operating system | Ubuntu Server 24.04.5 LTS |
| Target IP address | 192.168.100.226 |
| Web server | Nginx 1.24.0 |
| Web service | HTTP / TCP 80 |
| Attack simulation platform | Kali Linux |
| Simulation source IP | 192.168.100.245 |
| Laboratory network | 192.168.100.0/24 |
| Elastic Agent | 9.5.5 |
| Nginx integration | 3.2.2 |
| Agent policy | linux-soc-policy |
| Integration policy | nginx-web-security-monitoring |
| Nginx access log | /var/log/nginx/access.log |
| Event dataset | nginx.access |
| Elasticsearch data stream | logs-nginx.access-default |
| Detection type | Threshold |
| Query language | KQL |

The laboratory used QEMU/KVM virtualization with an isolated laboratory network and separate NAT connectivity.

The Kali Linux machine submitted authorized HTTP requests to the monitored Ubuntu Nginx server.

Nginx access logs were collected through Elastic Agent and processed by Elasticsearch.

---

## 3. Detection Rule Configuration

| Parameter | Configuration |
|---|---|
| Rule ID | SOC-WEB-002 |
| Rule type | Threshold |
| Query language | KQL |
| Index pattern | logs-nginx.access-default |
| Dataset | nginx.access |
| Target hostname | ubuntu-soc-target |
| HTTP response status | 404 |
| Grouping field 1 | source.ip |
| Grouping field 2 | host.name |
| Event threshold | 10 |
| Cardinality field | url.path |
| Minimum unique paths | 5 |
| Execution interval | 5 minutes |
| Additional look-back | 1 minute |
| Effective search window | Approximately 6 minutes |
| Severity | Medium |
| Risk score | 47 |
| Alert suppression | Disabled |
| Rule status | Enabled |
| MITRE ATT&CK tactic | Reconnaissance — TA0043 |
| MITRE ATT&CK technique | Active Scanning — T1595 |
| Additional mapping | Vulnerability Scanning — T1595.002 |

### 3.1 Native KQL Detection Query

```kql
event.dataset : "nginx.access" and
host.name : "ubuntu-soc-target" and
http.response.status_code : 404 and
source.ip : * and
url.path : *
```

### 3.2 Detection Logic

The detection requires two conditions to be satisfied for a particular combination of source IP and target hostname.

**Condition A — Event Count**

At least 10 matching HTTP 404 events must occur within the rule's evaluation window.

**Condition B — URL-Path Cardinality**

The matching events must involve at least five distinct `url.path` values.

Both conditions must be satisfied before a threshold alert can be generated.

The grouping configuration prevents requests from different source IP and hostname combinations from being combined into the same threshold group.

### 3.3 Engineering Rationale

Repeated HTTP 404 responses can indicate unsuccessful attempts to discover web directories, files, or application endpoints.

However, HTTP 404 responses alone are insufficient to distinguish reconnaissance from ordinary application errors.

The URL-path cardinality requirement helps differentiate repeated requests for one missing resource from requests targeting multiple resources.

For example, a browser repeatedly requesting one missing image could generate many HTTP 404 responses without indicating directory enumeration.

By requiring both request volume and URL-path diversity, SOC-WEB-002 provides a more specific detection hypothesis than a simple HTTP 404 event-count threshold.

Nevertheless, a matching alert does not independently establish malicious intent.

### 3.4 Evaluation Window

The rule runs approximately every five minutes with one additional minute of look-back.

This provides an effective search window of approximately six minutes.

The evaluation window is not an exact five-minute rolling window.

Event timestamps, ingestion delays, and scheduling behavior can influence which events contribute to a particular execution.

The configured thresholds are laboratory validation parameters, not statistically calibrated production thresholds.

---

## 4. Controlled Validation Methodology

### 4.1 Validation Objectives

The investigation used separate negative and positive tests.

The negative test evaluated whether the cardinality requirement prevented an alert despite sufficient HTTP 404 event volume.

The positive test evaluated whether Elastic Security generated an alert when both the event-count and URL-path cardinality conditions were satisfied.

### 4.2 Test Matrix

| Test | HTTP 404 Events | Distinct Paths | Expected Alert |
|---|---:|---:|---|
| Negative | 12 | 1 | No |
| Positive | 12 | 6 | Yes |

Both tests used the same authorized Kali Linux source and Ubuntu Nginx destination.

The principal behavioral difference was the number of distinct requested URL paths.

### 4.3 Test Isolation

The negative test was completed before the positive test.

Before beginning positive testing, Kali's local clock was checked.

It reported:

```text
2026-11-18 03:39:16 WAT +0100
```

The original negative-test activity had occurred around 03:14.

This provided more than six minutes of separation between the two tests.

The temporal separation was intended to prevent negative-test requests from contributing to the positive-test threshold evaluation.

---

## 5. Negative-Test Procedure and Results

### 5.1 Test Objective

Generate at least 10 HTTP 404 responses while requesting only one distinct URL path.

The expected behavior was:

- Event-count condition satisfied.
- Cardinality condition not satisfied.
- No threshold alert generated.

### 5.2 Test Command

The following command was executed on the authorized Kali Linux machine:

```bash
for i in $(seq 1 12); do
    /usr/bin/curl \
      --silent \
      --output /dev/null \
      --write-out "Request ${i}: HTTP %{http_code}\n" \
      --connect-timeout 5 \
      --max-time 10 \
      "http://192.168.100.226/soc-web-002-negative-test"

    /usr/bin/sleep 1
done
```

The requests targeted:

```text
/soc-web-002-negative-test
```

All 12 requests returned HTTP 404.

### 5.3 Elasticsearch Verification

Kibana Discover was used to search for the controlled negative-test events.

The query restricted the results to:

- Nginx access-log telemetry.
- The monitored Ubuntu hostname.
- The Kali source IP.
- HTTP 404 responses.
- The negative-test URL path.

Discover displayed 12 matching events.

The original requests occurred between approximately:

```text
03:14:33–03:14:44
```

on November 18, 2026, as displayed in Kibana.

All 12 events used the same requested URL path.

### 5.4 Rule Execution Verification

The relevant scheduled rule execution occurred at approximately:

```text
2026-11-18 03:17:24
```

The execution completed successfully.

Elastic Security reported zero alerts generated during that execution.

Subsequent relevant execution results also reported successful execution without new alerts.

### 5.5 Negative-Test Findings

| Validation Criterion | Observed Result |
|---|---|
| HTTP requests | 12 |
| HTTP status | 404 |
| Matching Elasticsearch documents | 12 |
| Distinct URL paths | 1 |
| Event-count condition | Satisfied |
| Cardinality condition | Not satisfied |
| Relevant rule execution | Succeeded |
| Alerts generated | 0 |

**Negative-test result: PASSED.**

The observations are consistent with the configured cardinality requirement preventing an alert when repeated HTTP 404 responses involve only one requested path.

### 5.6 Supplementary Evidence Capture

After the original negative test had been completed, the Kali terminal output was no longer available.

A subsequent controlled repetition of the same negative-test request pattern was performed to obtain terminal screenshot evidence.

The supplementary screenshot must not be represented as a screenshot of the original 03:14 execution.

The original negative-test outcome is supported by the Elasticsearch telemetry and rule-execution evidence captured during that test.

---

## 6. Positive-Test Procedure and Results

### 6.1 Test Objective

Generate at least 10 HTTP 404 responses involving at least five distinct URL paths.

The expected behavior was:

- Event-count condition satisfied.
- Cardinality condition satisfied.
- Elastic Security threshold alert generated.

### 6.2 Test Command

The following command was executed on Kali Linux:

```bash
TARGET="http://192.168.100.226"

for i in $(seq 1 12); do
    path="/soc-web-002-enumeration-$(( (i - 1) % 6 + 1 ))"

    printf 'Request %02d | %-30s | ' "$i" "$path"

    /usr/bin/curl \
        --silent \
        --output /dev/null \
        --write-out 'HTTP %{http_code}\n' \
        --connect-timeout 5 \
        --max-time 10 \
        "${TARGET}${path}"

    /usr/bin/sleep 1
done
```

### 6.3 Generated URL Paths

The command generated requests targeting:

```text
/soc-web-002-enumeration-1
/soc-web-002-enumeration-2
/soc-web-002-enumeration-3
/soc-web-002-enumeration-4
/soc-web-002-enumeration-5
/soc-web-002-enumeration-6
```

Each path was requested twice.

Therefore:

**Total requests:** 12

**Distinct paths:** 6

All requests returned HTTP 404.

### 6.4 Elasticsearch Verification

Kibana Discover confirmed 12 matching Nginx events.

The events shared the expected source IP and target hostname.

The requests occurred between approximately:

```text
03:43:08–03:43:19
```

on November 18, 2026, as displayed in Kibana.

The events occurred within approximately 11 seconds.

The six distinct URL paths and 12 HTTP 404 responses satisfied the configured detection conditions at the source-telemetry level.

### 6.5 Rule Execution Verification

SOC-WEB-002 subsequently executed at:

```text
2026-11-18 03:47:27.514
```

The execution status was:

```text
Succeeded
```

The execution generated:

```text
1 alert
```

The generated alert was subsequently examined in Elastic Security.

---

## 7. Generated Alert Evidence

### 7.1 Alert Details

| Field | Observed Value |
|---|---|
| Detection rule | SOC-WEB-002 |
| Rule category | Threshold |
| Alert timestamp | 2026-11-18 03:47:27.677 |
| Severity | Medium |
| Risk score | 47 |
| Source IP | 192.168.100.245 |
| Target hostname | ubuntu-soc-target |
| Matching event count | 12 |
| Cardinality field | url.path |
| Cardinality value | 6 |
| Final workflow status | Closed |

### 7.2 Threshold Event Count

The generated alert contained:

```text
kibana.alert.threshold_result.count = 12
```

This confirmed that the threshold aggregation counted 12 matching events.

The configured event-count requirement was:

```text
count >= 10
```

**Result: PASSED.**

### 7.3 URL-Path Cardinality

The alert contained:

```text
kibana.alert.threshold_result.cardinality.field = url.path

kibana.alert.threshold_result.cardinality.value = 6
```

This confirmed that Elastic Security counted six distinct URL-path values.

The configured cardinality requirement was:

```text
unique(url.path) >= 5
```

**Result: PASSED.**

### 7.4 Alert Aggregation Characteristics

SOC-WEB-002 is a threshold detection rule.

Unlike an individual-event custom-query alert, a threshold alert represents aggregated activity.

Consequently, investigators should not assume that every underlying HTTP request is reproduced directly within the alert document.

The original Nginx source events should be examined in Elasticsearch Discover to establish:

- Individual request timestamps.
- Requested URL paths.
- HTTP methods.
- HTTP response status codes.
- Source IP attribution.
- URL-path diversity.

---

## 8. Investigation Findings

### Finding 1 — Repeated HTTP 404 Activity Confirmed

Twelve HTTP requests returned HTTP 404 during the positive test.

The requests were submitted to the authorized Ubuntu Nginx server.

### Finding 2 — URL-Path Diversity Confirmed

The positive-test requests targeted six distinct URL paths.

Each path was requested twice.

This satisfied the cardinality requirement.

### Finding 3 — Source Attribution Confirmed

The matching events originated from:

```text
192.168.100.245
```

This address belonged to the authorized Kali Linux laboratory VM.

The monitored destination was:

```text
ubuntu-soc-target
192.168.100.226
```

### Finding 4 — Threshold Detection Confirmed

Elastic Security successfully executed SOC-WEB-002 and generated one alert.

The alert contained the expected grouped source and hostname information.

### Finding 5 — Aggregation Values Confirmed

The alert independently reported:

```text
Event count: 12
URL-path cardinality: 6
```

Both values exceeded their respective configured thresholds.

### Finding 6 — Negative-Test Behavior Confirmed

The original negative test generated 12 matching HTTP 404 events involving one URL path.

No threshold alert was generated during the relevant successful rule execution.

This provided evidence that URL-path diversity influenced the detection outcome.

### Finding 7 — Authorized Laboratory Activity

The activity was intentionally generated for security detection testing.

No unauthorized attacker was identified.

The HTTP 404 responses did not demonstrate successful access to the requested resources.

No successful exploitation or compromise was established.

---

## 9. MITRE ATT&CK Assessment

| Attribute | Classification |
|---|---|
| Tactic | Reconnaissance |
| Tactic ID | TA0043 |
| Technique | Active Scanning |
| Technique ID | T1595 |
| Sub-technique | Vulnerability Scanning |
| Sub-technique ID | T1595.002 |

Repeated requests targeting multiple web resources can occur during reconnaissance and vulnerability discovery.

The detection is therefore mapped to Active Scanning.

However, repeated HTTP 404 responses do not independently prove that vulnerability scanning occurred.

The sub-technique mapping represents a plausible detection hypothesis rather than confirmed malicious activity.

The laboratory simulation was authorized and used deliberately nonexistent resources.

Reference:

https://attack.mitre.org/techniques/T1595/

---

## 10. False-Positive Assessment

Potential benign causes of repeated HTTP 404 responses include:

- Broken website links.
- Missing application resources.
- Legitimate web crawlers.
- Search-engine indexing.
- Automated monitoring.
- Incorrect application configuration.
- Authorized penetration testing.
- Administrative troubleshooting.
- Laboratory simulations.

Although URL-path cardinality reduces alerts caused by repeated requests to a single missing resource, it does not eliminate false positives.

A legitimate crawler requesting many outdated URLs could satisfy both detection conditions.

The investigated activity originated from the authorized Kali Linux testing machine.

**Final classification: True Positive — Benign.**

---

## 11. Response and Alert Disposition

The investigation established that:

1. The detected activity matched the intended threshold conditions.
2. The event count was 12.
3. The distinct URL-path count was six.
4. All tested requests returned HTTP 404.
5. The source was an authorized laboratory machine.
6. No successful exploitation was established.
7. No incident escalation was required.

An investigation note was saved in Elastic Security.

The alert was subsequently closed.

The SOC-WEB-002 detection rule remained enabled.

**Final classification:** True Positive — Benign

**Final disposition:** Closed

**Investigation status:** Completed

---

## 12. Evidence Inventory

### 12.1 Detection Evidence

| No. | Evidence File | Purpose |
|---|---|---|
| 1 | `screenshots/05-detection/SOC-WEB-002-rule-overview.png` | Rule configuration |
| 2 | `screenshots/05-detection/SOC-WEB-002-rule-execution.png` | Successful execution and positive alert generation |
| 3 | `screenshots/05-detection/SOC-WEB-002-negative-test.png` | Supplementary negative-test terminal evidence |
| 4 | `screenshots/05-detection/SOC-WEB-002-negative-telemetry.png` | Original negative-test Elasticsearch events |
| 5 | `screenshots/05-detection/SOC-WEB-002-negative-execution.png` | Successful execution without alerts |
| 6 | `screenshots/05-detection/SOC-WEB-002-positive-test.png` | Positive-test terminal evidence |
| 7 | `screenshots/05-detection/SOC-WEB-002-positive-telemetry.png` | Positive-test Elasticsearch events |
| 8 | `screenshots/05-detection/SOC-WEB-002-alert-generated.png` | Generated threshold alert |

### 12.2 Investigation Evidence

| No. | Evidence File | Purpose |
|---|---|---|
| 9 | `screenshots/06-investigations/SOC-WEB-002-alert-cardinality.png` | Aggregation field and cardinality value |
| 10 | `screenshots/06-investigations/SOC-WEB-002-alert-closed.png` | Investigation closure |

All 10 evidence files were verified to exist and contain nonzero data.

The screenshot contents should undergo a final visual review before publication.

---

## 13. Recommendations

### 13.1 Retain the Detection Rule

Keep SOC-WEB-002 enabled within the laboratory environment.

The initial positive and negative tests demonstrate the expected behavior under controlled conditions.

### 13.2 Evaluate Production Thresholds

The current thresholds of 10 HTTP 404 responses and five distinct paths were selected for laboratory validation.

They have not been calibrated against representative production traffic.

Before production deployment, evaluate request distributions, false-positive rates, and expected application behavior.

### 13.3 Expand Behavioral Context

Correlate repeated HTTP 404 activity with:

- HTTP 200 responses.
- HTTP 401 and 403 responses.
- Suspicious URL requests.
- Request frequency.
- User-agent information.
- Nginx error logs.
- Other Elastic Security alerts.

### 13.4 Evaluate Additional Sources

Adapt the hostname restriction when monitoring multiple authorized web servers.

Ensure that event field mappings and IP attribution remain correct.

### 13.5 Preserve Detection Distinctions

Maintain a clear separation between:

**SOC-WEB-001:** Individual suspicious URL requests.

**SOC-WEB-002:** Repeated HTTP 404 responses involving multiple distinct URL paths.

The two detections complement one another but measure different behaviors.

### 13.6 Perform Additional Validation

Future improvements may include:

- Boundary testing at nine and ten matching events.
- Cardinality boundary testing at four and five distinct paths.
- Multiple-source-IP isolation testing.
- Multiple-hostname grouping tests.
- Evaluation of overlapping rule execution windows.
- Duplicate-alert assessment.
- Production-like benign traffic testing.

These are future engineering recommendations and were not part of the completed validation.

---

## 14. Investigation Conclusion

SOC-WEB-002 successfully detected a controlled web-resource enumeration simulation using a combination of HTTP 404 event counting and URL-path cardinality.

The negative test demonstrated that 12 HTTP 404 responses involving one distinct path did not generate an alert during the relevant rule execution.

The positive test demonstrated that 12 HTTP 404 responses involving six distinct paths generated one Elastic Security threshold alert.

The alert independently confirmed:

**Event count:** 12

**Distinct URL paths:** 6

The investigation established that the activity originated from an authorized Kali Linux laboratory machine.

No successful access to the requested resources or unauthorized compromise was demonstrated.

The alert was documented and closed as **True Positive — Benign**.

**SOC-WEB-002 detection validation: PASSED**

**SOC-WEB-002 investigation: COMPLETED**

**Portfolio documentation and GitHub publication: PENDING**

# SOC-WEB-002 — Repeated HTTP 404 Responses and Directory Enumeration

**Document Type:** Technical Implementation Guide (TIG)  
**Project:** Elastic SOC Homelab  
**Detection ID:** SOC-WEB-002  
**Implementation Date:** November 18, 2026  
**Detection Status:** Laboratory Validated  
**Alert Classification:** True Positive — Benign  
**Author:** Elastic SOC Homelab  

---

## 1. Introduction

### 1.1 Purpose

This Technical Implementation Guide documents the successful configuration,
implementation, validation, and investigation of SOC-WEB-002.

SOC-WEB-002 is an Elastic Security threshold detection designed to identify
repeated HTTP 404 responses involving multiple distinct URL paths from the
same source IP against the same monitored web server.

The detection combines two requirements:

1. At least 10 matching HTTP 404 events.
2. At least five distinct requested URL paths.

Both requirements must be satisfied within the configured detection
evaluation window.

### 1.2 Security Objective

Repeated HTTP 404 responses may indicate attempts to discover:

- Hidden web directories.
- Administrative interfaces.
- Application endpoints.
- Configuration files.
- Backup files.
- Other potentially sensitive resources.

However, HTTP 404 responses alone do not establish malicious intent.

The URL-path cardinality requirement helps distinguish repeated requests
to a single missing resource from requests targeting multiple resources.

### 1.3 Implementation Scope

This guide covers:

1. Laboratory architecture.
2. Environment prerequisites.
3. Nginx telemetry verification.
4. Elastic Security threshold rule configuration.
5. Detection logic and aggregation.
6. Controlled negative testing.
7. Controlled positive testing.
8. Alert generation and verification.
9. Investigation procedures.
10. MITRE ATT&CK mapping.
11. Sigma representation.
12. Evidence collection.
13. Validation acceptance criteria.
14. Operational considerations.
15. Future engineering improvements.
16. Conclusion and references.

This document records an implementation validated in the author's
laboratory environment. Independent reproduction and production
readiness have not been established.

---

## 2. Laboratory Architecture

### 2.1 Environment Configuration

| Component | Configuration |
|---|---|
| Virtualization Platform | QEMU/KVM |
| SIEM Platform | Elastic Security |
| SIEM Server | elastic-siem |
| SIEM IP Address | 192.168.100.104 |
| Target Hostname | ubuntu-soc-target |
| Target Operating System | Ubuntu Server 24.04.5 LTS |
| Target IP Address | 192.168.100.226 |
| Web Server | Nginx 1.24.0 |
| Web Service | HTTP / TCP 80 |
| Simulation Machine | kali-linux |
| Simulation Source IP | 192.168.100.245 |
| Laboratory Network | 192.168.100.0/24 |
| Telemetry Collector | Elastic Agent |
| Nginx Integration | 3.2.2 |
| Elastic Agent Policy | linux-soc-policy |
| Nginx Integration Policy | nginx-web-security-monitoring |

### 2.2 Network Architecture

The laboratory environment contains three principal systems.

**Elastic SIEM Server**

Hostname: elastic-siem

IP address: 192.168.100.104

Responsibilities:

- Receive and store security telemetry.
- Index Nginx access-log events.
- Execute detection rules.
- Generate security alerts.
- Support investigations through Kibana.

**Ubuntu Web Server**

Hostname: ubuntu-soc-target

IP address: 192.168.100.226

Responsibilities:

- Host the Nginx HTTP service.
- Receive controlled laboratory requests.
- Generate access-log telemetry.
- Forward logs through Elastic Agent.

**Kali Linux**

Hostname: kali-linux

Source IP: 192.168.100.245

Responsibilities:

- Generate authorized HTTP test requests.
- Simulate repeated resource enumeration.
- Validate negative and positive detection conditions.

### 2.3 Detection Data Flow

    Kali Linux
    192.168.100.245
          |
          | HTTP GET requests
          v
    Ubuntu Nginx
    192.168.100.226:80
          |
          | Nginx access.log
          v
    Elastic Agent
    Nginx Integration
          |
          v
    Elasticsearch
    logs-nginx.access-default
          |
          v
    Elastic Security
    SOC-WEB-002 Threshold Rule
          |
          v
    Security Alert
          |
          v
    SOC Investigation and Closure

### 2.4 Network Security Considerations

The test traffic uses the isolated laboratory network.

Nginx is configured to listen on the laboratory interface.

The simulation is authorized and uses deliberately nonexistent URL paths.

The example IP addresses are specific to this laboratory and must be
adapted before reproducing the procedure in another environment.

---

## 3. Implementation Prerequisites

Before implementing SOC-WEB-002, ensure that:

1. Elasticsearch is operational.
2. Kibana is accessible.
3. Elastic Security is available.
4. Elastic Agent is healthy on ubuntu-soc-target.
5. Nginx is installed and running.
6. Nginx access logging is enabled.
7. The Nginx integration collects access-log events.
8. Kali Linux can reach the target HTTP service.
9. Required ECS fields are populated.
10. The analyst has permission to create detection rules.

### 3.1 Nginx Access Log

The Nginx access-log location is:

    /var/log/nginx/access.log

### 3.2 Elasticsearch Data Stream

The Nginx events are stored in:

    logs-nginx.access-default

### 3.3 Event Dataset

The expected dataset is:

    nginx.access

### 3.4 Required Event Fields

| Field | Purpose |
|---|---|
| @timestamp | Event timestamp |
| event.dataset | Identifies Nginx access events |
| host.name | Identifies monitored web server |
| source.ip | Identifies request source |
| url.path | Identifies requested URL path |
| http.response.status_code | Identifies HTTP response status |
| http.request.method | Provides request method |
| user_agent.original | Provides user-agent context where available |

The source IP and URL path are especially important because the
detection uses source-based grouping and URL-path cardinality.

---

## 4. Verify Nginx Telemetry in Elasticsearch

### 4.1 Open Kibana Discover

Navigate to:

Kibana → Discover

Select a data view covering:

    logs-nginx.access-default

### 4.2 Apply the Verification Query

Use the following KQL:

    event.dataset : "nginx.access" and
    host.name : "ubuntu-soc-target"

### 4.3 Inspect Events

Verify that Nginx access-log events are visible.

Inspect individual events and confirm the presence of:

- @timestamp
- event.dataset
- host.name
- source.ip
- url.path
- http.response.status_code

### 4.4 Acceptance Criteria

Telemetry verification passes when:

1. Nginx events appear in Elasticsearch.
2. Events are associated with ubuntu-soc-target.
3. HTTP response status codes are correctly parsed.
4. URL paths are available for cardinality calculations.
5. Source IP addresses correctly identify request origins.

Do not proceed with threshold configuration until the required
telemetry fields are available.

---

## 5. Create SOC-WEB-002 in Elastic Security

### 5.1 Navigate to Detection Rules

Open:

Kibana → Security → Rules → Detection rules

Select the option to create a new detection rule.

### 5.2 Rule Metadata

Configure the following settings:

| Setting | Value |
|---|---|
| Rule Name | SOC-WEB-002 — Repeated HTTP 404 Responses and Directory Enumeration |
| Rule Type | Threshold |
| Query Language | KQL |
| Index | logs-nginx.access-default |
| Severity | Medium |
| Risk Score | 47 |
| Execution Interval | 5 minutes |
| Additional Look-back | 1 minute |
| Alert Suppression | Disabled |
| Initial Status | Enabled |

### 5.3 Detection Query

Enter the following KQL query:

    event.dataset : "nginx.access" and
    host.name : "ubuntu-soc-target" and
    http.response.status_code : 404 and
    source.ip : * and
    url.path : *

### 5.4 Query Explanation

The query selects events that satisfy all the following conditions:

1. The event belongs to the Nginx access dataset.
2. The monitored hostname is ubuntu-soc-target.
3. The HTTP response status is 404.
4. The source IP field exists.
5. The requested URL-path field exists.

### 5.5 Configure Threshold Aggregation

Under the threshold configuration, specify:

**Group by fields:**

    source.ip
    host.name

**Number of events:**

    10

**Cardinality field:**

    url.path

**Minimum unique values:**

    5

### 5.6 Detection Logic

The native Elastic rule implements the following combined logic:

    Matching HTTP 404 event count >= 10

                         AND

    Distinct requested URL paths >= 5

The aggregation is performed for each source-IP and hostname group.

Both conditions must be satisfied for an alert to be generated.

### 5.7 Detection Evaluation Window

Configure:

    Runs every: 5 minutes

    Additional look-back: 1 minute

This produces an effective search window of approximately six minutes.

The search window is based on scheduled rule execution and should not
be described as an exact continuously evaluated rolling window.

Event ingestion delays and execution timing can affect which events
are included in an evaluation.

### 5.8 Severity and Risk

Set:

    Severity: Medium

    Risk score: 47

These values provide a moderate prioritization for potentially
suspicious web-resource enumeration.

Severity does not prove malicious intent.

### 5.9 Recommended Tags

Use:

- SOC-Homelab
- SOC-WEB-002
- Web-Security
- Nginx
- Directory-Enumeration
- HTTP-404
- Threshold-Detection
- MITRE-T1595

### 5.10 Save and Enable

Save the detection rule.

Confirm that it is enabled.

Allow the rule scheduler to execute.

Verify that the rule execution status reports success.

---

## 6. MITRE ATT&CK Mapping

### 6.1 Tactic

Name: Reconnaissance

Identifier: TA0043

### 6.2 Technique

Name: Active Scanning

Identifier: T1595

### 6.3 Sub-technique

Name: Vulnerability Scanning

Identifier: T1595.002

### 6.4 Mapping Rationale

Repeated requests to multiple nonexistent web resources may be
associated with reconnaissance and vulnerability discovery.

However, HTTP 404 events do not independently prove that an attacker
is performing vulnerability scanning.

The ATT&CK mapping represents a plausible detection use case.

The historical SOC-WEB-002 activity was an authorized laboratory test.

Reference:

https://attack.mitre.org/techniques/T1595/

---

## 7. Controlled Negative-Test Validation

### 7.1 Objective

Verify that repeated HTTP 404 responses involving only one distinct
URL path do not generate a SOC-WEB-002 alert.

### 7.2 Test Conditions

| Parameter | Value |
|---|---|
| Source | 192.168.100.245 |
| Destination | 192.168.100.226 |
| Protocol | HTTP |
| Method | GET |
| Expected Status | 404 |
| Number of Requests | 12 |
| Distinct Paths | 1 |
| Expected Alert | None |

### 7.3 Execute the Negative Test

Run the following command on Kali Linux:

    for i in $(/usr/bin/seq 1 12); do
        /usr/bin/curl \
          --silent \
          --output /dev/null \
          --write-out "Request ${i}: HTTP %{http_code}\n" \
          --connect-timeout 5 \
          --max-time 10 \
          "http://192.168.100.226/soc-web-002-negative-test"

        /usr/bin/sleep 1
    done

The command sends 12 HTTP requests to the same URL path.

### 7.4 Expected Terminal Output

    Request 1: HTTP 404
    Request 2: HTTP 404
    Request 3: HTTP 404
    ...
    Request 12: HTTP 404

### 7.5 Verify Negative-Test Telemetry

Navigate to Kibana Discover.

Apply:

    event.dataset : "nginx.access" and
    host.name : "ubuntu-soc-target" and
    source.ip : "192.168.100.245" and
    http.response.status_code : 404 and
    url.path : "/soc-web-002-negative-test"

Confirm that:

- Twelve events are present.
- All events have HTTP status 404.
- All events contain the same URL path.
- The source IP is 192.168.100.245.
- The hostname is ubuntu-soc-target.

### 7.6 Verify Rule Execution

Inspect the relevant scheduled execution of SOC-WEB-002.

Confirm that the execution succeeded.

For an isolated negative test, the expected number of generated alerts
is zero.

Ensure no unrelated qualifying traffic from the same source and host
contributes additional distinct paths during the evaluation window.

### 7.7 Historical Negative-Test Results

The original negative test occurred on November 18, 2026.

Observed Nginx events:

    Approximately 03:14:33–03:14:44

Relevant rule execution:

    Approximately 03:17:24

Observed results:

| Measurement | Observed |
|---|---|
| HTTP 404 events | 12 |
| Distinct URL paths | 1 |
| Event-count requirement | Satisfied |
| Cardinality requirement | Not satisfied |
| Rule execution | Succeeded |
| Alerts generated | 0 |

### 7.8 Negative-Test Assessment

The negative test passed.

The event-count threshold was satisfied.

The cardinality requirement was not satisfied.

No alert was generated during the relevant successful rule execution.

This supports the conclusion that URL-path cardinality influenced
the observed detection behavior.

### 7.9 Supplementary Screenshot Note

After the original negative test, the Kali terminal output was cleared.

The negative-test command was later repeated to capture the missing
terminal screenshot.

The later screenshot is supplementary evidence of the test procedure.

It must not be presented as terminal evidence from the original
03:14 execution.

The original negative-test telemetry and rule-execution evidence
remain separate.

---

## 8. Controlled Positive-Test Validation

### 8.1 Objective

Verify that at least 10 HTTP 404 events involving at least five
distinct URL paths generate a threshold alert.

### 8.2 Test Conditions

| Parameter | Value |
|---|---|
| Source | 192.168.100.245 |
| Destination | 192.168.100.226 |
| Protocol | HTTP |
| Method | GET |
| Expected Status | 404 |
| Number of Requests | 12 |
| Distinct Paths | 6 |
| Expected Alert | Yes |

### 8.3 Test Isolation

The positive test should be performed after previous controlled
traffic has aged outside the rule evaluation window.

In the historical validation, more than six minutes separated the
original negative and positive tests.

This reduced the possibility of mixing events from the two scenarios.

### 8.4 Execute the Positive Test

Run the following command on Kali Linux:

    TARGET="http://192.168.100.226"

    for i in $(/usr/bin/seq 1 12); do
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

### 8.5 Requested URL Paths

The command cycles through six paths:

    /soc-web-002-enumeration-1
    /soc-web-002-enumeration-2
    /soc-web-002-enumeration-3
    /soc-web-002-enumeration-4
    /soc-web-002-enumeration-5
    /soc-web-002-enumeration-6

Each path is requested twice.

Total requests:

    12

Distinct URL paths:

    6

### 8.6 Verify Positive-Test Telemetry

Open Kibana Discover.

Apply:

    event.dataset : "nginx.access" and
    host.name : "ubuntu-soc-target" and
    source.ip : "192.168.100.245" and
    http.response.status_code : 404 and
    url.path : /soc-web-002-enumeration-*

Confirm:

1. Twelve matching events.
2. Six distinct URL paths.
3. Two requests per path.
4. HTTP status 404.
5. The expected source IP.
6. The expected target hostname.

### 8.7 Historical Positive-Test Results

The positive test was conducted on November 18, 2026.

Observed event interval:

    Approximately 03:43:08–03:43:19

Successful rule execution:

    2026-11-18 03:47:27.514

Alerts generated:

    1

Alert timestamp:

    2026-11-18 03:47:27.677

### 8.8 Positive-Test Assessment

| Measurement | Observed |
|---|---|
| HTTP 404 events | 12 |
| Distinct URL paths | 6 |
| Event-count requirement | Satisfied |
| Cardinality requirement | Satisfied |
| Rule execution | Succeeded |
| Alerts generated | 1 |

The positive test passed.

The alert was generated after a scheduled rule execution.

The elapsed time between the HTTP requests and alert generation
reflects the historical scheduling behavior of this implementation.

It is not a universal detection-latency guarantee.

---

## 9. Verify the Generated Threshold Alert

### 9.1 Navigate to Security Alerts

Open:

Kibana → Security → Alerts

Locate the alert generated by SOC-WEB-002.

### 9.2 Verify Alert Identity

Confirm:

    Rule: SOC-WEB-002

    Rule type: Threshold

    Severity: Medium

    Risk score: 47

### 9.3 Verify Source Attribution

Confirm that the threshold grouping identifies:

    source.ip = 192.168.100.245

    host.name = ubuntu-soc-target

### 9.4 Verify Event Count

Inspect:

    kibana.alert.threshold_result.count

Historically observed:

    12

This satisfies the configured event-count threshold of 10.

### 9.5 Verify Cardinality Field

Inspect:

    kibana.alert.threshold_result.cardinality.field

Historically observed:

    url.path

### 9.6 Verify Cardinality Value

Inspect:

    kibana.alert.threshold_result.cardinality.value

Historically observed:

    6

This satisfies the configured minimum of five distinct paths.

### 9.7 Alert Verification Summary

| Alert Attribute | Observed Value |
|---|---|
| Source IP | 192.168.100.245 |
| Target Hostname | ubuntu-soc-target |
| Event Count | 12 |
| Cardinality Field | url.path |
| Cardinality Value | 6 |
| Severity | Medium |
| Risk Score | 47 |
| Alerts Generated | 1 |

### 9.8 Threshold Alert Interpretation

Threshold alerts represent aggregated event activity.

An aggregated alert does not necessarily reproduce every underlying
HTTP request as a separate alert field.

Analysts should examine the original Nginx access events in Discover
to establish the requested paths, timestamps, methods, and responses.

---

## 10. Investigation and Alert Disposition

### 10.1 Investigation Objectives

The investigation should determine:

1. Whether the alert matches the configured detection conditions.
2. Which source generated the requests.
3. Which web server received the requests.
4. Whether multiple resources were requested.
5. Whether successful access occurred.
6. Whether the activity was authorized.
7. Whether further investigation or escalation is required.

### 10.2 Recommended Investigation Procedure

**Step 1 — Review the alert**

Confirm the rule name, severity, timestamp, and risk score.

**Step 2 — Inspect aggregation results**

Review the event count and URL-path cardinality.

**Step 3 — Identify the source**

Confirm the source IP and determine whether it belongs to an
authorized machine.

**Step 4 — Inspect original events**

Use Kibana Discover to inspect the matching Nginx access logs.

**Step 5 — Review requested resources**

Identify the requested URL paths and HTTP response codes.

**Step 6 — Search for related activity**

Review additional HTTP responses, unusual methods, successful access,
and other relevant security events where available.

**Step 7 — Determine authorization**

Establish whether the activity belongs to an approved test,
legitimate process, or potentially unauthorized source.

**Step 8 — Record findings**

Document supporting evidence and any limitations.

**Step 9 — Classify the alert**

Select an appropriate classification based on the evidence.

**Step 10 — Close or escalate**

Close benign activity after investigation or escalate suspicious
activity according to organizational procedures.

### 10.3 Historical Investigation Findings

The November 18, 2026 investigation confirmed:

- The source was Kali Linux at 192.168.100.245.
- The destination was ubuntu-soc-target at 192.168.100.226.
- Twelve HTTP 404 events were indexed.
- Six distinct URL paths were requested.
- Elastic Security generated one threshold alert.
- The threshold event count was 12.
- The URL-path cardinality value was six.
- The requests were part of an authorized laboratory simulation.
- No successful access to the tested resources was demonstrated.
- No unauthorized compromise was established.

### 10.4 Final Classification

    True Positive — Benign

This classification is appropriate because the alert correctly
identified activity satisfying the configured detection conditions.

The activity itself was authorized and benign within the laboratory.

### 10.5 Alert Closure

An investigation note was saved in Elastic Security.

The alert was closed after investigation.

Final disposition:

    Closed

No incident escalation was required for the authorized simulation.

---

## 11. Sigma Detection Representation

### 11.1 Sigma File

Repository location:

    detection-rules/SOC-WEB-002.yml

### 11.2 Sigma Structure

The experimental Sigma file contains three YAML documents:

1. Base HTTP 404 detection.
2. Event-count correlation.
3. URL-path cardinality correlation.

### 11.3 Base Detection

The base detection selects Nginx HTTP 404 events from the monitored
hostname.

It also requires the existence of:

    source.ip

    url.path

The verified detection condition is:

    selection and source_present and path_present

### 11.4 Event-Count Correlation

Correlation type:

    event_count

Threshold:

    gte: 10

Grouping:

    source.ip
    host.name

Timespan:

    6m

### 11.5 URL-Path Cardinality Correlation

Correlation type:

    value_count

Cardinality field:

    url.path

Threshold:

    gte: 5

Grouping:

    source.ip
    host.name

Timespan:

    6m

### 11.6 Important Sigma Limitation

The two Sigma correlations are independent components.

Placing them in the same YAML file does not automatically create
the combined logical condition:

    event_count >= 10 AND unique(url.path) >= 5

Therefore, the Sigma representation must not be described as
functionally equivalent to the native Elastic threshold rule.

The native Elastic Security implementation remains the authoritative
laboratory-validated detection.

### 11.7 Sigma Validation Status

Custom Python and PyYAML checks verified:

- Three YAML documents.
- Valid UUIDs.
- Unique UUIDs.
- Correct base detection condition.
- Nginx event dataset.
- HTTP 404 selection.
- Source IP existence requirement.
- URL-path existence requirement.
- Event-count correlation.
- Cardinality correlation.
- Correct correlation references.
- Correct grouping fields.
- Event-count threshold of 10.
- Cardinality threshold of five.
- Six-minute timespans.

The initial custom validation incorrectly expected the simpler
condition "selection".

Inspection established that the actual base rule contained additional
source-IP and URL-path existence checks.

The corrected validation passed.

Formal Sigma specification validation and backend conversion have
not yet been completed.

Runtime equivalence with the native Elastic rule has not been established.

---

## 12. Evidence Collection and Repository Organization

### 12.1 Evidence Verification

Ten SOC-WEB-002 screenshot files were verified to exist and contain
nonzero data.

The verification confirmed filenames, paths, and file sizes.

It did not independently inspect the visual contents of the images.

### 12.2 Detection Evidence

Directory:

    screenshots/05-detection/

Files:

1. SOC-WEB-002-rule-overview.png
2. SOC-WEB-002-rule-execution.png
3. SOC-WEB-002-negative-test.png
4. SOC-WEB-002-negative-telemetry.png
5. SOC-WEB-002-negative-execution.png
6. SOC-WEB-002-positive-test.png
7. SOC-WEB-002-positive-telemetry.png
8. SOC-WEB-002-alert-generated.png

### 12.3 Investigation Evidence

Directory:

    screenshots/06-investigations/

Files:

9. SOC-WEB-002-alert-cardinality.png
10. SOC-WEB-002-alert-closed.png

### 12.4 Evidence Interpretation

The rule overview screenshot supports configuration review.

The rule execution screenshots support scheduler and alert-count review.

The negative-test telemetry supports the original negative-test
observations.

The negative-test terminal screenshot documents a later repetition
of the request-generation procedure.

The positive-test screenshots support the successful controlled test.

The cardinality screenshot supports the observed aggregation values.

The closed-alert screenshot supports the final workflow disposition.

### 12.5 Related Documentation

Investigation report:

    reports/SOC-WEB-002-investigation.md

Sigma representation:

    detection-rules/SOC-WEB-002.yml

Technical Implementation Guide:

    implementation-guides/SOC-WEB-002-implementation.md

Planned PDF companion:

    implementation-guides/SOC-WEB-002-implementation.pdf

---

## 13. Validation Acceptance Criteria

### 13.1 Telemetry Validation

| Criterion | Historical Result |
|---|---|
| Nginx access logs collected | PASS |
| Events indexed in Elasticsearch | PASS |
| HTTP status field available | PASS |
| Source IP available | PASS |
| URL path available | PASS |

### 13.2 Detection Rule Validation

| Criterion | Historical Result |
|---|---|
| Threshold rule created | PASS |
| Rule enabled | PASS |
| Scheduled execution successful | PASS |
| Event threshold configured | PASS |
| Cardinality threshold configured | PASS |

### 13.3 Negative-Test Validation

| Criterion | Historical Result |
|---|---|
| 12 HTTP 404 events | PASS |
| One distinct URL path | PASS |
| Successful scheduled execution | PASS |
| No alert generated | PASS |

### 13.4 Positive-Test Validation

| Criterion | Historical Result |
|---|---|
| 12 HTTP 404 events | PASS |
| Six distinct URL paths | PASS |
| Successful scheduled execution | PASS |
| One alert generated | PASS |
| Alert event count = 12 | PASS |
| Alert cardinality field = url.path | PASS |
| Alert cardinality value = 6 | PASS |

### 13.5 Investigation Validation

| Criterion | Historical Result |
|---|---|
| Source identified | PASS |
| Target identified | PASS |
| Request activity examined | PASS |
| Authorization established | PASS |
| Investigation note saved | PASS |
| Alert classified | PASS |
| Alert closed | PASS |

### 13.6 Validation Boundary

The completed tests demonstrate the intended behavior for two
controlled laboratory scenarios.

They do not establish correctness for every possible combination
of request count, cardinality, source, hostname, or timing.

---

## 14. Operational Considerations

### 14.1 Potential False Positives

Legitimate processes may generate repeated HTTP 404 responses.

Examples include:

- Broken application links.
- Missing website resources.
- Search-engine crawlers.
- Legitimate monitoring.
- Website migration issues.
- Automated application testing.
- Authorized penetration testing.
- Administrative troubleshooting.

### 14.2 Potential False Negatives

SOC-WEB-002 may miss activity when:

- Fewer than 10 HTTP 404 events occur.
- Fewer than five distinct paths are requested.
- Requests fall outside the relevant evaluation window.
- Required fields are missing.
- The target hostname is not monitored by the rule.
- The activity produces response codes other than 404.
- Source IP attribution is incorrect.
- Telemetry ingestion is delayed or interrupted.

### 14.3 Source IP Accuracy

When Nginx operates behind reverse proxies, source IP attribution
requires special attention.

Proxy configuration and trusted forwarding headers can affect the
identity recorded in access logs.

Do not assume that a logged IP address always identifies the original
client without validating the deployment architecture.

### 14.4 Detection Threshold Calibration

The current thresholds were selected for laboratory validation.

They have not been calibrated against representative production data.

Before production deployment, review:

- Normal HTTP 404 volumes.
- Legitimate crawler activity.
- Application-specific request patterns.
- False-positive rates.
- Detection sensitivity.
- Rule execution costs.
- Alert duplication.
- Operational investigation capacity.

### 14.5 Complementary Detection

SOC-WEB-002 complements SOC-WEB-001.

SOC-WEB-001 focuses on suspicious individual URL requests.

SOC-WEB-002 focuses on repeated HTTP 404 responses involving multiple
distinct URL paths.

These detections measure different behaviors and should not be
treated as interchangeable.

---

## 15. Future Engineering Improvements

The following improvements are recommended for subsequent work.

They were not part of the completed SOC-WEB-002 validation.

### 15.1 Event-Count Boundary Testing

Compare outcomes for:

- Nine qualifying events.
- Ten qualifying events.

Verify the exact event threshold boundary.

### 15.2 Cardinality Boundary Testing

Compare outcomes for:

- Four distinct URL paths.
- Five distinct URL paths.

Verify the exact cardinality boundary.

### 15.3 Multiple Source-IP Testing

Generate controlled traffic from different authorized source IPs.

Confirm that event counts are not incorrectly combined across groups.

### 15.4 Multiple Hostname Testing

Extend the laboratory to additional monitored web servers.

Verify hostname-based aggregation.

### 15.5 Duplicate Alert Analysis

Examine overlapping evaluation windows.

Determine whether one sequence of requests can contribute to
multiple scheduled alert executions.

### 15.6 Additional HTTP Response Correlation

Investigate correlations between:

- HTTP 404.
- HTTP 403.
- HTTP 401.
- HTTP 200.

This may help distinguish unsuccessful enumeration from requests
that subsequently discover accessible resources.

### 15.7 Sigma Portability Testing

Perform formal Sigma validation.

Test supported correlation backends.

Verify field mappings.

Evaluate whether the combined threshold conditions can be expressed
and executed correctly in the chosen target backend.

### 15.8 Production-Like Benign Traffic

Generate representative benign web traffic.

Assess false-positive behavior before considering deployment
outside the controlled laboratory.

---

## 16. Conclusion

SOC-WEB-002 was successfully implemented and validated in the
Elastic SOC Homelab.

The detection combines:

1. A minimum of 10 matching HTTP 404 events.
2. A minimum of five distinct requested URL paths.

Both conditions are evaluated for the same source-IP and target-host
group within the configured search window.

The controlled negative test generated 12 HTTP 404 events involving
one distinct URL path.

No threshold alert was generated during the relevant successful
rule execution.

The controlled positive test generated 12 HTTP 404 events involving
six distinct URL paths.

Elastic Security generated one threshold alert.

The alert independently reported:

    Event count: 12

    Cardinality field: url.path

    Cardinality value: 6

The activity originated from an authorized Kali Linux laboratory
machine.

No successful access to the tested resources or unauthorized
compromise was established.

The alert was investigated, documented, classified as
True Positive — Benign, and closed.

### 16.1 Final Project Status

| Component | Status |
|---|---|
| Native Elastic Detection | VALIDATED |
| Negative Test | PASSED |
| Positive Test | PASSED |
| Alert Generation | CONFIRMED |
| Investigation | COMPLETED |
| Alert Disposition | CLOSED |
| Evidence Files | 10 VERIFIED AS PRESENT AND NONEMPTY |
| Investigation Report | SAVED |
| Sigma Structural Checks | PASSED |
| Formal Sigma Validation | NOT COMPLETED |
| Sigma Backend Equivalence | NOT ESTABLISHED |
| Independent Reproduction | NOT ESTABLISHED |
| Production Readiness | NOT ESTABLISHED |

### 16.2 Final Assessment

SOC-WEB-002 demonstrates a functioning laboratory implementation
of threshold-based web-resource enumeration detection using
Nginx access logs, Elasticsearch, and Elastic Security.

The successful positive and negative tests provide evidence that
the configured event-count and URL-path cardinality conditions
behaved as intended in the controlled scenarios.

---

## References

### MITRE ATT&CK — Active Scanning

https://attack.mitre.org/techniques/T1595/

### MITRE ATT&CK — Vulnerability Scanning

https://attack.mitre.org/techniques/T1595/002/

### Elastic Security Documentation

https://www.elastic.co/guide/en/security/current/index.html

### Sigma Correlation Specification

https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html

---

**End of SOC-WEB-002 Technical Implementation Guide**

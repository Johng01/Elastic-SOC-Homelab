# SOC-WEB-003 — Potential Path Traversal in HTTP Requests

**Document type:** Technical Implementation Guide (TIG)  
**Project:** Elastic SOC Homelab  
**Detection ID:** SOC-WEB-003  
**Implementation and validation:** November 18, 2026  
**Native detection status:** Laboratory-validated for the tested positive request  
**Investigation disposition:** True Positive — Benign; alert closed  
**Author:** Elastic SOC Homelab

---

## 1. Purpose, Scope, and Validation Boundary

### 1.1 Purpose

This guide records a successful implementation of **SOC-WEB-003 — Potential Path Traversal in HTTP Requests**, an Elastic Security **Custom Query** detection for selected directory-traversal indicators in Nginx HTTP access logs. It provides the reproducible configuration, controlled tests, alert investigation procedure, supporting evidence inventory, and detection-engineering limitations.

The rule examines two Elasticsearch URL fields:

- `url.original` for the encoded parent-directory indicator `%2E%2E`.
- `url.path` for the decoded path component `/../`.

The two indicators are joined by **OR**: a matching document needs either indicator, together with the required dataset, hostname, and source-IP conditions.

### 1.2 Scope limitations

This is **URL-based indicator detection**, not general SQL injection, cross-site scripting, command injection, or request-body inspection. The current Nginx access telemetry does **not** establish visibility into HTTP request-body content. The rule does not confirm successful traversal, sensitive-file disclosure, or exploitation. It has not been tested across all traversal variations, field mappings, or backends.

The implementation was validated in one authorized SOC homelab. This guide does not claim independent reproduction or production readiness. The historically observed negative test is treated as a **qualified** validation because its indexed event was not individually correlated with the exact covering execution window.

---

## 2. Laboratory Architecture

### 2.1 Environment inventory

| Component | Observed laboratory configuration |
|---|---|
| Hypervisor | QEMU/KVM |
| SIEM platform | Elastic Security / Elasticsearch / Kibana |
| SIEM hostname and address | `elastic-siem` — `192.168.100.104` |
| Target operating system | Ubuntu Server 24.04.5 LTS |
| Web target | `ubuntu-soc-target` — `192.168.100.226` |
| Web server | Nginx 1.24.0, HTTP port 80 |
| Simulation machine | Kali Linux — `192.168.100.245` |
| Laboratory subnet | `192.168.100.0/24` |
| Log collector | Elastic Agent |
| Nginx integration | 3.2.2 |
| Agent policy | `linux-soc-policy` |
| Integration policy | `nginx-web-security-monitoring` |
| Target access log | `/var/log/nginx/access.log` |
| Elasticsearch data stream | `logs-nginx.access-default` |
| Event dataset | `nginx.access` |

### 2.2 Telemetry flow

```text
Kali Linux (192.168.100.245)
    │ authorized HTTP GET requests
    ▼
Ubuntu Nginx (192.168.100.226:80)
    │ /var/log/nginx/access.log
    ▼
Elastic Agent / Nginx integration
    │
    ▼
Elasticsearch: logs-nginx.access-default
    │
    ▼
Elastic Security: SOC-WEB-003 Custom Query rule
    │
    ▼
Alert → Analyst investigation → True Positive — Benign → Closed
```

The lab subnet and host restrictions are **environment-specific**. Use only systems for which you have testing authorization; substitute the appropriate approved IPs and hostnames in another deployment.

---

## 3. Prerequisites and Readiness Checks

Before creating the rule, confirm that Elasticsearch and Kibana are available; Nginx serves HTTP on the laboratory interface; the Elastic Agent on `ubuntu-soc-target` is healthy; the Nginx integration reads the access log; and authorized Kali-to-target connectivity exists.

In **Kibana → Discover**, select a data view covering `logs-nginx.access-default`. With a time range containing recent traffic, query:

```kql
event.dataset : "nginx.access" and
host.name : "ubuntu-soc-target"
```

Inspect an expanded access-log event. The principal fields are:

| Field | Use |
|---|---|
| `@timestamp` | Determines when the source request was recorded |
| `event.dataset` | Restricts matching to `nginx.access` |
| `host.name` | Identifies the monitored target |
| `source.ip` | Attributes the request to a source |
| `url.original` | Holds the original request URL, including query string where present |
| `url.path` | Holds a parsed/decoded request path in the tested events |
| `url.query` | Holds query parameters **when present**; not required by this rule |
| `http.request.method` | Provides HTTP method context |
| `http.response.status_code` | Provides server response context |

**Critical distinction:** A field missing from the custom-highlighted-fields selector is not necessarily absent from source telemetry. `url.query` was confirmed in Discover for a request containing a query string, but it is not required by the detection query. HTTP request-body collection was **not** verified.

---

## 4. Verify Query-String Preservation

A harmless request was issued from Kali to establish the available URL fields:

```bash
/usr/bin/curl --silent --output /dev/null \
  --write-out 'HTTP %{http_code}\n' \
  --connect-timeout 5 --max-time 10 \
  'http://192.168.100.226/soc-web-003-field-test?marker=SOCWEB003&value=telemetry-check'
```

**Historically observed response:** HTTP 404.

Inspect the corresponding event in Discover using:

```kql
event.dataset : "nginx.access" and
host.name : "ubuntu-soc-target" and
source.ip : "192.168.100.245" and
url.path : "/soc-web-003-field-test"
```

The original laboratory telemetry showed:

```text
url.path     = /soc-web-003-field-test
url.query    = marker=SOCWEB003&value=telemetry-check
url.original = /soc-web-003-field-test?marker=SOCWEB003&value=telemetry-check
```

**Result: PASS —** The pipeline preserved and extracted query parameters for this request. This test does not imply that POST bodies are indexed.

---

## 5. Verify Encoded and Decoded Traversal Telemetry

### 5.1 Harmless encoded-path test

Execute on the **authorized Kali Linux VM**:

```bash
/usr/bin/curl --path-as-is --silent --output /dev/null \
  --write-out 'HTTP %{http_code}\n' \
  --connect-timeout 5 --max-time 10 \
  'http://192.168.100.226/soc-web-003-test/%2e%2e/harmless-marker'
```

`--path-as-is` prevents curl from normalizing away path segments before transmission. The resource is deliberately nonexistent, and the test does not request sensitive files.

**Historically observed response:** HTTP 404.

The expanded Nginx event showed the encoded indicator as `%2E%2E` in `url.original`, while `url.path` displayed the decoded `..` component. Note that the observed capitalization of hexadecimal escapes may differ from the submitted lowercase request.

### 5.2 Encoded-field KQL check

```kql
event.dataset : "nginx.access" and
host.name : "ubuntu-soc-target" and
source.ip : "192.168.100.245" and
url.original : *%2E%2E*
```

**Historically observed result:** One matching document.

### 5.3 Decoded-field KQL check

```kql
event.dataset : "nginx.access" and
host.name : "ubuntu-soc-target" and
source.ip : "192.168.100.245" and
url.path : */../*
```

**Historically observed result:** One matching document.

**Result: PASS —** Both tested representations were individually searchable in Discover. This establishes KQL search feasibility for the observed event, **not** independent alert-generation coverage of each OR branch.

---

## 6. Create the Elastic Security Custom Query Rule

Navigate to **Kibana → Security → Rules → Detection rules → Create new rule** and select **Custom query**.

### 6.1 Exact configuration

| Setting | Value |
|---|---|
| Name | `SOC-WEB-003 — Potential Path Traversal in HTTP Requests` |
| Type | Custom query |
| Data source | Index patterns |
| Index | `logs-nginx.access-default` |
| Language | KQL |
| Severity | Medium |
| Risk score | 47 |
| Schedule | Every 5 minutes |
| Additional look-back | 1 minute |
| Maximum alerts per run | 100 |
| Alert suppression | Disabled |
| Exceptions | None |
| Automated actions/connectors | None |
| Lab status | Experimental; enabled for controlled testing |
| Author | Elastic SOC Homelab |

### 6.2 Native detection query

```kql
event.dataset : "nginx.access" and
host.name : "ubuntu-soc-target" and
source.ip : * and
(
    url.original : *%2E%2E* or
    url.path : */../*
)
```

The query requires the Nginx dataset, the monitored hostname, a present source IP, and at least one of the two traversal indicators. Unlike SOC-WEB-002, this is **not** a threshold aggregation: matching source events may create individual alerts.

### 6.3 Rule description

> Identifies Nginx HTTP requests containing selected potential directory-traversal indicators in encoded original URLs or decoded paths. A match indicates a suspicious request pattern; it does not confirm successful exploitation, unauthorized file access, or system compromise. Initially scoped to `ubuntu-soc-target` in an authorized SOC homelab. Experimental, limited to tested URL representations.

### 6.4 Tags and references

Recommended tags: `SOC-Homelab`, `SOC-WEB-003`, `Web-Security`, `Nginx`, `Path-Traversal`, `Directory-Traversal`, `HTTP-Request`, `Custom-Query`, `Experimental`, `MITRE-T1190`.

Use `https://attack.mitre.org/techniques/T1190/` as a contextual reference; see Section 11 for mapping cautions.

### 6.5 Custom highlighted fields

Use fields available in the rule editor: `source.ip`, `host.name`, `url.original`, `url.path`, `http.request.method`, and `http.response.status_code`. Include `url.query` only if the editor supports it. The prior selector did not offer `url.query`, which **does not block** this rule.

### 6.6 Scheduling, suppression, and activation

Set the five-minute interval and one-minute additional look-back. Keep alert suppression and automated response actions **disabled** during the initial controlled test so generated alerts can be examined individually. For clean validation, save the rule disabled at first, establish baseline visibility, then enable it before generating fresh test events. The original laboratory workflow followed this pattern.

The six-minute search interval is an **approximation based on scheduled execution**, not a guarantee of continuously evaluated six-minute rolling detection. A subsequent execution-gap warning occurred around a period when the rule had been disabled; it was not separately investigated.

---

## 7. Add Investigation Guidance

The following is an implementation-ready investigation workflow for the rule's **Investigation guide** field:

1. Verify the alert belongs to SOC-WEB-003 and examine its event and alert timestamps.
2. Inspect `source.ip`, `host.name`, `url.original`, `url.path`, HTTP method, and response status.
3. Confirm whether the encoded `%2E%2E` or decoded `/../` pattern appears in the source event.
4. Determine which original Nginx event triggered the alert; do not rely only on highlighted fields.
5. Identify the source asset and establish whether the activity was authorized.
6. Search nearby requests from the source for additional paths, variations, and HTTP 200/400/401/403/404 responses.
7. Investigate any evidence of sensitive-content retrieval, application errors, or associated host activity. A 200 response is not proof of traversal, and a 404 response is not proof that all traversal vectors are prevented.
8. Record the detection hypothesis, observed evidence, uncertainty, and authorization findings.
9. Classify appropriately; for authorized simulation matching the rule, use **True Positive — Benign**.
10. Close authorized benign alerts after documenting findings, or escalate suspected unauthorized activity under the organization's response procedures.

**Optional setup guide content:** Confirm Elastic Agent health, Nginx integration version, `logs-nginx.access-default` ingestion, valid ECS field extraction, appropriate target hostname, and explicit testing authorization. Do not require `http.request.body.content` for this URL-based detection.

---

## 8. Establish the Alert Baseline

In the saved rule's **Alerts** tab, select a relevant time range and document whether the filter is **Open** or **All**. An Open-filter result of zero alerts means zero *visible open alerts*, not necessarily zero historical or closed alerts.

Inspect the **Execution results** tab for recent successful runs and any errors. Establish the timing of test traffic relative to successful rule executions. Old traversal test events should be outside the current evaluation window before commencing a new positive run.

**Historical observation:** The rule was disabled while a baseline was prepared, then re-enabled. The UI showed successful executions with zero created alerts around the negative testing period. An execution-gap warning was observed around disablement and was not investigated further.

---

## 9. Controlled Negative-Test Procedure

### 9.1 Objective

Submit an ordinary request that contains neither configured traversal indicator and examine the enabled rule's behavior.

### 9.2 Command — Kali Linux

```bash
/usr/bin/curl \
  --silent \
  --output /dev/null \
  --write-out 'SOC-WEB-003 Negative Test: HTTP %{http_code}\n' \
  --connect-timeout 5 \
  --max-time 10 \
  'http://192.168.100.226/soc-web-003-negative-live?marker=normal-request'
```

**Historically observed output:** `SOC-WEB-003 Negative Test: HTTP 404`.

The URL contains no `%2E%2E` and no `/../`. HTTP 404 is acceptable because the test resource does not exist.

### 9.3 Verify source telemetry

```kql
event.dataset : "nginx.access" and
host.name : "ubuntu-soc-target" and
source.ip : "192.168.100.245" and
url.path : "/soc-web-003-negative-live"
```

Expected indexed URL fields: `url.path = /soc-web-003-negative-live`, `url.query = marker=normal-request` and `url.original` containing the full request target.

### 9.4 Rule-execution acceptance criteria

For a **fully rigorous** negative test, confirm the precise event `@timestamp`, identify a successful rule execution whose search window covers that event, and verify that execution generated no matching alert. Use the All-alerts view when checking historical alert absence; do not rely solely on the Open filter.

**Historical outcome:** A benign request received HTTP 404; available successful rule executions created zero alerts, and the Open alert view showed none. **However, the exact negative event was not independently tied to a covering successful execution.** Therefore record the result as **expected behavior observed / qualified negative validation**, not an unqualified proof.

---

## 10. Controlled Positive-Test Procedure

### 10.1 Objective

Submit a fresh, authorized request that contains an encoded parent-directory indicator while the detection rule is enabled, then confirm source ingestion and alert generation.

### 10.2 Command — Kali Linux

```bash
/usr/bin/curl \
  --path-as-is \
  --silent \
  --output /dev/null \
  --write-out 'SOC-WEB-003 Positive Test: HTTP %{http_code}\n' \
  --connect-timeout 5 \
  --max-time 10 \
  'http://192.168.100.226/soc-web-003-positive/%2e%2e/harmless-marker'
```

**Historically observed output:** `SOC-WEB-003 Positive Test: HTTP 404`.

### 10.3 Discover verification

```kql
event.dataset : "nginx.access" and
host.name : "ubuntu-soc-target" and
source.ip : "192.168.100.245" and
url.original : *soc-web-003-positive*
```

One matching source document was confirmed with:

```text
source.ip                  192.168.100.245
host.name                  ubuntu-soc-target
url.original               /soc-web-003-positive/%2E%2E/harmless-marker
url.path                   /soc-web-003-positive/../harmless-marker
http.request.method        GET
http.response.status_code  404
```

**Source event timestamp displayed:** November 18, 2026, 23:16:26. Observe that the submitted lowercase `%2e%2e` was represented as uppercase `%2E%2E` in the indexed original URL during testing.

### 10.4 Alert verification

Inspect **Kibana → Security → Alerts** and the rule's **Execution results**. A corresponding alert was observed with:

| Alert attribute | Observed |
|---|---|
| Detection | SOC-WEB-003 — Potential Path Traversal in HTTP Requests |
| Rule category | Custom query |
| Severity | Medium |
| Risk score | 47 |
| Source IP | `192.168.100.245` |
| Host | `ubuntu-soc-target` |
| Original URL | `/soc-web-003-positive/%2E%2E/harmless-marker` |
| Decoded path | `/soc-web-003-positive/../harmless-marker` |
| Response | HTTP 404 |
| Alert timestamp displayed | November 18, 2026, 23:19:48.150 |
| Final workflow status | Closed |

**Positive-test result: PASS.** The approximately three-minute interval between source-event and alert timestamps reflects that specific scheduled execution, not a detection-latency service-level guarantee.

### 10.5 Interpretation

The positive request satisfied **both** branches of the OR query. This proves that the combined native rule detected that request; it does **not** independently prove that either branch would generate an alert if the other were absent. Do not claim independent branch coverage until branch-isolation tests are performed.

---

## 11. MITRE ATT&CK Mapping and Classification

The current rule includes the contextual mapping **Initial Access (TA0001) → Exploit Public-Facing Application (T1190)**. Directory traversal may occur during attempts to exploit a vulnerable web application, but a logged traversal-like string alone does not establish that T1190 exploitation occurred.

The investigation outcome is **True Positive — Benign**: the rule correctly identified the submitted URL indicator, but the source was an authorized Kali Linux simulation. There was no demonstrated successful file access, disclosure, or compromise. Do not reclassify the detected event as a false positive merely because the authorized test was benign.

---

## 12. Investigation and Alert Closure

### 12.1 Investigation findings

- Source: authorized Kali VM `192.168.100.245`.
- Destination: Nginx on `ubuntu-soc-target` (`192.168.100.226`).
- HTTP method: GET; response: 404.
- Suspicious input: `%2E%2E` in `url.original` and `/../` in `url.path`.
- Elasticsearch: the corresponding source event was indexed.
- Detection: SOC-WEB-003 generated a Medium-severity, risk-score-47 Custom Query alert.
- Exploitation: no successful unauthorized file access or system compromise established.

### 12.2 Investigation note and disposition

An Elastic Security investigation note was saved with the request values, timestamps, authorization finding, and conclusion. The alert was **closed** as **True Positive — Benign**. The detection rule was left enabled.

For repeated use, preserve a screenshot of the saved note and a separate screenshot of the closed status. Neither a matching indicator nor an HTTP 404 response alone determines attacker intent.

---

## 13. Evidence Inventory and Repository Paths

The operator verified **10/10 evidence files present and nonempty**. Filename and byte-size checks do **not** constitute independent visual inspection of the screenshots.

### 13.1 Detection evidence

| Evidence filename | Purpose |
|---|---|
| `SOC-WEB-003-rule-overview.png` | Saved rule settings and detection query |
| `SOC-WEB-003-rule-execution.png` | Scheduled execution history |
| `SOC-WEB-003-negative-test.png` | Benign Kali request and HTTP response |
| `SOC-WEB-003-negative-telemetry.png` | Benign request recorded in Discover |
| `SOC-WEB-003-negative-execution.png` | Successful execution(s) with no generated alert |
| `SOC-WEB-003-positive-test.png` | Encoded traversal request and HTTP response |
| `SOC-WEB-003-positive-telemetry.png` | Encoded/decoded URL fields in Discover |
| `SOC-WEB-003-alert-generated.png` | Corresponding generated Elastic Security alert |

Directory: `/home/cybersafe/Elastic-SOC-Homelab/screenshots/05-detection/`.

### 13.2 Investigation evidence

| Evidence filename | Purpose |
|---|---|
| `SOC-WEB-003-investigation-note.png` | Saved investigation narrative |
| `SOC-WEB-003-alert-closed.png` | Final alert closure |

Directory: `/home/cybersafe/Elastic-SOC-Homelab/screenshots/06-investigations/`.

### 13.3 Related project artifacts

```text
/home/cybersafe/Elastic-SOC-Homelab/reports/SOC-WEB-003-investigation.md
/home/cybersafe/Elastic-SOC-Homelab/detection-rules/SOC-WEB-003.yml
/home/cybersafe/Elastic-SOC-Homelab/implementation-guides/SOC-WEB-003-implementation.md
/home/cybersafe/Elastic-SOC-Homelab/implementation-guides/SOC-WEB-003-implementation.pdf
```

The PDF is the intended companion deliverable and must be generated and independently verified from this Markdown source before marking it complete.

---

## 14. Experimental Sigma Representation

The project includes an experimental Sigma rule at `detection-rules/SOC-WEB-003.yml` containing:

- Base `nginx.access` dataset and laboratory hostname selection.
- Required `source.ip` existence check.
- Encoded URL indicator: `url.original|contains: '%2E%2E'`.
- Decoded path indicator: `url.path|contains: '/../'`.
- Boolean condition requiring the base fields plus **at least one** traversal selection.
- Experimental status, Medium level, and contextual ATT&CK T1190 tag.

The operator reported that the **10 custom Python/PyYAML validation checks passed**, including UUID, selections, and Boolean condition. That is **not formal Sigma specification validation**, nor evidence of successful conversion or equivalence on any target backend. Field mapping, case behavior, string normalization, and matching semantics may differ from the native Elastic query.

The native Elastic Custom Query remains the **laboratory-validated reference implementation**. Any Sigma conversion should be tested against a representative corpus of both benign and malicious-looking URL examples before deployment.

---

## 15. Operational Risks, False Positives, and Next Tests

### 15.1 Potential benign matches

Authorized security testing, URL parser testing, development traffic, scanners, and unusual legitimate relative-path requests can contain traversal-looking strings. Investigate source identity and application context before treating a match as hostile.

### 15.2 Potential misses and technical limitations

The rule may miss alternate encodings, double encoding, platform-specific path separators, request-body-only payloads, variations of dot-segment handling, and traffic from hosts/data streams outside the current query. Changes in the Nginx logging format or the Elasticsearch field mapping could alter behavior. The KQL patterns were validated against the observed event, not all possible variants.

### 15.3 Recommended future test matrix — not yet performed

| Planned test | Objective |
|---|---|
| Encoded-only branch | Confirm the encoded expression produces an alert without the decoded branch |
| Decoded-only branch | Confirm the decoded expression independently produces an alert |
| Benign lookalike URLs | Assess false-positive behavior |
| Alternate encodings | Establish actual coverage rather than assume equivalence |
| Query-string and request-body scenarios | Determine where visibility is available and unavailable |
| Multiple sources / hosts | Verify scoping and attribution |
| Scheduling and duplicate-alert testing | Establish evaluation-window and suppression behavior |
| Formal Sigma validation/backend conversion | Assess portability and runtime parity |

Production use requires traffic baselining, rule tuning, response playbooks, and validation against the actual web application architecture. The current scope is a controlled laboratory detection demonstration.

---

## 16. Verification Checklist and Conclusion

### 16.1 Acceptance record

| Milestone | Historical outcome |
|---|---|
| Nginx access-log ingestion | PASS |
| Query-string preservation | PASS for tested GET request |
| Encoded traversal in `url.original` | PASS |
| Decoded traversal in `url.path` | PASS |
| Encoded KQL search | One matching document |
| Decoded KQL search | One matching document |
| Rule saved and enabled | Confirmed |
| Benign negative test | Expected behavior observed; timing qualification applies |
| Encoded traversal positive test | PASS |
| Corresponding Elastic Security alert | Confirmed |
| Investigation note | Saved |
| Alert closure | Completed — True Positive, Benign |
| Evidence files | 10/10 present and nonempty |
| Sigma custom checks | Reported GREEN |
| Formal Sigma backend validation | Not completed |
| Independent OR-branch testing | Not completed |
| Production readiness | Not established |

### 16.2 Conclusion

**SOC-WEB-003 successfully detected the tested URL-encoded traversal indicator** using existing Nginx access-log telemetry and an Elastic Security Custom Query rule. The alert was investigated and closed as a benign authorized test. The negative-test evidence is consistent with the desired no-alert outcome, with the recorded event-to-execution limitation. No successful exploitation was demonstrated.

This guide documents the validated path and preserves explicit boundaries around untested detection variants, native-to-Sigma equivalence, and production deployment.

---

## References

- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [Elastic Security documentation](https://www.elastic.co/docs/solutions/security)
- [Elastic Common Schema](https://www.elastic.co/docs/reference/ecs)
- [Sigma specification](https://sigmahq.io/sigma-specification/)

---

**End of SOC-WEB-003 Technical Implementation Guide**

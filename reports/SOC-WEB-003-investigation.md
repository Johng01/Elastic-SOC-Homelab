# SOC-WEB-003 — Potential Path Traversal in HTTP Requests

**Document Type:** SOC Detection Investigation Report  
**Project:** Elastic SOC Homelab  
**Detection ID:** SOC-WEB-003  
**Investigation Date:** November 18, 2026  
**Detection Type:** Elastic Security Custom Query (KQL)  
**Severity:** Medium  
**Risk Score:** 47  
**Investigation Status:** Completed  
**Alert Classification:** True Positive — Benign  
**Alert Disposition:** Closed  
**Author:** Elastic SOC Homelab

---

## 1. Executive Summary

SOC-WEB-003 identifies potential directory traversal indicators in HTTP requests collected from an Nginx web server. The rule inspects `url.original` for a URL-encoded parent-directory sequence, `%2E%2E`, and `url.path` for a decoded parent-directory component, `/../`.

A controlled test was conducted from Kali Linux (`192.168.100.245`) against the monitored Ubuntu Nginx host (`192.168.100.226`). The benign negative-test request contained neither indicator and returned HTTP 404. Available successful rule executions produced zero alerts, consistent with the intended behavior. However, the precise negative-test event timestamp was not independently correlated with a covering rule execution; the negative result is therefore **qualified**.

The positive test used an encoded parent-directory indicator in a deliberately nonexistent resource path. Nginx returned HTTP 404. Elasticsearch ingested the event and preserved its encoded original URL and decoded path; the enabled Elastic Security custom-query rule generated a Medium-severity alert. The alert was investigated, documented, classified **True Positive — Benign** because the source was an authorized laboratory machine, and closed.

**Verified outcome:** The positive test successfully demonstrated detection of the tested traversal request. No unauthorized file access, data disclosure, or successful exploitation was established.

---

## 2. Investigation Objectives

The investigation evaluated whether the telemetry pipeline preserves encoded and decoded URL representations, whether Kibana KQL can retrieve those indicators, whether benign traffic avoids the configured indicators, whether the enabled rule alerts on a controlled positive request, and whether sufficient context exists to investigate and appropriately classify the alert.

The detection is **not** designed to prove successful exploitation, and this investigation does not claim comprehensive path traversal coverage.

---

## 3. Laboratory Environment and Telemetry

| Component | Configuration |
|---|---|
| Virtualization | QEMU/KVM |
| SIEM | Elastic Security on `elastic-siem` |
| SIEM address | `192.168.100.104` |
| Target hostname | `ubuntu-soc-target` |
| Target OS | Ubuntu Server 24.04.5 LTS |
| Web server | Nginx 1.24.0 |
| Target address and service | `192.168.100.226:80` (HTTP) |
| Authorized test machine | `kali-linux` |
| Source address | `192.168.100.245` |
| Laboratory subnet | `192.168.100.0/24` |
| Collector | Elastic Agent; Nginx integration 3.2.2 |
| Agent policy | `linux-soc-policy` |
| Integration policy | `nginx-web-security-monitoring` |
| Nginx access log | `/var/log/nginx/access.log` |
| Elasticsearch data stream | `logs-nginx.access-default` |
| Dataset | `nginx.access` |

**Telemetry flow:** Kali HTTP GET → Ubuntu Nginx access log → Elastic Agent/Nginx integration → Elasticsearch → SOC-WEB-003 rule → Elastic Security alert → investigation and closure.

All request generation was performed as authorized laboratory testing. Neither external victim infrastructure nor sensitive-file retrieval was involved.

---

## 4. Detection Rule Configuration

| Setting | Observed/configured value |
|---|---|
| Rule name | SOC-WEB-003 — Potential Path Traversal in HTTP Requests |
| Rule type | Custom query |
| Language | KQL |
| Index | `logs-nginx.access-default` |
| Monitored host | `ubuntu-soc-target` |
| Severity | Medium |
| Risk score | 47 |
| Runs every | 5 minutes |
| Additional look-back | 1 minute |
| Maximum alerts per run | 100 |
| Alert suppression | Disabled |
| Rule exceptions | None |
| Automated actions | None |
| MITRE ATT&CK mapping | TA0001 / T1190 (possible association; not confirmed exploitation) |

### 4.1 Native detection query

```kql
event.dataset : "nginx.access" and
host.name : "ubuntu-soc-target" and
source.ip : * and
(
    url.original : *%2E%2E* or
    url.path : */../*
)
```

The rule matches Nginx access events with a source IP and either tested URL indicator. The clauses are joined by `OR`, so a request matching one or both can generate an alert. This is an **individual-event** custom-query detection, not the aggregated threshold model used for SOC-WEB-002.

**Scope limitations:** The rule does not inspect HTTP request bodies. It has not been proven to detect all case, encoding, normalization, separator, double-encoding, or application-specific traversal variants. A matching URL string does not prove malicious intent or successful exploitation.

---

## 5. Telemetry Feasibility Assessment

### 5.1 Query-string parsing

A benign GET request was submitted to:

```text
/soc-web-003-field-test?marker=SOCWEB003&value=telemetry-check
```

Nginx returned HTTP 404. Kibana Discover showed `url.original` retaining the query string, `url.path` containing `/soc-web-003-field-test`, and `url.query` containing `marker=SOCWEB003&value=telemetry-check`. This established that query parameters are available for requests that contain them, even though the field had been absent from earlier events.

### 5.2 Encoded traversal indicator

A controlled test request was submitted with `curl --path-as-is`:

```text
/soc-web-003-test/%2e%2e/harmless-marker
```

Nginx returned HTTP 404. The indexed event showed an encoded `%2E%2E` indicator in `url.original` and a decoded `/../` component in `url.path`.

### 5.3 KQL feasibility tests

**Encoded-field query:**

```kql
event.dataset : "nginx.access" and
host.name : "ubuntu-soc-target" and
source.ip : "192.168.100.245" and
url.original : *%2E%2E*
```

**Observed:** One matching document.

**Decoded-path query:**

```kql
event.dataset : "nginx.access" and
host.name : "ubuntu-soc-target" and
source.ip : "192.168.100.245" and
url.path : */../*
```

**Observed:** One matching document.

These searches demonstrate query feasibility on the same controlled event. They do **not** constitute independent alert-generation tests of each `OR` branch.

---

## 6. Controlled Negative Test

### 6.1 Hypothesis

An ordinary HTTP GET request without `%2E%2E` in `url.original` or `/../` in `url.path` should not match SOC-WEB-003.

### 6.2 Request and command

```bash
/usr/bin/curl \
  --silent \
  --output /dev/null \
  --write-out 'SOC-WEB-003 Negative Test: HTTP %{http_code}\n' \
  --connect-timeout 5 \
  --max-time 10 \
  'http://192.168.100.226/soc-web-003-negative-live?marker=normal-request'
```

**Observed terminal response:**

```text
SOC-WEB-003 Negative Test: HTTP 404
```

The 404 response is expected for a nonexistent resource and is **not** itself a detection failure. The URL lacks both traversal indicators.

### 6.3 Detection observations

The rule was enabled for formal testing. The available execution-history evidence showed successful rule executions with zero alerts, while the alert view showed no visible open alerts for the selected period. An execution-gap notification also appeared around an earlier disablement/reactivation period; the operator attributed it to the rule's disabled interval and elected not to investigate further.

**Assessment:** The observations were consistent with the expected no-alert outcome; **qualified negative-test pass**. The timestamp of the fresh benign request was not independently matched to a successful rule execution window, and the Open alert filter alone cannot establish that there were no acknowledged or closed alerts. These boundaries should be retained in any portfolio claims.

---

## 7. Controlled Positive Test

### 7.1 Hypothesis

A GET request containing the previously verified encoded traversal indicator should be indexed and generate a matching SOC-WEB-003 alert while the rule is enabled.

### 7.2 Request and command

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

**Observed terminal response:**

```text
SOC-WEB-003 Positive Test: HTTP 404
```

The test used a harmless marker rather than attempting to retrieve sensitive files.

### 7.3 Indexed source event

Kibana Discover confirmed one corresponding indexed Nginx event.

| Field | Observed value |
|---|---|
| `source.ip` | `192.168.100.245` |
| `host.name` | `ubuntu-soc-target` |
| `http.request.method` | `GET` |
| `url.original` | `/soc-web-003-positive/%2E%2E/harmless-marker` |
| `url.path` | `/soc-web-003-positive/../harmless-marker` |
| `http.response.status_code` | `404` |
| Source event timestamp displayed | November 18, 2026, 23:16:26 |

### 7.4 Detection alert

Elastic Security generated an alert corresponding to the controlled request.

| Alert attribute | Observed value |
|---|---|
| Rule | SOC-WEB-003 — Potential Path Traversal in HTTP Requests |
| Type | Custom query (`query`) |
| Severity | Medium |
| Risk score | 47 |
| Alert timestamp displayed | November 18, 2026, 23:19:48.150 |
| Original request | Encoded `%2E%2E` parent-directory indicator |
| Decoded path | Contains `/../` |
| Initial status | Open |

The approximate three-minute interval between source event and alert was consistent with scheduled execution in this run, but does not establish a general detection-latency guarantee.

**Assessment:** **Positive detection test PASSED.** The evidence confirms alerting on the submitted request, not successful exploitation.

---

## 8. Investigation and Attribution

The analyst examined the generated alert, source IP, target hostname, encoded and decoded URL values, request method, HTTP response, rule type, severity, and risk score. The source was the authorized Kali Linux laboratory VM. The target was the Ubuntu Nginx server.

The `%2E%2E` sequence corresponds to the parent-directory token `..`, which can be used in traversal attempts. The response was HTTP 404. No successful access to the marker resource was shown, and the available evidence did not establish unauthorized file disclosure, successful application exploitation, remote code execution, or compromise.

An investigation note recording the authorized test, source and destination, URL values, response code, detection result, and absence of confirmed exploitation was saved to the Elastic Security alert.

---

## 9. MITRE ATT&CK Assessment

| Attribute | Mapping |
|---|---|
| Tactic | Initial Access (`TA0001`) |
| Technique | Exploit Public-Facing Application (`T1190`) |

Directory traversal can be associated with attempts to exploit public-facing web applications. Nevertheless, this rule matches a request indicator, not confirmed exploitation. The mapping is **hypothesis-level**, and no evidence establishes that T1190 was completed in this authorized test.

Reference: https://attack.mitre.org/techniques/T1190/

---

## 10. False-Positive, False-Negative, and Coverage Analysis

### 10.1 Potential benign matches

Authorized penetration tests, vulnerability scanners, development tests, URL normalization checks, troubleshooting, and legitimate paths containing relative components may generate similar-looking requests. A true match can therefore still be benign.

### 10.2 Potential missed activity

The rule may miss alternate encodings, double encoding, nonstandard separators, request-body-only payloads, application-specific transformations, telemetry gaps, and requests outside the monitored hostname/data stream. The exact behavior also depends on the mapped fields and query semantics.

### 10.3 Branch-isolation limitation

The positive request satisfied both the encoded and decoded representations. Although separate KQL queries found the original controlled event, no positive test isolated one branch while excluding the other. Do not claim independent alerting validation of both `OR` branches.

### 10.4 Production limitation

No production baseline, false-positive-rate study, exhaustive bypass suite, or independent reproduction has been completed. The rule is a validated **laboratory prototype**, not a production-ready comprehensive path traversal detector.

---

## 11. Classification and Disposition

**Detection result:** True Positive — the alert accurately reflected the configured request indicators.

**Activity classification:** Benign — the request was generated by an authorized laboratory simulation.

**Exploitation confirmed:** No.

**Escalation required:** No.

**Investigation note:** Saved in Elastic Security.

**Alert status:** Closed.

**Detection rule:** Left enabled.

The classification distinguishes correct detection from an actual hostile incident.

---

## 12. Evidence Inventory

All ten named screenshot files were verified to exist in the appropriate repository directories and have nonzero sizes. This file verification did not independently inspect every image visually.

### 12.1 Detection and validation screenshots

Directory: `screenshots/05-detection/`

| No. | Screenshot | Purpose |
|---:|---|---|
| 1 | `SOC-WEB-003-rule-overview.png` | Rule configuration |
| 2 | `SOC-WEB-003-rule-execution.png` | Scheduled execution history |
| 3 | `SOC-WEB-003-negative-test.png` | Benign Kali request |
| 4 | `SOC-WEB-003-negative-telemetry.png` | Indexed benign event |
| 5 | `SOC-WEB-003-negative-execution.png` | Zero-alert execution evidence |
| 6 | `SOC-WEB-003-positive-test.png` | Encoded traversal Kali request |
| 7 | `SOC-WEB-003-positive-telemetry.png` | Indexed encoded/decoded URL |
| 8 | `SOC-WEB-003-alert-generated.png` | Positive detection alert |

### 12.2 Investigation screenshots

Directory: `screenshots/06-investigations/`

| No. | Screenshot | Purpose |
|---:|---|---|
| 9 | `SOC-WEB-003-investigation-note.png` | Saved investigation note |
| 10 | `SOC-WEB-003-alert-closed.png` | Closed disposition |

These files should remain linked to the investigation report and later implementation guide in the GitHub repository.

---

## 13. Validation Matrix

| Validation criterion | Observation | Assessment |
|---|---|---|
| Nginx events ingested | Indexed in Elasticsearch | PASS |
| Query-string visibility | `url.query` populated for query request | PASS |
| Encoded URL visibility | `%2E%2E` observed | PASS |
| Decoded URL visibility | `/../` observed | PASS |
| Encoded KQL feasibility | One document retrieved | PASS |
| Decoded KQL feasibility | One document retrieved | PASS |
| Benign request handling | HTTP 404, no traversal indicator | PASS |
| Negative no-alert evidence | Zero-alert executions/open alerts | QUALIFIED |
| Positive source event | One indexed document | PASS |
| Positive detection | Corresponding alert generated | PASS |
| Source/target attribution | Consistent with lab | PASS |
| Investigation note | Saved | PASS |
| Alert closure | Closed | PASS |
| Independent `OR`-branch alert tests | Not performed | PENDING |
| Production readiness | Not demonstrated | NOT ESTABLISHED |

---

## 14. Recommendations

1. **Keep the rule enabled in the homelab** for continued controlled observation.
2. **Independently test each `OR` branch** with carefully designed cases where only one condition matches.
3. **Test additional encodings and normalization behavior**, documenting both detection and missed matches.
4. **Review related HTTP status codes and request sequences**, including 200, 400, 401, 403, and 404, rather than treating a status code as conclusive proof of exploitation or prevention.
5. **Validate source attribution behind proxies** before broader deployment.
6. **Establish a production-like benign baseline** before changing severity, response automation, or alert suppression.
7. **Keep detection distinctions clear:** SOC-WEB-001 (suspicious individual URLs), SOC-WEB-002 (404-count and path-cardinality aggregation), SOC-WEB-003 (specific traversal-like URL strings).

These are future engineering improvements, not completed tests.

---

## 15. Related Repository Artifacts

| Artifact | Path | Status at report creation |
|---|---|---|
| Investigation report | `reports/SOC-WEB-003-investigation.md` | Current deliverable |
| Sigma representation | `detection-rules/SOC-WEB-003.yml` | Planned |
| Markdown TIG | `implementation-guides/SOC-WEB-003-implementation.md` | Planned |
| PDF TIG | `implementation-guides/SOC-WEB-003-implementation.pdf` | Planned |
| Detection screenshots | `screenshots/05-detection/` | 8 present/nonempty |
| Investigation screenshots | `screenshots/06-investigations/` | 2 present/nonempty |

The Sigma rule and implementation guides should not be represented as complete until they are separately created and verified.

---

## 16. Investigation Conclusion

SOC-WEB-003 successfully identified the controlled positive request containing a URL-encoded parent-directory indicator. Nginx returned HTTP 404; Elastic Agent transported the event into Elasticsearch, where the encoded original URL and decoded path were observable. Elastic Security generated a Medium-severity Custom Query alert, and the analyst documented and closed it as **True Positive — Benign**.

The negative-test observations were consistent with the intended no-alert outcome, with the documented timing-verification limitation. The positive test proved detection of the submitted request, not successful traversal or comprehensive bypass resistance. Independent branch validation and production calibration remain open engineering tasks.

**Investigation:** COMPLETE  
**Positive test:** PASSED  
**Negative test:** QUALIFIED PASS  
**Alert disposition:** CLOSED  
**Documentation/GitHub publication:** PENDING

---

## References

- MITRE ATT&CK T1190: https://attack.mitre.org/techniques/T1190/
- Elastic Security documentation: https://www.elastic.co/docs/solutions/security
- Elastic Common Schema: https://www.elastic.co/docs/reference/ecs
- Sigma documentation: https://sigmahq.io/

---

**End of SOC-WEB-003 Investigation Report**

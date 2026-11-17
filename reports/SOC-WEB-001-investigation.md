# SOC-WEB-001 — Web Reconnaissance and Suspicious URL Requests

## 1. Executive Summary

**Investigation Date:** November 16–17, 2026

**Rule ID:** SOC-WEB-001

**Rule Name:** Web Reconnaissance and Suspicious URL Requests

**Detection Type:** Custom Query (KQL)

**Classification:** True Positive — Benign

**Alert Disposition:** Closed

**Investigation Status:** Completed

SOC-WEB-001 successfully detected an HTTP request targeting the potentially sensitive `/.env` resource on the Ubuntu SOC Homelab's Nginx web server.

The request originated from the authorized Kali Linux test machine at `192.168.100.245` and targeted `ubuntu-soc-target` at `192.168.100.226`.

Nginx returned HTTP `404 Not Found`.

The request was collected through the Nginx integration, indexed in Elasticsearch, and subsequently detected by the SOC-WEB-001 Elastic Security rule.

The generated alert contained the expected source IP address, requested URL path, HTTP response status, severity, risk score, and target hostname.

The activity was intentionally generated for an authorized laboratory validation.

No successful access to the requested sensitive resource was observed.

The alert was investigated and closed as **True Positive — Benign**.

---

## 2. Laboratory Environment

| Component | Configuration |
|---|---|
| SIEM | Elastic Security |
| Elasticsearch | 9.5.5 |
| Target hostname | ubuntu-soc-target |
| Target operating system | Ubuntu Server 24.04.5 LTS |
| Target IP | 192.168.100.226 |
| Web server | Nginx 1.24.0 |
| Web server port | TCP/80 |
| Attack simulation host | kali-linux |
| Simulation source IP | 192.168.100.245 |
| Laboratory network | 192.168.100.0/24 |
| Elastic Agent | 9.5.5 |
| Elastic integration | Nginx |
| Nginx integration version | 3.2.2 |
| Agent policy | linux-soc-policy |
| Integration policy | nginx-web-security-monitoring |
| Access log | /var/log/nginx/access.log |
| Dataset | nginx.access |
| Data stream | logs-nginx.access-default |
| Detection type | Custom Query |

---

## 3. Detection Rule Configuration

| Parameter | Value |
|---|---|
| Rule ID | SOC-WEB-001 |
| Rule type | Custom Query |
| Query language | KQL |
| Index pattern | logs-nginx.access-default |
| Detection scope | ubuntu-soc-target |
| Severity | Medium |
| Risk score | 47 |
| Execution interval | 5 minutes |
| Additional look-back | 1 minute |
| Alert suppression | Disabled |
| Maximum alerts per run | 100 |
| MITRE ATT&CK tactic | Reconnaissance (TA0043) |
| MITRE ATT&CK technique | Active Scanning (T1595) |
| Rule status | Enabled |

### 3.1 Native KQL Detection Query

```kql
event.dataset : "nginx.access" and
host.name : "ubuntu-soc-target" and
url.path : (
  "/.env" or
  "/.git/config" or
  "/server-status" or
  "/wp-admin/" or
  "/phpmyadmin/"
)
```

### 3.2 Detection Logic

The rule identifies Nginx access-log events where the requested URL path matches one of five predefined potentially sensitive resources.

The monitored paths are:

| URL Path | Potential Security Significance |
|---|---|
| `/.env` | Environment configuration that may contain application secrets |
| `/.git/config` | Git repository metadata |
| `/server-status` | Web-server operational information |
| `/wp-admin/` | WordPress administration interface |
| `/phpmyadmin/` | Database administration interface |

The rule does not require multiple requests, repeated failures, or a minimum event count.

Each matching event is independently eligible to generate an alert.

HTTP response status is not part of the matching condition.

Consequently, requests returning `200`, `403`, or `404` may match if their URL paths satisfy the query.

### 3.3 Detection Engineering Considerations

The rule is restricted to the laboratory target using `host.name`.

This restriction reduces unrelated laboratory events but makes the rule unsuitable for direct deployment across multiple production web servers without adaptation.

The selected paths represent a limited set of reconnaissance indicators. The rule is not a comprehensive web-scanning detection system.

The MITRE ATT&CK T1595 mapping describes the reconnaissance scenario being tested. An isolated suspicious URL request does not independently establish a scanning campaign.

---

## 4. Controlled Validation Procedure

### 4.1 Test Objective

Validate that requests targeting suspicious web resources are:

1. Received by Nginx.
2. Recorded in the access log.
3. Collected through the Elastic Agent Nginx integration.
4. Indexed in Elasticsearch.
5. Matched by the SOC-WEB-001 detection query.
6. Converted into Elastic Security alerts.

### 4.2 Initial Five-Path Telemetry Validation

An initial controlled test submitted requests for five monitored resources:

```bash
TARGET="http://192.168.100.226"

for path in "/.env" "/.git/config" "/server-status" "/wp-admin/" "/phpmyadmin/"
do
    printf 'Testing: %-20s ' "$path"

    /usr/bin/curl \
      --silent \
      --output /dev/null \
      --write-out 'HTTP %{http_code}\n' \
      --connect-timeout 5 \
      --max-time 10 \
      "${TARGET}${path}"

    /usr/bin/sleep 2
done
```

All five requests returned HTTP `404`.

Elasticsearch Discover subsequently displayed five matching Nginx events.

These results validated access-log ingestion and KQL matching.

**Limitation:** This preliminary test did not establish that the subsequently created SOC-WEB-001 rule generated an alert for each of the five paths.

### 4.3 Live Detection Validation

Following rule creation and activation, a fresh controlled request was submitted from Kali Linux:

```bash
/usr/bin/curl -v \
  --connect-timeout 5 \
  --max-time 10 \
  'http://192.168.100.226/.env'
```

The successful test produced the following relevant output:

```text
Established connection to 192.168.100.226
from 192.168.100.245

GET /.env HTTP/1.1

HTTP/1.1 404 Not Found

Server: nginx/1.24.0 (Ubuntu)
```

The HTTP response contained the date:

```text
Mon, 16 Nov 2026 17:05:01 GMT
```

The response confirmed that the web server processed the controlled request but did not find the requested resource.

### 4.4 Laboratory Network Recovery

Before the successful live test, Kali's laboratory interface had lost its IPv4 configuration.

The resulting connection attempts incorrectly used Kali's NAT interface.

A dedicated NetworkManager profile was created and activated to restore:

```text
eth0: 192.168.100.245/24
eth1: 192.168.122.10/24
```

Subsequent routing verification established that traffic to `192.168.100.226` used `eth0`.

The successful HTTP request confirmed restoration of the intended laboratory connectivity.

This recovery is included for investigative context. Detailed troubleshooting chronology is not required in the separate successful-path Technical Implementation Guide.

---

## 5. Observed Event Timeline

### 5.1 Initial Telemetry Validation

The following requests were observed in Discover on November 14, 2026.

| Timestamp | Requested URL | HTTP Status |
|---|---|---|
| 09:39:19 | `/.env` | 404 |
| 09:39:21 | `/.git/config` | 404 |
| 09:39:23 | `/server-status` | 404 |
| 09:39:25 | `/wp-admin/` | 404 |
| 09:39:27 | `/phpmyadmin/` | 404 |

All five events identified the source IP as `192.168.100.245`.

These timestamps are recorded as previously displayed in Kibana.

### 5.2 Live Detection

| Event | Observed Time |
|---|---|
| Controlled HTTP request | November 16, 2026, 17:05:01 GMT |
| Elastic Security alert | November 16, 2026, 18:06:08, as displayed in Kibana |

The timestamps use different displayed timezone representations. They should not be directly subtracted to calculate detection latency without normalization and source-event timestamp verification.

---

## 6. Generated Alert Evidence

| Field | Observed Value |
|---|---|
| Rule | SOC-WEB-001 |
| Alert generated | Yes |
| Severity | Medium |
| Risk score | 47 |
| Source IP | 192.168.100.245 |
| Target hostname | ubuntu-soc-target |
| Requested URL | `/.env` |
| HTTP method | GET |
| HTTP response | 404 |
| User agent | curl/8.20.0 |
| Final workflow status | Closed |

Elastic Security generated one confirmed alert corresponding to the controlled `/.env` request.

The alert contained the expected HTTP request attributes and detection metadata.

**Evidence:**

- `screenshots/05-detection/SOC-WEB-001-alert-generated.png`
- `screenshots/05-detection/SOC-WEB-001-nginx-telemetry.png`
- `screenshots/05-detection/SOC-WEB-001-rule-execution.png`

---

## 7. Investigation Findings

### Finding 1 — Suspicious URL Request Confirmed

The source requested:

```text
/.env
```

This path is commonly associated with application environment configuration.

The request matched an explicitly monitored path in the SOC-WEB-001 KQL rule.

### Finding 2 — Source Attribution Confirmed

The request originated from:

```text
192.168.100.245
```

This address belonged to the authorized Kali Linux testing VM.

The destination was the Ubuntu Nginx server at:

```text
192.168.100.226
```

### Finding 3 — HTTP Response Confirmed

Nginx returned:

```text
404 Not Found
```

The available evidence did not show successful retrieval of an environment configuration file.

A `404` response does not establish that the server is free from all sensitive-file exposure risks.

### Finding 4 — Detection Pipeline Confirmed

The request was successfully represented in the Nginx telemetry indexed by Elasticsearch.

Elastic Security matched the request and generated an SOC-WEB-001 alert.

This established successful operation of the tested detection path.

### Finding 5 — Authorized Laboratory Activity

The request was intentionally generated to test the detection rule.

The source system was part of the authorized laboratory environment.

No evidence of an unauthorized attacker was established.

### Finding 6 — Detection Scope Limitation

The five-path preliminary test established matching telemetry for all five monitored paths.

The live Elastic Security alert validation established confirmed alert generation for `/.env`.

The remaining four paths were not individually validated through generated alerts during the documented live test.

---

## 8. MITRE ATT&CK Assessment

| Attribute | Classification |
|---|---|
| Tactic | Reconnaissance |
| Tactic ID | TA0043 |
| Technique | Active Scanning |
| Technique ID | T1595 |

Requests targeting potentially sensitive application resources may occur during reconnaissance and vulnerability discovery.

However, the observed request alone cannot establish a malicious scanning campaign.

The ATT&CK mapping represents the detection hypothesis and authorized simulation scenario rather than independently proven attacker intent.

Reference:

https://attack.mitre.org/techniques/T1595/

---

## 9. False-Positive Assessment

Potential benign sources of matching requests include:

- Authorized vulnerability scanning.
- Penetration testing.
- Administrative troubleshooting.
- Asset discovery.
- Security training.
- Laboratory simulation.

The investigated alert originated from the authorized Kali Linux testing system.

The activity was therefore classified as:

**True Positive — Benign**

The detection correctly identified an event within its intended detection conditions, but the event was not associated with unauthorized malicious activity.

---

## 10. Response and Alert Disposition

The investigation established that:

1. The request originated from an authorized laboratory VM.
2. The targeted resource returned HTTP `404`.
3. Elastic Security correctly generated the expected alert.
4. No successful access to the targeted configuration resource was observed.
5. No incident escalation was required for this authorized test.

An investigation note was saved in Elastic Security.

The alert was subsequently closed.

The SOC-WEB-001 detection rule remained enabled.

**Final classification:** True Positive — Benign

**Final disposition:** Closed

**Investigation status:** Completed

---

## 11. Recommendations

### 11.1 Improve Detection Coverage

Consider additional suspicious URL indicators based on observed threat activity and authorized application exposure.

Avoid indiscriminately expanding the path list without evaluating expected application behavior and false-positive rates.

### 11.2 Add Behavioral Detection

Develop SOC-WEB-002 to identify repeated unsuccessful requests or directory-enumeration patterns.

This will complement SOC-WEB-001's single-request detection logic.

### 11.3 Correlate Source Activity

Investigate suspicious requests alongside source IP, user agent, request frequency, and related web-server errors.

### 11.4 Review Web-Server Hardening

Verify that sensitive files and administrative interfaces are not unintentionally exposed.

### 11.5 Validate Production Portability

Before deploying outside the homelab:

- Remove or appropriately replace the laboratory-specific hostname condition.
- Confirm compatible Nginx integration mappings.
- Evaluate expected administrative traffic.
- Review alert volume and suppression strategy.
- Validate each enabled path against real operational telemetry.

---

## 12. Evidence Inventory

### 12.1 Detection Evidence

| No. | Evidence File | Purpose |
|---|---|---|
| 1 | `screenshots/05-detection/SOC-WEB-001-rule-overview.png` | Detection configuration |
| 2 | `screenshots/05-detection/SOC-WEB-001-rule-execution.png` | Rule execution result |
| 3 | `screenshots/05-detection/SOC-WEB-001-nginx-telemetry.png` | Elasticsearch telemetry |
| 4 | `screenshots/05-detection/SOC-WEB-001-alert-generated.png` | Generated security alert |
| 5 | `screenshots/05-detection/SOC-WEB-001-test-request.png` | Controlled HTTP test |

### 12.2 Investigation Evidence

| No. | Evidence File | Purpose |
|---|---|---|
| 6 | `screenshots/06-investigations/SOC-WEB-001-alert-investigation.png` | Alert investigation |
| 7 | `screenshots/06-investigations/SOC-WEB-001-investigation-note.png` | Analyst findings |
| 8 | `screenshots/06-investigations/SOC-WEB-001-alert-closed.png` | Final alert disposition |

All eight screenshot files were confirmed to exist and contain nonzero data.

Their visual contents should be reviewed before the final GitHub commit.

---

## 13. Investigation Conclusion

SOC-WEB-001 successfully detected a controlled HTTP request targeting the potentially sensitive `/.env` resource.

The test confirmed the operation of the Nginx logging, Elastic Agent ingestion, Elasticsearch indexing, and Elastic Security alert-generation pipeline for the tested request.

The source IP, destination hostname, requested path, response code, and detection metadata were consistent with the intended simulation.

The alert was investigated and closed as **True Positive — Benign**.

No successful access to the targeted resource or unauthorized compromise was established.

**SOC-WEB-001 live detection validation: PASSED**

**SOC-WEB-001 investigation: COMPLETED**

**Portfolio documentation and GitHub publication: PENDING**

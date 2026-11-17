# SOC-WEB-001 — Technical Implementation Guide

**Web reconnaissance and suspicious URL requests**<br>
**Project:** Elastic SOC Homelab | **Version:** 1.0 | **Guide date:** 2026-11-17<br>
**Scope:** Authorized laboratory reproduction | **Status:** Original `/.env` alert functionally validated; this guide has not been independently reproduced end-to-end

## 1. Outcome and scope

Deploy an Elastic Security **Custom Query (KQL)** detection that alerts on individual Nginx HTTP requests for five potentially sensitive paths. Confirm Nginx telemetry reaches Elasticsearch, submit an authorized `GET /.env` from Kali Linux, verify a matching alert, and close the investigated test alert as **True Positive — Benign**.

**Boundary:** This is a *detection deployment guide*, not an installation guide for Elasticsearch, Kibana, Fleet Server, PKI, virtual machines, or the underlying network. Those components must exist and be healthy first. The guide intentionally excludes unsuccessful troubleshooting attempts. The original test confirmed a live alert for **`/.env` only**; the other four paths were observed as matching events in Discover before rule activation.

## 2. Reference laboratory

| Component | Verified reference value |
|---|---|
| SIEM | Elastic Security / Elasticsearch 9.5.5 |
| Target | `ubuntu-soc-target`, Ubuntu Server 24.04.5 LTS |
| Nginx | `nginx/1.24.0 (Ubuntu)` |
| Target lab address | `192.168.100.226/24` (interface `enp1s0`) |
| Target NAT address | `192.168.122.145/24` (interface `enp7s0`) |
| Source VM | Kali Linux, `192.168.100.245/24` (`eth0`) |
| Source NAT | Kali `192.168.122.10/24` (`eth1`) |
| Web listener | `192.168.100.226:80` (lab interface only) |
| Access/error logs | `/var/log/nginx/access.log`; `/var/log/nginx/error.log` |
| Elastic Agent | 9.5.5; policy `linux-soc-policy` |
| Nginx integration | 3.2.2; `nginx-web-security-monitoring` |
| Dataset / data stream | `nginx.access` / `logs-nginx.access-default` |
| Detection | SOC-WEB-001, Custom Query (KQL) |
| MITRE ATT&CK | Reconnaissance TA0043 / Active Scanning T1595 |

## 3. Prerequisites and data contract

1. Elasticsearch, Kibana, Fleet Server, and an Elastic Agent on `ubuntu-soc-target` must be connected and healthy. The Kibana account must be authorized to manage detection rules and alerts.
2. Kali and the Ubuntu target must communicate on the **isolated, authorized** `192.168.100.0/24` laboratory network; do not send tests to public or third-party systems.
3. An Nginx server and its log files must be available on the target. The Nginx integration must collect **access logs**, not merely metrics or errors.
4. Verify the following field contract in **Kibana > Discover** using `logs-nginx.access-default`:

| Field | Expected reference value / purpose |
|---|---|
| `event.dataset` | `nginx.access` |
| `host.name` | `ubuntu-soc-target` |
| `source.ip` | Kali source address, `192.168.100.245` |
| `url.path` | e.g. `/.env` |
| `http.request.method` | `GET` during the positive test |
| `http.response.status_code` | `404` during the observed test |
| `user_agent.original` | `curl/8.20.0` during the observed test |
| `@timestamp` | Parsed event timestamp |
| `log.file.path` | `/var/log/nginx/access.log` |

**Acceptance gate:** The data stream contains parsed Nginx access events with `host.name`, `event.dataset`, and `url.path`. Verify the fields in your environment rather than assuming the same integration mappings.

## 4. Confirm Nginx listener and telemetry on the target

The verified reference deployment bound Nginx to the **lab IP only** to avoid serving the test site on the target's NAT interface. The active default server site was `/etc/nginx/sites-available/default` (enabled by `/etc/nginx/sites-enabled/default`). Its HTTP listener was configured as:

```nginx
listen 192.168.100.226:80 default_server;
# listen [::]:80 default_server;
```

The original deployment used the system Nginx package and restarted Nginx after its configuration was validated. On `ubuntu-soc-target`, verify the existing, authorized deployment:

```bash
sudo nginx -t
sudo systemctl is-active nginx
sudo ss -lntp | grep ':80'
curl -I --connect-timeout 5 http://192.168.100.226/
```

**Expected in the reference lab:** Nginx configuration test succeeds, service is active, the listener is `192.168.100.226:80`, and the local HTTP request receives a response (the reference default page returned `200`). Do not change a production web server's listen directives without assessing all configured virtual hosts and IPv6 requirements.

In **Kibana > Fleet**, confirm `ubuntu-soc-target` reports **Healthy**, with Nginx integration collecting `/var/log/nginx/access.log*` and `/var/log/nginx/error.log*` under the `linux-soc-policy`. In **Discover**, confirm recent events in `logs-nginx.access-default`. The documented integration was Nginx **3.2.2**, with access/error collection enabled and Nginx metrics disabled.

## 5. Create the Elastic Custom Query rule

In **Kibana > Security > Rules > Detection rules > Create new rule**, select **Custom Query**. Use the following reference values:

| Parameter | Exact reference configuration |
|---|---|
| Rule name | `SOC-WEB-001 — Web Reconnaissance and Suspicious URL Requests` |
| Rule type | Custom Query (KQL) |
| Source/index pattern | `logs-nginx.access-default` |
| Severity | Medium |
| Risk score | 47 |
| Runs every | 5 minutes |
| Additional look-back | 1 minute |
| Alert suppression | Disabled |
| Maximum alerts per run | 100 |
| MITRE ATT&CK | TA0043 / T1595 |
| Related integration | Nginx |
| State | Enabled |

**Validated KQL query — paste into the Custom Query editor:**

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

A matching request is independently eligible for an alert; **this is not a frequency threshold or multi-event correlation rule**. HTTP status is intentionally not filtered. Leave alert suppression disabled for initial validation. Save and enable the rule, then confirm **Execution results > Succeeded** before sending live test traffic.

Use a concise description explaining that matched URLs *may* indicate reconnaissance, but do not independently demonstrate malicious intent or exploitation. Record authorized scanning, testing, and administrative access as potential benign contexts.

## 6. Generate authorized test events

On Kali Linux, first verify that the destination routes over the lab interface:

```bash
ip route get 192.168.100.226
```

**Expected reference route:** `192.168.100.226 dev eth0 src 192.168.100.245`. If different, correct the lab's network setup using separately documented infrastructure procedures *before* continuing; do not run tests through an unintended interface.

Submit **one** controlled request from Kali:

```bash
/usr/bin/curl -v \
  --connect-timeout 5 \
  --max-time 10 \
  'http://192.168.100.226/.env'
```

**Observed original test:** the client connected from `192.168.100.245` and received `HTTP/1.1 404 Not Found` from `nginx/1.24.0 (Ubuntu)`. The HTTP Date header was **Mon, 16 Nov 2026 17:05:01 GMT**. A `404` shows only that this requested resource was not found; it is not proof that every sensitive file is inaccessible.

**Optional separate telemetry-only coverage test:** the earlier laboratory run requested `/.env`, `/.git/config`, `/server-status`, `/wp-admin/`, and `/phpmyadmin/`, receiving `404` for all five and observing five matching Discover documents. If you repeat it, label it as a *new* test with its own timestamps. Do not present those original five Discover events as evidence that five rule alerts fired.

## 7. Validate the detection and investigate

1. In **Discover**, select `logs-nginx.access-default`, set a time range including the new request, and verify `host.name`, `source.ip`, `url.path`, `http.response.status_code`, and the source log path.
2. In **Security > Rules**, inspect SOC-WEB-001 **Execution results** and confirm a successful scheduled run. A five-minute interval with one-minute look-back is a scheduling/search-window configuration, *not* a six-minute behavioral correlation.
3. In the SOC-WEB-001 **Alerts** view, include the test period and verify the generated alert. For the original controlled request, the screenshot showed `source.ip: 192.168.100.245`, `url.path: /.env`, HTTP `404`, **Medium**, and risk score **47**.
4. Open the alert and inspect its original Nginx event, source, URL, user agent, response, and related requests. Confirm the source VM and activity were authorized.
5. Add an investigation note. For authorized laboratory traffic with a correctly matching detection, classify **True Positive — Benign** (Kibana may label the close reason **Benign positive**); set the workflow status to **Closed**. Keep the detection enabled.

**Historical reference:** The original alert screenshot displayed **November 16, 2026, 18:06:08** (Kibana display time), whereas the web server Date header used GMT. **Do not calculate detection latency by subtracting these unreconciled display timestamps.**

## 8. Acceptance checklist

| Test | Pass condition |
|---|---|
| Web service | Nginx listening on the authorized lab address |
| Access-log collection | Recent `nginx.access` events in `logs-nginx.access-default` |
| Field mapping | `host.name`, `source.ip`, `url.path`, HTTP status usable |
| Rule compilation | Kibana accepts KQL and enables SOC-WEB-001 |
| Rule execution | Last run status **Succeeded** |
| Positive test | Kali `GET /.env` reaches Nginx and produces an access event |
| Alert | SOC-WEB-001 alert for `/.env`, Medium / risk 47 |
| Investigation | Source, URL, response, authorization recorded |
| Disposition | Note saved; alert closed as benign-positive authorized test |
| Evidence | Eight named screenshots retained in repository |

## 9. Evidence and maintained artifacts

The following artifact paths were established for the completed investigation:

- `reports/SOC-WEB-001-investigation.md` — investigation findings and limitations.
- `detection-rules/SOC-WEB-001.yml` — experimental Sigma representation (YAML parsing and eight custom semantic checks passed; **formal pySigma/backend validation remains outstanding**).
- `screenshots/05-detection/SOC-WEB-001-rule-overview.png`.
- `screenshots/05-detection/SOC-WEB-001-rule-execution.png`.
- `screenshots/05-detection/SOC-WEB-001-nginx-telemetry.png`.
- `screenshots/05-detection/SOC-WEB-001-alert-generated.png`.
- `screenshots/05-detection/SOC-WEB-001-test-request.png`.
- `screenshots/06-investigations/SOC-WEB-001-alert-investigation.png`.
- `screenshots/06-investigations/SOC-WEB-001-investigation-note.png`.
- `screenshots/06-investigations/SOC-WEB-001-alert-closed.png`.

All eight screenshots were verified to exist and have nonzero file sizes on the Ubuntu host; **their complete visual contents have not been independently audited in this guide's preparation**.

**Version control:** Commit the approved Markdown and a PDF generated from that same source. Preserve evidence filenames and review exports for passwords, tokens, credentials, and other secrets.

## 10. Adaptation for training and client environments

These are **deployment considerations, not production-validated procedures**:

- Replace `host.name: ubuntu-soc-target` with properly scoped production assets; confirm integration and ECS mappings.
- Consider baseline request patterns, approved scanners, reverse proxies, NAT/source attribution, and application-specific paths before broad deployment.
- Review potential duplicate alerts, ingestion latency, alert volume, and the use of suppression in the operational SOC.
- Distinguish a successful HTTP response from evidence of confidential data exposure; a `404` is not proof of comprehensive hardening.
- Apply server-side access controls and least privilege to sensitive resources; never rely on detection rules alone to protect them.
- Coordinate timestamps, log retention, RBAC, detection ownership, and alert response workflows.
- The experiment's T1595 mapping is a **reconnaissance hypothesis**: one matching request is not proof of an active scanning campaign.
- Independently test Sigma parsing and conversion for each target backend before replacing the native Elastic KQL rule.

## 11. Source and verification status

**Established from the completed SOC-WEB-001 investigation and command outputs:** working lab routing, Nginx HTTP `404` response to `/.env`, indexed Nginx telemetry, successful rule execution, generated alert with matching attributes, saved investigation note, closed alert, and eight nonempty screenshot files. The earlier five-path test was confirmed in Discover, not through five independent rule alerts.

**Not independently established:** a fresh start-to-finish reproduction of this written TIG, independent visual inspection of every repository screenshot, formal Sigma schema validation, Sigma backend conversion, or production deployment readiness. The base infrastructure installation is documented separately.

**Further reading:** [MITRE T1595](https://attack.mitre.org/techniques/T1595/) · [Elastic Security documentation](https://www.elastic.co/docs/solutions/security)

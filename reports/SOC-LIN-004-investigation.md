# SOC-LIN-004 - Linux Account Creation and Privilege Modification

**Document type:** SOC detection investigation report  
**Project:** Elastic SOC Homelab  
**Detection ID:** SOC-LIN-004  
**Evidence period:** November 19-23, 2026  
**Report prepared:** November 23, 2026  
**Classification:** Authorized laboratory test; positive alerts True Positive - Benign  
**Completion status:** Controlled detection tests passed; November 23 alert investigation note saved and alert closed (operator-confirmed); temporary account, sudo membership, and home directory removed and verified. Formal Sigma backend validation remains outstanding.

---

## 1. Executive summary

SOC-LIN-004 monitors successful Linux audit *syscalls* made by the account-management programs `useradd` and `usermod` against files monitored with the key `soc_lin_004_account_change`. The native Elastic Security Threshold rule generated a Medium-severity alert after a controlled account-comment change and again following a controlled sudo-group assignment. The November 23 positive alert grouped six matching syscall records for one process (PID `9550`); this is **six records, not six different privilege assignments**. The controlled `touch /etc/group` negative test was ingested and was not followed by a new rule alert in the covering scheduled run.

Both positive tests occurred on an authorized isolated Ubuntu target. The rule does not itself distinguish `usermod -aG sudo` from ordinary `usermod` modifications, and a successful individual syscall does not prove complete command success or malicious intent.

## 2. Environment and scope

| Component | Observed configuration |
|---|---|
| Monitored VM | `ubuntu-soc-target`, Ubuntu Server 24.04.5 LTS, `192.168.100.226` |
| SIEM | `elastic-siem` / Elasticsearch / Kibana / Elastic Security |
| Collection | Existing Elastic Agent 9.5.5, `linux-soc-policy` |
| Integration | Auditd Logs, `auditd-linux-security-monitoring`, namespace `default` |
| Source log | `/var/log/audit/audit.log` (`ENRICHED`, write_logs `yes`) |
| Dataset/index | `auditd.log` / `logs-auditd.log-default` |
| Audit rules file | `/etc/audit/rules.d/50-soc-lin-004.rules` |
| Audit key | `soc_lin_004_account_change` |
| Test account | `soctest004`, UID observed `1001` |
| Rule type | Threshold, grouped by `host.id` and `process.pid`, threshold 1 |

## 3. Audit policy and host verification

Persistent audit rules used:

```text
-w /etc/passwd -p wa -k soc_lin_004_account_change
-w /etc/shadow -p wa -k soc_lin_004_account_change
-w /etc/group -p wa -k soc_lin_004_account_change
-w /etc/gshadow -p wa -k soc_lin_004_account_change
-w /etc/sudoers -p wa -k soc_lin_004_account_change
-w /etc/sudoers.d/ -p wa -k soc_lin_004_account_change
```

- `auditd` installed, enabled, active; `auditctl -s` observed `enabled 1`, PID `5869`, `lost 0` at inspection.
- `augenrules --load` executed; `auditctl -l` returned all six active watches.
- `touch /etc/passwd` produced local audit sequence `820` with `comm=touch`, `exe=/usr/bin/touch`, `auid=cybersafe`, `euid=root`, and `/etc/passwd` PATH.
- Local audit records for `useradd` showed account database modification and successful `rename` operations across `/etc/passwd`, `/etc/shadow`, `/etc/group`, and `/etc/gshadow` (e.g., sequences `848-851`).
- Local audit records for `usermod -aG sudo soctest004` showed successful modifications to `/etc/group` and `/etc/gshadow` (sequences `1027-1028`).
- `id soctest004` initially confirmed `groups=1001(soctest004),27(sudo)`.

## 4. Ingestion and audit-record reconstruction

Discover search `event.dataset : "auditd.log" and host.name : "ubuntu-soc-target"` returned **727 documents** in the observed window. A new `touch /etc/group` generated a successfully indexed event. Audited syscall sequence `1151` had five Elasticsearch documents with identical timestamp:

| Record type | Count | Verified payload |
|---|---:|---|
| `SYSCALL` | 1 | `process.executable=/usr/bin/touch`, audit key, original user, `openat`, success |
| `PATH` | 2 | `/etc/` parent and `/etc/group` (`auditd.log.name`, `nametype=NORMAL`) |
| `CWD` | 1 | Current working directory record |
| `PROCTITLE` | 1 | `auditd.log.proctitle=/usr/bin/touch^@/etc/group` |

These are **separate indexed documents**; a plain KQL match cannot treat fields from different records as if they lived in one document. `auditd.log.sequence` helps analysts correlate within the same host and period. `log.file.path=/var/log/audit/audit.log` describes the log source, **not** the modified account file.

## 5. Native Elastic rule configuration

| Parameter | Saved value |
|---|---|
| Name | SOC-LIN-004 - Linux Account Creation and Privilege Modification |
| Index | `logs-auditd.log-default` |
| Type | Threshold |
| Severity / risk | Medium / 47 |
| Group by | `host.id`, `process.pid` |
| Threshold | 1 |
| Runs | Every 5 minutes |
| Look-back | 1 minute additional |
| Max alerts per run | 100 (observed screenshot) |
| MITRE | TA0003 / T1136 / T1136.001 (context for account creation only) |
| Suppression | Disabled per configuration workflow |

```kql
event.dataset : "auditd.log" and
host.name : "ubuntu-soc-target" and
auditd.log.record_type : "SYSCALL" and
auditd.log.key : "soc_lin_004_account_change" and
auditd.log.success : true and
(
    process.executable : "/usr/sbin/useradd" or
    process.executable : "/usr/sbin/usermod"
)
```

A matching audit syscall is **not** an alert for a successful completed `useradd` or `usermod` command; the final operation outcome must be verified separately. `useradd` and `usermod` are combined in this rule and cannot be distinguished in the threshold alert without source-document investigation.

## 6. Positive test 1 - account comment modification

**Test command:**

```bash
/usr/bin/sudo /usr/sbin/usermod --comment "SOC-LIN-004 controlled detection test" soctest004
```

**Observed results:**

- Scheduled execution at **November 21, 2026 02:21:11.182** succeeded and created **one** alert.
- Alert timestamp **02:21:11.341**; Medium severity; risk 47; Open at investigation.
- Threshold result count **3**, grouping process PID **8103**.
- Discover showed three matching SYSCALL records for PID 8103, executable `/usr/sbin/usermod`, source timestamps around **02:20:41**.
- Investigation note saved; analyst marked the authorized result **True Positive - Benign** and closed the alert (user-confirmed).

**Verdict:** PASS for detecting audited `usermod` modification. This test is not a sudo-assignment-specific validation.

## 7. Negative test - unrelated executable

**Test command:**

```bash
/usr/bin/sudo /usr/bin/touch /etc/group
```

**Observed records:**

- Source `SYSCALL` on **November 23, 2026 at 09:08:29.990** (Kibana displayed local time).
- Indexed by **09:08:40**, executable `/usr/bin/touch`, process PID `9497`, audit sequence `2041`, audit user `cybersafe`.
- Relevant successful scheduled executions at **09:09:33.531**, **09:14:36.506**, **09:19:36.515**, **09:24:39.702**, and **09:29:42.517** each showed **0 alerts created**.

**Verdict:** PASS for the controlled negative test. The 09:09:33 run followed the source event by approximately one minute and is consistent with a 5-minute schedule plus 1-minute look-back covering it; the screenshots do not independently expose the exact Elasticsearch query interval bounds. The event's executable is outside the detection's `useradd`/`usermod` filter.

## 8. Positive test 2 - sudo-group assignment

**Preparation:** The authorized laboratory operator removed `soctest004` from `sudo` using `gpasswd -d soctest004 sudo`, then re-added it with:

```bash
/usr/bin/sudo /usr/sbin/usermod -aG sudo soctest004
```

**Observed results:**

- Scheduled execution **November 23, 2026 at 09:44:39.670**: Succeeded; **1 alert**.
- Alert timestamp **09:44:39.865**, severity Medium, risk score 47, Open when captured.
- Threshold result count **6**; process PID **9550**.
- Discover returned **six** matching SYSCALL records for process `9550`, executable `/usr/sbin/usermod`, audit key `soc_lin_004_account_change`, source events at **09:41:43.495-09:41:43.693**.

**Verdict:** PASS for alert generation and source-process attribution associated with the authorized sudo-group assignment. Command intent comes from the operator's executed command; the latest six SYSCALL documents alone do **not** prove the parsed `sudo` argument, final membership post-test, or completion of the alert investigation. Those are explicit evidence boundaries.

## 9. False positives and classification

Expected benign triggers include authorized onboarding/offboarding, normal changes to shells or comments, approved sudo-group provisioning, configuration management, service-account creation, package installation, incident-response actions, and lab simulations. A correctly matched authorized command is **True Positive - Benign**, not a detection false positive. Multiple matched syscalls from one program are **redundant records**, not multiple unrelated attacks.

## 10. Final investigation closure and account cleanup — November 23, 2026

The operator saved the final investigation note for the `09:44:39.865` alert (PID `9550`) and confirmed that the alert status was changed to **Closed**. The classification recorded was **True Positive — Benign (Authorized Laboratory Simulation)**. The operator saved both positive-alert and closed-alert screenshots.

After preserving the alert evidence, the operator executed:

```bash
/usr/bin/sudo /usr/sbin/userdel --remove soctest004
```

`userdel` warned that `/var/mail/soctest004` did not exist; this was not an account-removal failure. Subsequent `/usr/bin/id soctest004` returned **no such user**. A further explicit test returned **GREEN: Sudo membership removed** and **GREEN: Home directory removed**. These observations establish the cleanup of this local test account; they do not constitute a comprehensive assessment of all credential or filesystem artifacts.

**Source of closure and cleanup assertions:** operator confirmations and terminal outputs in the project conversation, not a remote machine inspection by the document author.

### Outstanding engineering limits

1. Formal Sigma syntax/backend conversion and parity with the native threshold rule have **not** been performed.
2. Repeated overlapping-window executions and PID-reuse edge cases have **not** been independently stress-tested.
3. No independent saved-rule **useradd positive alert** was verified; account-creation *audit telemetry* was verified.
4. The native threshold alert proves an associated `usermod` process, not indexed `-aG sudo` command-line semantics without related-record corroboration.

## 11. MITRE ATT&CK

Account creation maps contextually to **Persistence / Create Account: Local Account** (`T1136.001`). `usermod` comment changes or group membership modification cannot automatically be classified as Create Account. Suspicious access manipulation might warrant a different technique mapping following case-specific verification. No observed malicious persistence or exploitation is claimed.

## 12. Evidence and publication

- Screenshots confirmed saved **on the operator's Ubuntu host repository**, not embedded in this downloadable package:
  - `screenshots/05-detection/SOC-LIN-004-sudo-positive-alert.png`
  - `screenshots/05-detection/SOC-LIN-004-sudo-positive-source-events.png`
  - `screenshots/05-detection/SOC-LIN-004-negative-test-source-events.png`
  - `screenshots/05-detection/SOC-LIN-004-negative-test-zero-alerts.png`
  - `screenshots/06-investigations/SOC-LIN-004-sudo-alert-closed.png`
- Do not claim evidence files were uploaded to GitHub until they have been committed and pushed.
- Investigation report: `reports/SOC-LIN-004-investigation.md`.
- TIG: `implementation-guides/SOC-LIN-004-implementation.md` and companion PDF.
- Native rule configuration: `detection-rules/SOC-LIN-004-rule.md`.
- Experimental Sigma: `detection-rules/SOC-LIN-004.yml`.

**End of SOC-LIN-004 investigation report.**

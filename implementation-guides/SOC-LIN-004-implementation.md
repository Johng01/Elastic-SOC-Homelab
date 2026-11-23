# SOC-LIN-004 - Linux Account Creation and Privilege Modification

**Document type:** Technical Implementation Guide (TIG)  
**Project:** Elastic SOC Homelab  
**Detection ID:** SOC-LIN-004  
**Lab verification:** November 19-23, 2026  
**Document prepared:** November 23, 2026  
**Deployment:** Native Elastic Security Threshold rule, laboratory validated for tested account-modification activity.  
**Risk classification:** Experimental detection, not a generalized privilege-grant detector.

---

## 1. Purpose and detection boundary

Deploy Linux audit monitoring to identify account-management syscalls made by `useradd` or `usermod`. Demonstrate a complete auditd -> Auditd Logs integration -> Elastic Agent -> Elasticsearch -> Elastic Security pipeline. The rule monitors syscalls that accessed/wrote account-control data and does not independently distinguish the exact group membership granted. Its name is a monitoring hypothesis, not proof of privilege escalation.

## 2. Laboratory architecture

| Component | Configuration |
|---|---|
| Hypervisor | QEMU/KVM |
| SIEM | `elastic-siem` |
| Ubuntu target | `ubuntu-soc-target`, Ubuntu 24.04.5 LTS, `192.168.100.226` |
| Original user | `cybersafe` |
| Test account | `soctest004` (created in isolated lab) |
| `auditd` | Running as service; kernel auditing `enabled 1` |
| Agent | Existing Elastic Agent 9.5.5 / Fleet |
| Agent policy | `linux-soc-policy` |
| Fleet integration | Auditd Logs; policy `auditd-linux-security-monitoring` |
| Source log | `/var/log/audit/audit.log` |
| Data stream | `logs-auditd.log-default` |
| Dataset | `auditd.log` |

**Telemetry path:** Linux audit syscall + path + proctitle records -> auditd writes `/var/log/audit/audit.log` -> Elastic Agent Auditd Logs file input -> Elasticsearch dataset -> Elastic Threshold rule -> alert -> investigation. `Auditd Manager` is not used because `auditd` owns the kernel audit stream.

## 3. Prerequisites and protective constraints

Work only on authorized Linux infrastructure. The operator must have administrative access to the target and Kibana rule-authoring privileges. Before creating any watch file, inspect `auditctl -l` to avoid overwriting legitimate policy. Installing `auditd` changes the operating system's audit service, so avoid conflicting kernel audit consumers. Preserve Elastic Agent and other Fleet integrations. Use the dedicated test account only in the isolated lab.

## 4. Install and verify the daemon

The historical lab installation used:

```bash
/usr/bin/sudo /usr/bin/apt-get update && /usr/bin/sudo /usr/bin/apt-get install -y auditd audispd-plugins
```

Check:

```bash
/usr/bin/sudo /usr/sbin/auditctl -s
/usr/bin/systemctl is-enabled auditd
/usr/bin/systemctl is-active auditd
```

Observed: `enabled 1`, failure mode `1`, daemon running, service active/enabled, and `lost 0` when checked. This is a point-in-time observation, not a future zero-loss guarantee.

## 5. Configure persistent host audit rules

Path: `/etc/audit/rules.d/50-soc-lin-004.rules`.

```text
-w /etc/passwd -p wa -k soc_lin_004_account_change
-w /etc/shadow -p wa -k soc_lin_004_account_change
-w /etc/group -p wa -k soc_lin_004_account_change
-w /etc/gshadow -p wa -k soc_lin_004_account_change
-w /etc/sudoers -p wa -k soc_lin_004_account_change
-w /etc/sudoers.d/ -p wa -k soc_lin_004_account_change
```

Apply via `/usr/bin/sudo /usr/sbin/augenrules --load`, then confirm `/usr/bin/sudo /usr/sbin/auditctl -l` returns all six rules. These are file watches for write/attribute operations and do not by themselves establish which account change succeeded.

## 6. Audit daemon storage

Validated settings:

```ini
write_logs = yes
log_file = /var/log/audit/audit.log
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
```

These settings enabled the working file-backed collection pipeline. Do not infer immediate durability from asynchronous flushing.

## 7. Onboard Auditd Logs into Fleet

1. Kibana -> Fleet -> Integrations -> **Auditd Logs** (not Auditd Manager).
2. Integration name: `auditd-linux-security-monitoring`.
3. Description: collect account-management and sensitive-file auditd records for Linux security monitoring.
4. Agent policy: `linux-soc-policy` and namespace `default`.
5. Enable `Collect Auditd application logs (input: logfile)`.
6. Path: `/var/log/audit/audit.log*`.
7. Save. Fleet should distribute the policy automatically. Do not restart the already functional `auditd` or Elastic Agent without a specific diagnosed issue.

A Discover query for `event.dataset : "auditd.log" and host.name : "ubuntu-soc-target"` returned 727 matching documents in a prior observation window, establishing successful file ingestion. Older audit records were also seen, but collection of rotated historical records depends on input behavior and file availability.

## 8. Verified fields and multi-record model

| Field | Meaning |
|---|---|
| `auditd.log.key` | Custom watch rule key |
| `auditd.log.record_type` | `SYSCALL`, `PATH`, `CWD`, `PROCTITLE` |
| `auditd.log.sequence` | Local audit-event ID for correlating separate documents |
| `auditd.log.success` | Result of audited syscall, **not** complete command result |
| `auditd.log.SYSCALL` | Syscall name |
| `auditd.log.proctitle` | Command-line arguments, `^@` separators |
| `auditd.log.name` | Actual PATH record target; `/etc/` may be parent |
| `process.executable` | Executable recorded on SYSCALL events |
| `process.pid` | Process identifier, used in threshold grouping |
| `user.audit.name` | Original authenticated identity (`cybersafe` observed) |
| `user.effective.name` | Effective user (`root` observed) |
| `log.file.path` | **Audit log file**, not account database path |

Audit sequence `1151` yielded five documents: SYSCALL 1, PATH 2, CWD 1, PROCTITLE 1. A PATH document confirmed `auditd.log.name=/etc/group`, `auditd.log.nametype=NORMAL`. Event reconstruction requires host/time/sequence correlation; do not write KQL assuming the PATH and SYSCALL fields share a source document.

## 9. Create the Elastic Threshold rule

**Rule name:** SOC-LIN-004 - Linux Account Creation and Privilege Modification.

**Type:** Threshold. **Index:** `logs-auditd.log-default`.

**KQL:**

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

**Settings:**

| Field | Value |
|---|---|
| Group by | `host.id`, `process.pid` |
| Threshold | 1 |
| Count-field configuration | None |
| Severity | Medium |
| Risk score | 47 |
| Schedule | Every 5 minutes + 1 minute look-back |
| Alert suppression | Off |
| Automated actions | None |
| Rule state | Enabled in test screenshots |
| MITRE | TA0003 / T1136 / T1136.001, limited to creation activity |
| Max alerts per run | 100 (observed UI) |

**Suggested tags:** `SOC-Homelab`, `SOC-LIN-004`, `Linux-Security`, `Auditd`, `Account-Management`, `Privilege-Modification`, `Persistence`, `Experimental`.

## 10. Setup guide, investigation guide, false-positive examples

**Setup guide:** Document active auditd, persistent watches, Auditd Logs integration and input path, index, data mapping, KQL, grouped threshold settings, and validation boundaries.

**Investigation:** Confirm alert host/PID/count; retrieve source SYSCALL documents for host/PID, and identify corresponding `PROCTITLE` and `PATH` documents using host identity + sequence + timeframe; verify intended account/privileged group from command line; confirm authorization and resulting host state where possible. Record final classification and alert closure.

**Benign triggers:** authorized account provisioning, changes to existing shells/comments, approved sudo-group changes, configuration management, service-account provisioning, package maintenance, incident response, and authorized laboratory tests. A correctly fired alert on authorized activity is **True Positive - Benign**; duplicate matches across syscalls are not automatically false positives.

## 11. Controlled audit host tests (historical)

### 11.1 Audit watch proof

```bash
/usr/bin/sudo /usr/bin/touch /etc/passwd
```

Local `ausearch -k soc_lin_004_account_change -ts recent -i` displayed the resulting `/usr/bin/touch` event, `auid=cybersafe`, `euid=root`, file `/etc/passwd`, syscall `openat`. This proves the audit watch; it is not an account-creation test.

### 11.2 Account creation

```bash
/usr/bin/sudo /usr/sbin/useradd --create-home --shell /usr/sbin/nologin soctest004
```

Local audit recorded `useradd` modifications to `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` and subsequent `id` established account existence. The native saved-rule was not independently tested using a fresh `useradd` after rule activation.

### 11.3 Sudo-group assignment

```bash
/usr/bin/sudo /usr/sbin/usermod -aG sudo soctest004
```

Initial lab audit showed `usermod` activity and `id soctest004` showed `27(sudo)`. Later, after temporarily removing sudo group membership via `gpasswd`, the same command was executed for the final positive-rule test. **Do not rerun on an already privileged account merely to create duplicate evidence.**

## 12. Positive test 1: benign account comment

```bash
/usr/bin/sudo /usr/sbin/usermod --comment "SOC-LIN-004 controlled detection test" soctest004
```

- Nov 21 **02:21:11.182** scheduled execution: success, **1** alert.
- Alert timestamp **02:21:11.341**, process PID `8103`, result count `3`, severity Medium, risk 47.
- Discover: three corresponding `/usr/sbin/usermod` SYSCALL documents at ~02:20:41.
- Investigation note saved and first alert closed as authorized **True Positive - Benign**.

**Outcome:** PASS for general account modification. Rule did not parse the account comment itself as its matching predicate.

## 13. Negative test: different executable

```bash
/usr/bin/sudo /usr/bin/touch /etc/group
```

- Indexed `touch` SYSCALL at Nov 23 **09:08:29.990**, ingested 09:08:40, PID `9497`, audit seq `2041`.
- Successful scheduled executions at 09:09:33, 09:14:36, 09:19:36, 09:24:39, 09:29:42 each created **0** alerts.
- The first execution is consistent with the defined search window covering this event. Exact window boundaries were not independently exported.

**Outcome:** PASS for the tested exclusion. No claim of immunity to all unrelated account-file changes.

## 14. Positive test 2: sudo-group assignment

**Operator sequence:** remove lab test account `soctest004` from `sudo` with `gpasswd -d`, then perform fresh `usermod -aG sudo soctest004`.

- Nov 23 **09:44:39.670** scheduled run succeeded; **1 alert**.
- Alert timestamp **09:44:39.865**, severity Medium, risk 47; threshold result count **6**; PID **9550**.
- Discover showed six matching `SYSCALL` records for `process.pid=9550`, `/usr/sbin/usermod`, key `soc_lin_004_account_change` around **09:41:43.495-09:41:43.693**.
- Source-event screenshot is confirmed saved in the operator's Ubuntu host repository; screenshot image files are **not** bundled with this documentation package.

**Outcome:** PASS for detection and executable attribution associated with authorized sudo-group assignment, **not** independent determination of sudo command arguments by the threshold rule. The operator subsequently saved an investigation note classifying the alert **True Positive — Benign**, closed the alert, and saved the closure screenshot. These are operator-confirmed actions, not independent platform inspections.

## 15. Alert investigation and closure workflow

1. Capture rule overview, execution log and original alert (timestamp, count, PID, host).
2. Query the raw audit dataset using the grouped `host.id` and `process.pid` from the alert.
3. Find corresponding `PROCTITLE` and `PATH` via audit sequence and timestamp to confirm arguments and file target; note the multi-document structure.
4. Check whether the account/group change was authorized and whether resulting state matches the command.
5. Classify accurately: authorized matching event = True Positive - Benign.
6. Save the alert investigation note and close the alert once fully reviewed. For the second test, note-saving and closure were confirmed by the operator on November 23, 2026.

## 16. Implementation risks, portability and future checks

- The rule is **broader than its title**: it alerts on any qualifying `useradd` and `usermod` syscalls, not only privileged account creation.
- `auditd.log.success:true` is syscall success, not the final account-management operation status.
- Grouping by `host.id` + `process.pid` aggregates records within one evaluation window, not indefinitely. PID reuse and overlapping windows can generate additional alerts.
- Threshold alerts contain aggregated fields and often omit source event process arguments, audit user and target file. Recover these from original records.
- Different kernel architectures, audit rules, distro commands and integration mappings may not produce identical fields.
- Sigma representation is experimental and expresses the **base event selection only**; threshold aggregation, scheduling and suppression are outside plain Sigma rule parity.
- A separate, more specific correlation rule is needed to claim `usermod -aG sudo` detection based on indexed command-line arguments.
- Laboratory account `soctest004` was removed after evidence collection. `/usr/bin/id soctest004` reported no such user; sudo-group membership and home directory absence were checked and reported GREEN.

## 17. Evidence matrix and completion gate

| Evidence | Status |
|---|---|
| Persistent audit rules loaded | Confirmed via `auditctl -l` |
| Host audit `touch` record | Confirmed |
| Host `useradd` / `usermod` records | Confirmed |
| `id` showed sudo membership after initial assignment | Confirmed |
| Auditd Logs ingestion and parsed field mapping | Confirmed |
| Positive account-comment alert | Confirmed; note saved, alert closed |
| Negative `touch` no-alert test | Confirmed for tested event |
| Positive sudo-assignment-associated alert | Confirmed; source process correlated |
| Second alert note and closure | Operator-confirmed; final alert closed, screenshot saved |
| Laboratory test-account cleanup | Confirmed by `id` and separate sudo-membership/home-directory checks |
| Formal Sigma validation/backend parity | **Not performed** |
| Screenshot inventory | Five files operator-confirmed saved on host; screenshots are not included in this downloadable package |

### Final screenshot inventory (saved on physical Ubuntu host)

- `screenshots/05-detection/SOC-LIN-004-sudo-positive-alert.png`
- `screenshots/05-detection/SOC-LIN-004-sudo-positive-source-events.png`
- `screenshots/05-detection/SOC-LIN-004-negative-test-source-events.png`
- `screenshots/05-detection/SOC-LIN-004-negative-test-zero-alerts.png`
- `screenshots/06-investigations/SOC-LIN-004-sudo-alert-closed.png`

These files were saved by the operator and must be included in the Git commit; they are not embedded in this archive.

**Conclusion:** The controlled SOC-LIN-004 detection workflow demonstrated successful alert generation for two authorized `usermod` operations and correct exclusion of an unrelated audited executable. Full privilege-grant semantics require related-record investigation. The final alert investigation and laboratory-account cleanup are complete based on operator confirmations and checks; formal Sigma portability remains unvalidated.

## References

- [Elastic Auditd Logs integration](https://www.elastic.co/docs/reference/integrations/auditd)
- [Elastic Security detection rules](https://www.elastic.co/docs/solutions/security/detect-and-alert)
- [Sigma rule specification](https://sigmahq.io/sigma-specification/)
- [MITRE ATT&CK T1136.001](https://attack.mitre.org/techniques/T1136/001/)

**End of SOC-LIN-004 Technical Implementation Guide.**

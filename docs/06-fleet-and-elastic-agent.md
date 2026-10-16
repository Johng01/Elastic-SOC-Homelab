# Fleet and Elastic Agent

This document merges the former empty `06-Fleet.md` and `06-Elastic-Agent.md` placeholders because Fleet management and agent enrollment form one operational workflow.

## Status

**Operational and validated — October 2026.**

Fleet Server and Elastic Agent are running in the active Dell laptop
SOC homelab using Elastic Stack 9.5.5.

This deployment is separate from the Dell PowerEdge R710 environment,
which remains offline pending hardware repair.

### Verified deployment

| Component | Verified state |
|---|---|
| Elastic Stack | Version 9.5.5 |
| Fleet Server | Operational on `elastic-siem` |
| Fleet Server policy | `fleet-server-policy` |
| Fleet Server agent | Healthy |
| Windows endpoint | `windows-client` |
| Windows agent policy | `windows-soc-policy` |
| Windows Elastic Agent | Healthy |
| Windows integration | System integration collecting Security logs |
| Event ingestion | Windows Security Events 4624 and 4625 validated |
| Detection | SOC-WIN-001 successfully generated threshold alerts |

### Connectivity and certificate validation

- Fleet Server uses HTTPS with a certificate issued by the internal SOC Homelab Root CA.
- The lab root CA was installed in the Windows Local Machine trusted root store.
- Fleet Server health was confirmed through its `/api/status` endpoint.
- Windows Elastic Agent enrollment completed successfully without `--insecure`.
- Both Fleet-managed agents were subsequently confirmed Healthy.

### Detection validation

The Windows integration forwards authentication events to the
`logs-system.security-default` data stream.

SOC-WIN-001 detected repeated failed authentication attempts during
authorized local testing.

The investigation identified an IPv6 loopback source (`::1`), consistent
with the controlled local test.

Remote authentication testing using Kali Linux remains pending.

Supporting evidence:

- [Detection Rule](../detection-rules/SOC-WIN-001.md)
- [Investigation Report](../reports/SOC-WIN-001-investigation.md)
- [Detection Screenshots](../screenshots/05-detection/README.md)
- [Investigation Screenshots](../screenshots/06-investigations/README.md)


## Deployment sequence

1. Configure Fleet settings and outputs.
2. Create separate policies for Windows, Linux, and web-server workloads.
3. Add only the integrations required by each policy.
4. Deploy Fleet Server if the chosen topology requires it.
5. Enroll agents using short-lived credentials.
6. Confirm agent health and expected data streams.
7. Revoke or rotate exposed enrollment tokens.

## Validation

- Agent status is Healthy.
- Host identity and policy assignment are correct.
- Expected data streams contain recent events.
- Timestamps and time zones are correct.
- Integration errors are investigated before detection testing.

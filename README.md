# Elastic SOC Homelab

A hands-on blue-team portfolio project for collecting Windows, Linux, and web-server telemetry in Elastic Security, engineering detections, and documenting investigations.

> **Status (October 2026):** Active development on a Dell laptop running Ubuntu Desktop 26.04.1. The laptop hosts an operational Elastic Security 9.5.5 environment using KVM/libvirt. Fleet Server and Windows Elastic Agent are healthy, Windows Security logs are being ingested, and SOC-WIN-001 and SOC-WIN-002 failed-logon detection rules have been successfully validated. The original Dell PowerEdge R710 environment, running Elasticsearch and Kibana 9.3.3, is currently offline pending repair.

## Objectives

- Build a defensible Elastic Security lab.
- Ingest Windows Event Logs, Linux authentication logs, and web-server logs.
- Detect failed-login bursts, privilege escalation, and suspicious process execution.
- Record repeatable investigation procedures and evidence.
- Maintain a portfolio-quality repository without publishing secrets or private keys.

## Current environment

### Active SOC homelab — Dell laptop

| Component | Current state |
|---|---|
| Physical host | Dell laptop running Ubuntu Desktop 26.04.1 |
| Virtualization | KVM/QEMU with libvirt |
| SIEM VM | `elastic-siem` |
| Elasticsearch | 9.5.5 — operational |
| Kibana | 9.5.5 — operational |
| Fleet Server | Operational |
| Elastic Agent | Healthy on `elastic-siem` and `windows-client` |
| Windows endpoint | Windows Enterprise Evaluation VM |
| Kali endpoint | Kali Linux 2026.2 VM — remote authentication testing validated |
| Windows telemetry | Security Event IDs 4624 and 4625 validated |
| Detection engineering | SOC-WIN-001 and SOC-WIN-002 validated |
| Investigation | Local and remote authentication investigations completed |
| Network | Isolated `lab-net` (`192.168.100.0/24`) and libvirt `default` NAT for selected VM internet access |

### Original SOC environment — Dell PowerEdge R710

| Component | Current state |
|---|---|
| Physical server | Dell PowerEdge R710 |
| Operating system | Ubuntu Server |
| Elasticsearch | 9.3.3 — previously operational |
| Kibana | 9.3.3 — previously operational |
| Availability | Offline pending repair |
| Upgrade | To be evaluated after hardware restoration |

The two environments are separate. The successful SOC-WIN-001 and SOC-WIN-002 validations apply to the active laptop-based environment, not the currently offline R710.


## Repository map

| Path | Purpose |
|---|---|
| [docs](docs/) | Architecture, deployment, PKI, detection, and investigation documentation |
| [diagrams](diagrams/) | Architecture and PKI visuals |
| [screenshots](screenshots/) | Evidence organized by project phase |
| [detection-rules](detection-rules/) | Elastic detection-rule exports and documentation |
| [sigma](sigma/) | Portable Sigma rules |
| [yara](yara/) | YARA rules used in endpoint investigations |
| [procedures](procedures/) | Repeatable SOC runbooks |
| [reports](reports/) | Sanitized investigation reports |
| [scripts](scripts/) | Safe automation and validation scripts |

## Documentation

1. [Lab architecture](docs/01-lab-architecture.md)
2. [PKI design and implementation](docs/02-pki-design-and-implementation.md)
3. [Installation baseline](docs/03-installation.md)
4. [Elasticsearch configuration](docs/04-elasticsearch.md)
5. [Kibana configuration](docs/05-kibana.md)
6. [Fleet and Elastic Agent](docs/06-fleet-and-elastic-agent.md)
7. [Log-source onboarding](docs/07-log-source-onboarding.md)
8. [Detection engineering](docs/08-detection-engineering.md)
9. [Incident investigation](docs/09-incident-investigation.md)
10. [Troubleshooting](docs/10-troubleshooting.md)
11. [Lessons learned](docs/11-lessons-learned.md)
12. [Future intermediate-CA migration](docs/12-pki-migration-to-intermediate-ca.md)

See [the follow-up audit](docs/13-repository-audit-2026-10-08.md), [certificate inventory](docs/14-certificate-inventory.md), and [asset provenance](docs/15-asset-provenance.md) for evidence limits and preservation checks.

See [Screenshot Guide](screenshots/README.md) for the evidence naming standard and [CHANGELOG](CHANGELOG.md) for repository changes.

## Security boundary

This repository contains documentation and sanitized evidence only. It must never contain private keys, certificate archives, keystores, passwords, enrollment tokens, API keys, real public IP addresses, or unredacted personal data. See [.gitignore](.gitignore).

## Detection engineering progress

### Completed and validated

- [SOC-WIN-001 — Multiple Failed Logon Attempts](detection-rules/SOC-WIN-001.md): Windows Event ID 4625 threshold detection.
- [SOC-WIN-001 Investigation Report](reports/SOC-WIN-001-investigation.md): Authorized local authentication test, event correlation, source IP verification, and benign-positive classification.
- [SOC-WIN-002 — Multiple Remote Failed Logon Attempts](detection-rules/SOC-WIN-002.md): Windows Event ID 4625, Logon Type 3, source-IP threshold detection validated using Kali Linux and RDP/NLA.
- [SOC-WIN-002 Investigation Report](reports/SOC-WIN-002-investigation.md): Five remote authentication failures, successful alert generation, source-IP attribution, and benign-positive disposition.
- [Detection evidence](screenshots/05-detection/README.md): Rule configuration, execution, and generated alert.
- [Investigation evidence](screenshots/06-investigations/README.md): Windows authentication events and source IP analysis.

### Planned detection use cases

- Failed-to-successful authentication correlation across Windows endpoints.
- Windows privilege-group and privilege-use events.
- Suspicious PowerShell and LOLBin execution.
- Linux SSH authentication failures.
- Linux `sudo` and account-change activity.
- Web reconnaissance and repeated error responses.


## Author

John Victor Olumiye — SOC Analyst / Blue Team portfolio project.

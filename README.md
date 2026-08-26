# Elastic SOC Homelab

A hands-on blue-team portfolio project for collecting Windows, Linux, and web-server telemetry in Elastic Security, engineering detections, and documenting investigations.

> **Status:** Active build. Elasticsearch 9.3.3 is operational; the custom HTTP PKI work is documented. Kibana, Fleet, agent onboarding, log-source integrations, detections, and investigations remain in progress.

## Objectives

- Build a defensible Elastic Security lab.
- Ingest Windows Event Logs, Linux authentication logs, and web-server logs.
- Detect failed-login bursts, privilege escalation, and suspicious process execution.
- Record repeatable investigation procedures and evidence.
- Maintain a portfolio-quality repository without publishing secrets or private keys.

## Current environment

| Component | Current state |
|---|---|
| SIEM server | Ubuntu 24.04, hostname `elastic-siem` |
| Elasticsearch | 9.3.3, HTTPS enabled |
| Kibana | Enrollment/configuration in progress |
| Fleet / Elastic Agent | Planned |
| PKI | Password-protected lab root CA and HTTP certificate workflow documented |
| Network | NetworkManager with DHCP on `enp1s0` |

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

See [Screenshot Guide](screenshots/README.md) for the evidence naming standard and [CHANGELOG](CHANGELOG.md) for repository changes.

## Security boundary

This repository contains documentation and sanitized evidence only. It must never contain private keys, certificate archives, keystores, passwords, enrollment tokens, API keys, real public IP addresses, or unredacted personal data. See [.gitignore](.gitignore).

## Planned detection use cases

- Windows Event ID 4625 failed-logon burst
- Windows privilege-group and privilege-use events
- Suspicious PowerShell and LOLBin execution
- Linux SSH authentication failures
- Linux `sudo` and account-change activity
- Web reconnaissance and repeated error responses

## Author

John Victor Olumiye — SOC Analyst / Blue Team portfolio project.

# Changelog

All notable repository changes are recorded here. Dates use YYYY-MM-DD.

## [Unreleased]

### Added

- Onboarded the Windows Enterprise Evaluation endpoint into Elastic Fleet using
  the `windows-soc-policy` agent policy.
- Verified Windows Security Event IDs 4624 and 4625 in Elasticsearch.
- Created and validated SOC-WIN-001, a threshold detection rule for repeated
  failed Windows authentication attempts.
- Validated the rule using two controlled local authentication tests.
- Added the SOC-WIN-001 detection documentation and sanitized investigation report.
- Added references to the validated detection in the detection engineering,
  incident investigation, detection-rules, and reports documentation.

- Created and validated SOC-WIN-002, a source-IP-grouped threshold
  detection for repeated failed Windows network authentication.
- Added SOC-WIN-002 detection documentation and investigation report.
- Updated detection engineering, incident investigation, and project
  overview documentation to include SOC-WIN-002.

### Changed

- Updated the Windows failed-logon detection status from Planned to
  Validated — Local Authentication.
- Strengthened `.gitignore` to recursively exclude nested credentials and
  secrets directories.
- Documented the distinction between source events in Discover and aggregated
  threshold alerts.

- Completed Kali Linux remote authentication detection validation.
- Extended the documented detection coverage from local authentication
  failures to remote source-IP-based authentication monitoring.

### Verified

- Fleet Server and Windows Elastic Agent reported Healthy.
- Windows Security Event ID 4625 ingestion was confirmed.
- SOC-WIN-001 generated alerts for two different test usernames.
- The second test produced six matching events.
- The source address `::1` was verified in Windows and Elasticsearch.
- The investigated test alert was closed following authorized-test classification.

- Five controlled RDP/NLA authentication failures were generated
  from Kali Linux (192.168.100.245).
- Windows Security Event ID 4625 recorded the originating IP
  and Logon Type 3.
- Elastic Security generated the SOC-WIN-002 threshold alert
  with a matching event count of five.
- No matching successful network logons from Kali were found
  during the investigated 17:30–18:00 window on 2026-10-17.
- The SOC-WIN-002 alert was classified as benign positive
  and closed after investigation.

### Planned

- Capture additional Kibana, Elasticsearch CA-trust, and browser TLS evidence.
- Complete Linux agent onboarding.
- Ingest web-server logs.
- Add and validate Sigma detection rules.
- Add sanitized screenshots supporting SOC-WIN-001.

## [0.3.0] - 2026-10-08

### Changed

- Audited the already merged restructuring and preserved the Fleet/Agent merge and existing naming.
- Separated historical HTTP TLS evidence, transport configuration, reported Kibana service activity, and planned certificate deployment.
- Scoped directory ignore rules to root-level workspaces while keeping private-key and archive exclusions.
- Clarified proposed architecture and PKI diagram limitations.

### Added

- Follow-up audit, certificate inventory, diagram guide, complete PKI screenshot index, and asset hash manifest.

### Preserved

- All original documents and all 19 binary assets; no useful content deleted.

## [0.2.1] - 2026-08-26

### Fixed

- Scoped credential-related ignore rules so legitimate detection content such as password-spray and token-theft rules remains trackable.
- Labelled the original PKI design diagram as a superseded proposal where it conflicts with implemented paths.
- Labelled Kibana and Fleet certificate rows in the original inventory image as planned rather than deployed current state.

## [0.2.0] - 2026-08-26

### Added

- Portfolio-ready project overview and status.
- PKI design and implementation documentation.
- Architecture, installation, Elasticsearch, Kibana, Fleet, onboarding, detection, investigation, troubleshooting, lessons-learned, and migration documents.
- Screenshot naming and sanitization guide.
- Security-focused `.gitignore`.
- Placeholder READMEs for future rules, procedures, reports, and scripts.

### Changed

- Standardized Markdown filenames to lowercase kebab-case.
- Merged the overlapping Fleet and Elastic Agent documents.
- Corrected “Agent Development” to “Log Source Onboarding.”
- Standardized PKI screenshot names to `pki-NNN-description.png`.
- Standardized diagram filenames to lowercase kebab-case.

### Preserved

- All 15 substantive PKI screenshots.
- All four substantive diagrams.
- Existing project history on `main`.

### Removed

- One-byte placeholder files that contained no project information.

## [0.1.0] - 2026-08-02

### Added

- Initial repository scaffold.
- PKI evidence screenshots and diagrams.

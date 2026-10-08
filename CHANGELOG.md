# Changelog

All notable repository changes are recorded here. Dates use YYYY-MM-DD.

## [Unreleased]

### Planned

- Capture fresh Kibana service, Elasticsearch CA trust, and browser TLS validation evidence.
- Configure Fleet and onboard Windows/Linux agents.
- Ingest web-server logs.
- Add tested Elastic and Sigma detection rules.
- Publish the first sanitized investigation report.

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

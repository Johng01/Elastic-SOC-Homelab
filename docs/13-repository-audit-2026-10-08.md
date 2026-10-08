# Repository Follow-up Audit — 2026-10-08

## Baseline and finding

Audited `main` at `6a7f14d54b7d7b42ed3e73db0e300186637d0c00` (merged PR #1). The earlier restructuring is already present: numbered lowercase document names, merged Fleet/Agent workflow, corrected onboarding name, 15 consistently named PKI screenshots, and four preserved diagrams. Repeating those moves would add churn without improving the portfolio.

## Changes and exact documentation updates

| Files | Update |
|---|---|
| `README.md`, `docs/05-kibana.md`, `CHANGELOG.md` | Distinguish user-reported Kibana service activity from unverified connection/browser TLS; retain planned work |
| `docs/02-pki-design-and-implementation.md`, `docs/04-elasticsearch.md`, `docs/14-certificate-inventory.md` | Separate custom HTTP PEM deployment, transport keystore, older HTTP assets, and future certificates; index exact historical paths |
| `docs/01-lab-architecture.md`, `diagrams/README.md` | Classify architecture and all PKI diagrams as proposals or conceptual views |
| `screenshots/01-pki/README.md`, `screenshots/README.md` | Link every PKI screenshot to its supported claim; clarify naming and review limits |
| `.gitignore` | Anchor runtime/secret directories at repository root so nested documentation and evidence remain trackable; retain conservative key/container exclusions |
| `docs/09-incident-investigation.md` | Allow synthetic isolated lab addresses consistently with existing evidence, while excluding sensitive organizational topology |
| `docs/15-asset-provenance.md` | Record SHA-256 hashes for all 19 existing binary assets |

The original August audit remains unchanged as a historical record. The previous Fleet/Agent merge is retained; PKI implementation and future intermediate-CA migration remain separate because they describe different states.

## Validation and limits

- All existing image assets retained byte-for-byte; see provenance manifest.
- Local relative Markdown targets checked for existence.
- Screenshot and document naming checked against the current convention.
- Ignore behavior checked with representative rule, documentation, evidence, and secret paths.
- Images visually reviewed as a contact sheet: no visible secret values or private-key bodies identified. This review cannot certify that every pixel is sanitized. Hostnames, lab private addresses, UUIDs, and certificate metadata remain visible.
- No live VM access, certificate-expiry measurements, ingestion tests, or detection execution performed.

## Next portfolio gate

Collect current Elasticsearch and Kibana status plus successful CA-trusted connection evidence. Then onboard one log source, demonstrate one controlled event in Discover, and build/test the Windows 4625 detection or Linux authentication detection. Until that exists, this is an infrastructure build portfolio rather than evidence of operational SOC detection work.

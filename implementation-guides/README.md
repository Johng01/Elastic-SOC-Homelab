# Technical Implementation Guides (TIG)

Each TIG is a successful-path, reproducible deployment procedure for one homelab project or detection implementation. It is separate from the investigation report (observations and disposition) and detection documentation (logic and tuning).

## Publishing standard

- Document objective, tested versions, prerequisites, telemetry fields, exact commands, configuration, test, validation, acceptance criteria, evidence, and operational limitations.
- Omit troubleshooting chronology, unsuccessful experiments, secrets, and credentials. Retain essential security and safety requirements.
- Identify **verified historical settings** versus **reconstructed procedures** and **unverified production adaptations**. Never invent commands to fill historical gaps.
- Maintain one authoritative Markdown source and export a **matching PDF** for offline retention. Both should use the same base filename and version. Review the PDF visually before publishing.
- Store guide Markdown and its PDF together in `implementation-guides/`. Retain downloadable offline backups on the engineer's laptop and external storage; do not commit secrets or client data.
- Validate Git links, Markdown headings, code fences, PDF text extraction, and any attached evidence before merging.

## Guides

| Guide | Status | Implementation |
|---|---|---|
| SOC-LIN-003 | Initial TIG prepared; end-to-end reproduction not yet retested | [Markdown](SOC-LIN-003-implementation.md) · [PDF](SOC-LIN-003-implementation.pdf) |

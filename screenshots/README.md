# Screenshot Evidence Guide

## Naming standard

Use lowercase kebab-case:

```text
<phase>-<sequence>-<short-description>.png
```

Examples:

- `pki-001-workspace-structure.png`
- `elasticsearch-001-service-status.png`
- `kibana-001-enrollment-success.png`
- `fleet-001-agent-healthy.png`
- `detection-001-windows-4625-rule.png`
- `investigation-001-alert-timeline.png`

Sequence numbers are three digits and restart inside each phase directory.

## Current evidence

The [PKI index](01-pki/README.md) maps all 15 existing screenshots to supported claims. Retain sequence numbers when adding evidence; use the next unused number and update the phase index and relevant document. Do not invent capture dates from filenames.

Synthetic or isolated RFC1918 lab addresses may remain for reproducibility; redact sensitive real-world topology. Review full-resolution images before publication; `.gitignore` cannot sanitize pixels or remove already tracked secrets.

## Required sanitization

Before committing, remove or obscure passwords, private keys, enrollment/service tokens, API keys, cookies, email addresses, public IP addresses, device identifiers, and unrelated browser or terminal content.

## Evidence rule

A screenshot supports a documented claim; it does not replace the explanation. Reference each useful screenshot from the relevant Markdown document or report.

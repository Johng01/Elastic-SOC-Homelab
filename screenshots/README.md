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

## Required sanitization

Before committing, remove or obscure passwords, private keys, enrollment/service tokens, API keys, cookies, email addresses, public IP addresses, device identifiers, and unrelated browser or terminal content.

## Evidence rule

A screenshot supports a documented claim; it does not replace the explanation. Reference each useful screenshot from the relevant Markdown document or report.

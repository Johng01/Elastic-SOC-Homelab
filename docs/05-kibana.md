# Kibana

## Status

The user reported Kibana running on 2026-08-26 and configured `elasticsearch.hosts` as `["https://elastic-siem:9200"]`. That is historical host information, not a fresh verification performed during this audit. The repository has no Kibana validation screenshots yet.

Track these separately:

| Connection | Evidence status |
|---|---|
| Kibana service running | User-reported on 2026-08-26; fresh service output pending |
| Kibana → Elasticsearch HTTPS | Hostname configured; successful CA trust/connection evidence pending |
| Browser → Kibana HTTPS | Certificate deployment and browser validation not established |

An active service does not prove either TLS path works. The earlier CA-path error (`curl: (77)`) also requires a documented resolution; do not infer success from configuration alone.

## Completion criteria

- Kibana connects to Elasticsearch using the trusted CA.
- Kibana listens only on the intended interface.
- Browser access uses a hostname covered by the certificate SAN.
- Saved objects and encryption keys are configured appropriately.
- Elastic Security loads without connection or certificate errors.
- No enrollment token, service token, cookie, or password is captured in screenshots.

## Evidence to collect

Follow the [screenshot naming standard](../screenshots/README.md) and capture service status, trusted Elasticsearch connection, browser TLS validation, and the Elastic Security landing page.

# Kibana

## Status

Kibana enrollment and final TLS validation are in progress.

## Completion criteria

- Kibana connects to Elasticsearch using the trusted CA.
- Kibana listens only on the intended interface.
- Browser access uses a hostname covered by the certificate SAN.
- Saved objects and encryption keys are configured appropriately.
- Elastic Security loads without connection or certificate errors.
- No enrollment token, service token, cookie, or password is captured in screenshots.

## Evidence to collect

Follow the [screenshot naming standard](../screenshots/README.md) and capture service status, trusted Elasticsearch connection, browser TLS validation, and the Elastic Security landing page.

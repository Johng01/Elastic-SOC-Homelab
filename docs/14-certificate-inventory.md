# Certificate Inventory and Evidence States

As of the repository audit on 2026-10-08. These are historical evidence states, not a live certificate scan. No certificate bytes or private keys belong in this inventory.

| Purpose | Historical path | Issuer / validity | Evidence state |
|---|---|---|---|
| Custom root CA | `/opt/elastic-pki/ca/ca/ca.crt`; encrypted key beside it as `ca.key` | Self-signed; creation records state 3650 days / 4096-bit key; exact validity dates and fingerprint need live output | Created: screenshots 002–003; not evidence of offline storage |
| Custom Elasticsearch HTTP leaf | Staged beneath `/opt/elastic-pki/generated/http/test-staging/elastic-http/`; deployed `/etc/elasticsearch/certs-managed/http/elastic-http.crt` and `elastic-http.key` | Custom root; generation requests 1095 days / 4096 bits; exact issued dates/serial pending | Historical configuration and authenticated TLS checks: 006, 010–015 |
| Deployed HTTP trust anchor | `/etc/elasticsearch/certs-managed/http/ca.crt` | Must match intended custom root; fingerprint comparison pending | Used without `-k` in 012–014 |
| Elasticsearch transport | `/etc/elasticsearch/certs/transport.p12` (relative `certs/transport.p12` in configuration) | Issuer, SANs, validity, and relationship to custom root unverified | Configured in 015; no independent chain validation evidence |
| Earlier auto-generated HTTP assets | `http_ca.crt`, `http.p12`; full live location pending | Unverified | Earlier host record; active use not established after custom PEM deployment |
| Browser-facing Kibana HTTPS | Deployment path not established | Unverified | Planned / evidence pending; separate from Kibana trusting Elasticsearch |
| Fleet Server HTTPS | Deployment path not established | Unverified | Planned; no deployment evidence |

HTTP SANs shown in screenshot 010: `elastic-siem`, `localhost`, `127.0.0.1`, and `192.168.100.104`. Changes to client hostnames or IPs require SAN review.

## Complete the live inventory

For each certificate, record subject, issuer, SANs, serial, SHA-256 fingerprint, `notBefore`, `notAfter`, owner/mode, consuming service, last successful validation date, and renewal deadline. Read certificates locally; never export private-key contents or keystore passwords. A requested lifetime is not a measured expiry date.

Compare the root and deployed trust-anchor fingerprints. Validate HTTP and transport separately. Confirm the current `elasticsearch.yml` before recording a path as active. Validate Kibana's two TLS connections separately. Record findings here and link sanitized evidence using the screenshot guide.

The original inventory image's “Active” labels and root expiry are planning claims, not measured inventory values. Preserve that image as history; use this table for status.

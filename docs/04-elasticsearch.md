# Elasticsearch

## Confirmed state

| Setting | Value |
|---|---|
| Version | 9.3.3 |
| Node name | `elastic-siem` |
| Cluster name | `elasticsearch` |
| HTTP bind | `0.0.0.0` |
| Transport bind | `0.0.0.0` |
| HTTP security | TLS and authentication enabled |

The TLS assets include `http_ca.crt`, `http.p12`, and `transport.p12`; relevant passwords are stored in the Elasticsearch keystore.

## Hardening notes

Binding to `0.0.0.0` increases exposure. Host firewall rules and network segmentation must restrict access to approved lab systems. Do not expose ports 9200 or 9300 directly to the public Internet.

## Health checks

```bash
sudo systemctl is-active elasticsearch
sudo journalctl -u elasticsearch --since today --no-pager
curl --cacert /path/to/http_ca.crt -u elastic https://localhost:9200
curl --cacert /path/to/http_ca.crt -u elastic https://localhost:9200/_cluster/health?pretty
```

Record sanitized output and the exact version after material upgrades.

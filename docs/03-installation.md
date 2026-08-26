# Installation Baseline

## Confirmed platform

- Ubuntu 24.04
- Elasticsearch 9.3.3 installed from a Debian package
- NetworkManager managing `enp1s0` through the `netplan-enp1s0` connection
- HTTPS enabled for Elasticsearch

## Safe installation principles

1. Record package versions and repository sources.
2. Back up configuration and keystores before material changes.
3. Bind services only to required interfaces.
4. keep authentication and TLS enabled.
5. Validate service health after every change.
6. Never publish generated passwords or enrollment tokens.

## Existing backup evidence

A dated local backup was created under `/opt/elastic-backup/2026-08-02/`, including certificates, `elasticsearch.yml`, and later the Elasticsearch keystore. This path describes the lab host; its contents must not be committed.

## Verification baseline

```bash
sudo systemctl status elasticsearch --no-pager
curl --cacert /path/to/ca.crt -u elastic https://localhost:9200
```

The final test should trust the CA explicitly. `curl -k` is acceptable only for diagnosis, never as proof that PKI validation works.

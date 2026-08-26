# Troubleshooting

## TLS trust warning

Check the certificate chain, SANs, client hostname, CA path, file permissions, and system clock. Do not make `-k` a permanent workaround.

## HTTP 401

A 401 response proves that HTTPS reached Elasticsearch but authentication failed or was missing. Verify the intended user and credential source; do not paste passwords into documentation.

## No default route

Confirm NetworkManager state, connection profile, DHCP lease, and routing. The lab previously used `netplan-enp1s0` on `enp1s0`.

## Service failure after configuration change

Review `journalctl`, validate YAML syntax and paths, compare against the dated backup, and revert only the specific faulty change.

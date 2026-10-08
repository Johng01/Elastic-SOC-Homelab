# PKI Evidence Index

Historical evidence preserved byte-for-byte. Sequence numbers identify workflow order, not capture dates. All filenames already follow the repository standard; no cosmetic renaming was needed in the follow-up audit.

| Screenshot | What it supports |
|---|---|
| [pki-001-workspace-structure.png](pki-001-workspace-structure.png) | Workspace and nested directory layout |
| [pki-002-root-ca-created.png](pki-002-root-ca-created.png) | CA output locations |
| [pki-003-encrypted-root-ca-key-verification.png](pki-003-encrypted-root-ca-key-verification.png) | Encrypted CA key check; no key contents displayed |
| [pki-004-certificate-instance-definition.png](pki-004-certificate-instance-definition.png) | Original instance definition |
| [pki-005-http-certificate-request.png](pki-005-http-certificate-request.png) | HTTP-specific instance definition |
| [pki-006-http-certificate-generation-success.png](pki-006-http-certificate-generation-success.png) | HTTP issuance command and successful archive generation |
| [pki-007-http-certificate-archive.png](pki-007-http-certificate-archive.png) | Generated archive and instance-file listing |
| [pki-008-http-certificate-archive-contents.png](pki-008-http-certificate-archive-contents.png) | Archive member listing; no extracted key contents |
| [pki-009-http-certificate-staging-permissions.png](pki-009-http-certificate-staging-permissions.png) | Staging ownership and permission changes |
| [pki-010-http-certificate-san-validation.png](pki-010-http-certificate-san-validation.png) | HTTP subject and SAN inspection |
| [pki-011-http-certificate-key-match.png](pki-011-http-certificate-key-match.png) | Matching public-key SHA-256 hashes |
| [pki-012-http-tls-validation-localhost.png](pki-012-http-tls-validation-localhost.png) | Authenticated localhost HTTPS response without insecure bypass |
| [pki-013-http-tls-validation-ip-san.png](pki-013-http-tls-validation-ip-san.png) | Authenticated IP-SAN HTTPS response without insecure bypass |
| [pki-014-http-tls-validation-hostname-san.png](pki-014-http-tls-validation-hostname-san.png) | Authenticated hostname-SAN HTTPS response without insecure bypass |
| [pki-015-elasticsearch-managed-http-tls-configuration.png](pki-015-elasticsearch-managed-http-tls-configuration.png) | Historical HTTP PEM and transport PKCS#12 configuration |

The set supports historical custom HTTP TLS work. It does not establish current service health, the transport issuer, Kibana browser TLS, or Fleet deployment. See the [certificate inventory](../../docs/14-certificate-inventory.md).

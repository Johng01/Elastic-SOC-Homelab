# PKI Design and Implementation

## Scope

This document records the lab's custom HTTP TLS work for Elasticsearch. It is documentation—not a source of private keys or certificate bundles.

## Source-of-truth warning

The two linked planning diagrams were created before the implementation was completed. They are retained for design-history value, but they are **not authoritative descriptions of the deployed paths or component status**:

- [Original PKI design proposal](../diagrams/pki-design-proposal.png) uses proposed locations that differ from the implemented nested `ca/ca`, `generated/http`, and `/etc/elasticsearch/certs-managed` layout.
- [Original certificate inventory plan](../diagrams/certificate-inventory-plan.png) labels Kibana and Fleet Server certificates as active. Those rows are planned targets: browser-facing Kibana TLS remains unverified and Fleet remains planned. A running Kibana service is not proof of an active browser-facing certificate.
- [Original PKI flow](../diagrams/pki-flow.png) is also conceptual: it does not prove that transport or Fleet certificates were signed by the custom root CA.

See the [certificate inventory](14-certificate-inventory.md) for separate evidence states and exact HTTP paths.

The confirmed facts and evidence below take precedence over both planning images.

## Confirmed design

| Item | Value |
|---|---|
| PKI workspace | `/opt/elastic-pki` |
| Root CA distinguished name | `Cybersafe SOC Lab Root CA` |
| Root CA lifetime | 3650 days |
| Root key size | 4096 bits |
| Root key protection | Password-encrypted |
| Elasticsearch version | 9.3.3 |
| Elasticsearch node | `elastic-siem` |
| HTTP protocol | HTTPS |
| Elasticsearch HTTP deployment | `/etc/elasticsearch/certs-managed/http/` |
| Kibana browser-facing certificate | Deployment not established by repository evidence |
| Fleet Server certificate | Planned / not active |

Top-level workspace layout:

```text
/opt/elastic-pki/
├── backups/
├── ca/
├── documentation/
├── generated/
└── instances/
```

The screenshots show implementation-specific nested paths beneath this top-level structure. The [indexed screenshot set](../screenshots/01-pki/README.md) records historical HTTP deployment evidence; revalidate the live host before treating those paths as current.

## Security model

- The CA private key is encrypted and remains outside Git.
- Generated archives, private keys, PKCS#12 files, keystores, passwords, and enrollment tokens are excluded by `.gitignore`.
- Certificates must contain only the SANs actually used by clients.
- File ownership and permissions must be verified before service restart.
- Backups are stored under controlled local paths, not in this repository.

## Implemented evidence

The [PKI screenshot set](../screenshots/01-pki/) records:

1. workspace creation;
2. root CA creation;
3. encrypted-key verification;
4. instance definition;
5. HTTP certificate request and generation;
6. archive inspection and staging permissions;
7. SAN and key-match validation;
8. TLS validation through localhost, IP, and hostname;
9. managed Elasticsearch HTTP TLS configuration.

## Validation controls

A successful TLS deployment requires all of the following:

- certificate chain validates against the intended CA;
- certificate and private key match;
- hostname/IP used by the client appears in the SAN extension;
- Elasticsearch starts without TLS errors;
- authenticated HTTPS requests succeed;
- no `-k`/insecure bypass is used for final validation.

## Certificate lifecycle

Maintain a live inventory containing certificate purpose, subject, SANs, issuer, serial number, validity dates, storage path, owner, deployment state, and renewal date. Do not promote a planned certificate to active status until deployment and validation evidence exists.

## Limitation

This is currently a direct root-CA signing design suitable for a controlled homelab. A future intermediate CA improves key isolation; see [the migration plan](12-pki-migration-to-intermediate-ca.md).

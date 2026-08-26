# PKI Migration to an Intermediate CA

## Rationale

The current homelab root CA directly signs the HTTP certificate. A future intermediate CA would allow the root key to remain offline while the intermediate handles operational issuance.

## Migration outline

1. Inventory every certificate and trust store.
2. Back up the current configuration and keystores.
3. Create an encrypted intermediate key and CA certificate signed by the root.
4. Issue replacement service certificates with the required SANs.
5. Distribute the new chain to trust stores.
6. Test clients before switching services.
7. Rotate services in a controlled order with rollback points.
8. Retire old certificates only after validation.
9. Protect or revoke superseded material as appropriate.

This is a future enhancement, not evidence that an intermediate CA currently exists.

# Sky Secret Vault Security Model

## Protected assets

Sky Secret Vault is designed to protect secret **values at rest** in the local vault file. Values are encrypted with AES-256-GCM using a 256-bit master key supplied at runtime. Namespace, secret name, version number, deletion state, nonce, and authentication tag remain visible as metadata.

## Trust boundaries

- The host process and operating-system account running the vault are trusted.
- `SKY_VAULT_MASTER_KEY_HEX` is a root secret. Anyone who can read it can decrypt vault contents.
- The local filesystem is trusted to enforce owner-only permissions. The vault sets data/audit files to mode `0600`.
- The CLI does not provide network authentication, multi-user RBAC, HSM/KMS custody, distributed consensus, or remote secret leasing.

## Implemented controls

- AES-256-GCM authenticated encryption through OpenSSL EVP.
- Random 96-bit nonce per encrypted record.
- Namespace, secret name, and version bound as authenticated additional data (AAD).
- Append-only version records and deletion tombstones.
- Exclusive file locks for local concurrent writers/readers.
- Secret values never written to the audit log.
- Master-key and plaintext buffers explicitly cleansed before release where controlled by the application.
- Restricted secret/namespace character set to prevent record/audit injection.
- 64 KiB maximum secret size.
- Non-root container, read-only root filesystem support, dropped Linux capabilities.
- CI includes strict compiler warnings, tests, AddressSanitizer, UndefinedBehaviorSanitizer, and container build verification.

## Known limitations

This release is a **single-host local vault**, not a replacement for HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or Google Secret Manager. It does not yet include:

- master-key rotation/re-encryption;
- KMS/HSM-backed key unwrap;
- network API authentication or authorization;
- dynamic secret issuance or leases;
- replicated/high-availability storage;
- tamper-evident signed audit logs;
- automatic backup/restore tooling;
- independent cryptographic/security audit.

## Deployment requirements

Never commit a real master key. Inject the key using an operating-system secret facility, container secret, cloud secret manager, or HSM/KMS integration. Restrict access to vault and audit files to the service identity. Backups containing `vault.db` remain encrypted but should still be access-controlled.

## Reporting

Do not publish live credentials or exploit payloads containing real secrets in public issues. Report suspected vulnerabilities privately to the repository owner through an appropriate private channel.

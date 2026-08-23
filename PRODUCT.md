# Product Definition — Sky Secret Vault

## Positioning

Sky Secret Vault is a compact, local-first encrypted secrets vault for developer workstations, CI runners, edge appliances, private services, and single-host deployments that need encrypted-at-rest secret storage without operating a large external control plane.

## Core customer jobs

- Store deployment credentials encrypted at rest.
- Rotate application secrets while retaining version history.
- Delete secrets with an append-only tombstone rather than rewriting historical records.
- Retrieve secrets from scripts and automation through a small CLI surface.
- List secret metadata without exposing values.
- Maintain a metadata-only audit trail of create, rotate, read, list, and delete operations.

## Supported interface

```text
sky-secret-vault put <namespace> <name>     # value from stdin
sky-secret-vault get <namespace> <name>
sky-secret-vault delete <namespace> <name>
sky-secret-vault list <namespace>
```

## Commercial packaging

The executable can be shipped as:

1. a standalone Linux binary linked against OpenSSL;
2. a hardened non-root container;
3. an embedded C static library (`skyvault`) for local application integration.

## Current product boundary

This version is intentionally single-node and local-first. Enterprise network APIs, HSM/KMS key custody, RBAC, dynamic credentials, HA replication, signed audit chains, and managed SaaS tenancy are future products—not implied by this release.

## Upgrade path

- **Community/Edge:** local encrypted vault and CLI.
- **Team:** authenticated local/Unix-socket daemon, policy files, key rotation.
- **Enterprise:** KMS/HSM envelope encryption, OIDC/mTLS identity, RBAC/ABAC policies, signed audit stream, HA replicated backend, admin console, telemetry, backup/restore, and managed service controls.

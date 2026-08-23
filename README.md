# Sky Secret Vault

Sky Secret Vault is a local-first encrypted secrets platform written in C. It replaces the repository's original in-memory integer demo with a persistent, versioned vault backed by AES-256-GCM authenticated encryption through OpenSSL.

> **Status:** productization branch under verification. This release is a single-host encrypted vault, not a managed multi-tenant cloud secrets service.

## What it does

- encrypts secret values at rest with AES-256-GCM;
- generates a fresh 96-bit nonce per stored version;
- binds namespace, name, and version into authenticated additional data;
- stores append-only versions and deletion tombstones;
- supports secret rotation by writing a new version;
- uses exclusive file locking for local concurrent access;
- creates vault and audit files with owner-only `0600` permissions;
- keeps secret values out of the audit log;
- explicitly cleanses key/plaintext buffers controlled by the application;
- validates namespace/name characters and enforces a 64 KiB secret limit;
- ships as a CLI, static C library, and hardened non-root container.

## Build

Requirements: CMake, a C11 compiler, and OpenSSL development headers.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## Master key

Supply exactly 32 bytes encoded as 64 hexadecimal characters:

```bash
export SKY_VAULT_MASTER_KEY_HEX="$(openssl rand -hex 32)"
```

Do not commit or paste a production master key into source, shell history, CI configuration, or public logs. Prefer your operating system, container runtime, cloud secret manager, or HSM/KMS to inject it at runtime.

Optional paths:

```bash
export SKY_VAULT_DATA=/secure/path/vault.db
export SKY_VAULT_AUDIT=/secure/path/vault.audit.log
```

## CLI

Store a secret from standard input:

```bash
printf '%s' "$DATABASE_PASSWORD" | ./build/sky-secret-vault put production database/password
```

Retrieve it:

```bash
./build/sky-secret-vault get production database/password
```

Rotate it by storing another value at the same path:

```bash
printf '%s' "$NEW_DATABASE_PASSWORD" | ./build/sky-secret-vault put production database/password
```

List metadata without values:

```bash
./build/sky-secret-vault list production
```

Delete using an append-only tombstone:

```bash
./build/sky-secret-vault delete production database/password
```

## Container

```bash
docker build -t sky-secret-vault .
export SKY_VAULT_MASTER_KEY_HEX="$(openssl rand -hex 32)"
docker compose run --rm vault list production
```

`docker-compose.yml` uses a non-root image, read-only root filesystem, dropped Linux capabilities, a dedicated persistent volume, and `no-new-privileges`.

## Audit behavior

The audit log records timestamp, action, namespace, secret metadata name, and result. It never intentionally records the secret value. The encrypted record store exposes metadata such as namespace/name/version; see `SECURITY.md` for the exact threat model.

## Verification

CI is configured to run:

- strict warning-as-error C compilation;
- unit/integration tests;
- CLI persistence/encryption smoke tests;
- AddressSanitizer and UndefinedBehaviorSanitizer tests;
- Docker image build verification.

A branch is not considered finished until those checks pass on the exact commit.

## Product boundary

See `PRODUCT.md` for packaging and commercialization scope and `SECURITY.md` for trust boundaries and limitations. Current limitations include no KMS/HSM master-key wrapping, remote auth/RBAC, dynamic credentials, distributed HA, or independent security audit.

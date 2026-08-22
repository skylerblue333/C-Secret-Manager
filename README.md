# C Secret Store

A small bounded in-memory key/value store written in C. It is suitable for demonstrating safe API boundaries and testable storage behavior; it is **not** a secrets vault and does not encrypt values at rest.

## Implemented behavior

The store enforces maximum key length, rejects null and empty keys, prevents duplicate keys, distinguishes invalid, full, duplicate, and missing states, supports reset, and uses a shared implementation for the executable and tests. CMake enables C11, strict warnings, and `-Werror`.

```bash
cmake -S . -B build
cmake --build build
./build/test_app
./build/app
```

## Validation

The test executable covers insertion, lookup, missing keys, duplicate rejection, invalid keys, reset behavior, and bounded key handling. The current build and tests pass with strict compiler warnings enabled.

## Scope and security limitations

This repository stores integer values in process memory only. It has no persistence, encryption, access control, audit logging, key rotation, secret-provider integration, or concurrency protection. Do not store real credentials or private keys in it. A production secret-management system requires a reviewed design using an established secrets manager and secure key management. The former “secure,” “enterprise,” and “AES-style XOR encryption” claims were removed because the implementation did not substantiate them.

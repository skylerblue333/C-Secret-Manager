#define _POSIX_C_SOURCE 200809L
#include "crypto.h"
#include "vault.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_key_parser(void) {
    uint8_t key[SKY_KEY_BYTES];
    assert(crypto_parse_key_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key));
    assert(!crypto_parse_key_hex("bad", key));
    crypto_cleanse(key, sizeof(key));
}

static void test_name_validation(void) {
    assert(vault_valid_name("prod/payments/api-key"));
    assert(vault_valid_name("service_1.token"));
    assert(!vault_valid_name(""));
    assert(!vault_valid_name("bad name"));
    assert(!vault_valid_name("bad\nname"));
}

static void test_crypto_round_trip(void) {
    uint8_t key[SKY_KEY_BYTES];
    assert(crypto_parse_key_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key));
    const uint8_t plaintext[] = "super-secret";
    const uint8_t aad[] = "prod:api:1";
    uint8_t nonce[SKY_NONCE_BYTES];
    uint8_t tag[SKY_TAG_BYTES];
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t recovered[sizeof(plaintext)];
    assert(crypto_encrypt_gcm(key, plaintext, sizeof(plaintext) - 1, aad, sizeof(aad) - 1, nonce, ciphertext, tag));
    assert(crypto_decrypt_gcm(key, ciphertext, sizeof(plaintext) - 1, aad, sizeof(aad) - 1, nonce, tag, recovered));
    assert(memcmp(plaintext, recovered, sizeof(plaintext) - 1) == 0);
    tag[0] ^= 1;
    assert(!crypto_decrypt_gcm(key, ciphertext, sizeof(plaintext) - 1, aad, sizeof(aad) - 1, nonce, tag, recovered));
    crypto_cleanse(key, sizeof(key));
    crypto_cleanse(recovered, sizeof(recovered));
}

static void test_vault_lifecycle(void) {
    char data_template[] = "/tmp/sky-vault-data-XXXXXX";
    char audit_template[] = "/tmp/sky-vault-audit-XXXXXX";
    int data_fd = mkstemp(data_template);
    int audit_fd = mkstemp(audit_template);
    assert(data_fd >= 0 && audit_fd >= 0);
    close(data_fd);
    close(audit_fd);

    uint8_t key[SKY_KEY_BYTES];
    assert(crypto_parse_key_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key));
    vault v;
    assert(vault_init(&v, data_template, audit_template, key));
    crypto_cleanse(key, sizeof(key));

    const uint8_t first[] = "alpha-value";
    const uint8_t second[] = "rotated-value";
    uint64_t version = 0;
    assert(vault_put(&v, "prod", "payments/api-key", first, sizeof(first) - 1, &version) == VAULT_OK);
    assert(version == 1);
    assert(vault_put(&v, "prod", "payments/api-key", second, sizeof(second) - 1, &version) == VAULT_OK);
    assert(version == 2);

    uint8_t output[SKY_SECRET_MAX];
    size_t output_len = 0;
    assert(vault_get(&v, "prod", "payments/api-key", output, sizeof(output), &output_len, &version) == VAULT_OK);
    assert(version == 2);
    assert(output_len == sizeof(second) - 1);
    assert(memcmp(output, second, output_len) == 0);

    assert(vault_delete(&v, "prod", "payments/api-key", &version) == VAULT_OK);
    assert(version == 3);
    assert(vault_get(&v, "prod", "payments/api-key", output, sizeof(output), &output_len, &version) == VAULT_NOT_FOUND);

    vault_destroy(&v);
    crypto_cleanse(output, sizeof(output));
    unlink(data_template);
    unlink(audit_template);
}

int main(void) {
    test_key_parser();
    test_name_validation();
    test_crypto_round_trip();
    test_vault_lifecycle();
    puts("Sky Secret Vault tests passed");
    return 0;
}

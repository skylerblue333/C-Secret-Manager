#define _POSIX_C_SOURCE 200809L
#include "crypto.h"
#include "key_loader.h"
#include "vault.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static const char *TEST_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

static void test_key_parser(void) {
    uint8_t key[SKY_KEY_BYTES];
    CHECK(crypto_parse_key_hex(TEST_KEY, key));
    CHECK(!crypto_parse_key_hex("bad", key));
    crypto_cleanse(key, sizeof(key));
}

static void test_key_file_loader(void) {
    char key_template[] = "/tmp/sky-vault-key-XXXXXX";
    int fd = mkstemp(key_template);
    CHECK(fd >= 0);
    CHECK(write(fd, TEST_KEY, strlen(TEST_KEY)) == (ssize_t)strlen(TEST_KEY));
    CHECK(fchmod(fd, S_IRUSR | S_IWUSR) == 0);
    close(fd);

    unsetenv("SKY_VAULT_MASTER_KEY_HEX");
    CHECK(setenv("SKY_VAULT_MASTER_KEY_FILE", key_template, 1) == 0);
    uint8_t key[SKY_KEY_BYTES];
    char error[192] = {0};
    CHECK(key_load_from_runtime(key, error, sizeof(error)));
    crypto_cleanse(key, sizeof(key));

    CHECK(chmod(key_template, S_IRUSR | S_IWUSR | S_IRGRP) == 0);
    memset(error, 0, sizeof(error));
    CHECK(!key_load_from_runtime(key, error, sizeof(error)));

    unsetenv("SKY_VAULT_MASTER_KEY_FILE");
    unlink(key_template);
}

static void test_name_validation(void) {
    CHECK(vault_valid_name("prod/payments/api-key"));
    CHECK(vault_valid_name("service_1.token"));
    CHECK(!vault_valid_name(""));
    CHECK(!vault_valid_name("bad name"));
    CHECK(!vault_valid_name("bad\nname"));
}

static void test_crypto_round_trip(void) {
    uint8_t key[SKY_KEY_BYTES];
    CHECK(crypto_parse_key_hex(TEST_KEY, key));
    const uint8_t plaintext[] = "super-secret";
    const uint8_t aad[] = "prod:api:1";
    uint8_t nonce[SKY_NONCE_BYTES] = {0};
    uint8_t tag[SKY_TAG_BYTES] = {0};
    uint8_t ciphertext[sizeof(plaintext)] = {0};
    uint8_t recovered[sizeof(plaintext)] = {0};
    CHECK(crypto_encrypt_gcm(key, plaintext, sizeof(plaintext) - 1, aad, sizeof(aad) - 1, nonce, ciphertext, tag));
    CHECK(crypto_decrypt_gcm(key, ciphertext, sizeof(plaintext) - 1, aad, sizeof(aad) - 1, nonce, tag, recovered));
    CHECK(memcmp(plaintext, recovered, sizeof(plaintext) - 1) == 0);
    tag[0] ^= 1;
    CHECK(!crypto_decrypt_gcm(key, ciphertext, sizeof(plaintext) - 1, aad, sizeof(aad) - 1, nonce, tag, recovered));
    crypto_cleanse(key, sizeof(key));
    crypto_cleanse(recovered, sizeof(recovered));
}

static void test_vault_lifecycle(void) {
    char data_template[] = "/tmp/sky-vault-data-XXXXXX";
    char audit_template[] = "/tmp/sky-vault-audit-XXXXXX";
    int data_fd = mkstemp(data_template);
    int audit_fd = mkstemp(audit_template);
    CHECK(data_fd >= 0 && audit_fd >= 0);
    close(data_fd);
    close(audit_fd);

    uint8_t key[SKY_KEY_BYTES];
    CHECK(crypto_parse_key_hex(TEST_KEY, key));
    vault v;
    CHECK(vault_init(&v, data_template, audit_template, key));
    crypto_cleanse(key, sizeof(key));

    const uint8_t first[] = "alpha-value";
    const uint8_t second[] = "rotated-value";
    uint64_t version = 0;
    CHECK(vault_put(&v, "prod", "payments/api-key", first, sizeof(first) - 1, &version) == VAULT_OK);
    CHECK(version == 1);
    CHECK(vault_put(&v, "prod", "payments/api-key", second, sizeof(second) - 1, &version) == VAULT_OK);
    CHECK(version == 2);

    uint8_t output[SKY_SECRET_MAX];
    size_t output_len = 0;
    CHECK(vault_get(&v, "prod", "payments/api-key", output, sizeof(output), &output_len, &version) == VAULT_OK);
    CHECK(version == 2);
    CHECK(output_len == sizeof(second) - 1);
    CHECK(memcmp(output, second, output_len) == 0);

    CHECK(vault_delete(&v, "prod", "payments/api-key", &version) == VAULT_OK);
    CHECK(version == 3);
    CHECK(vault_get(&v, "prod", "payments/api-key", output, sizeof(output), &output_len, &version) == VAULT_NOT_FOUND);

    vault_destroy(&v);
    crypto_cleanse(output, sizeof(output));
    unlink(data_template);
    unlink(audit_template);
}

int main(void) {
    test_key_parser();
    test_key_file_loader();
    test_name_validation();
    test_crypto_round_trip();
    test_vault_lifecycle();
    puts("Sky Secret Vault tests passed");
    return 0;
}

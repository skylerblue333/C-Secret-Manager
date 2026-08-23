#include "crypto.h"

#include <ctype.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int crypto_parse_key_hex(const char *hex, uint8_t out[SKY_KEY_BYTES]) {
    if (hex == NULL || out == NULL || strlen(hex) != SKY_KEY_BYTES * 2) return 0;
    for (size_t i = 0; i < SKY_KEY_BYTES; i++) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            crypto_cleanse(out, SKY_KEY_BYTES);
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

int crypto_encrypt_gcm(const uint8_t key[SKY_KEY_BYTES], const uint8_t *plaintext, size_t plaintext_len,
                       const uint8_t *aad, size_t aad_len, uint8_t nonce[SKY_NONCE_BYTES],
                       uint8_t *ciphertext, uint8_t tag[SKY_TAG_BYTES]) {
    if (plaintext_len > INT_MAX || aad_len > INT_MAX) return 0;
    if (RAND_bytes(nonce, SKY_NONCE_BYTES) != 1) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return 0;
    int ok = 0;
    int len = 0;
    int total = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SKY_NONCE_BYTES, NULL) != 1) goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto out;
    if (aad_len > 0 && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto out;
    if (plaintext_len > 0 && EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) goto out;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total, &len) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SKY_TAG_BYTES, tag) != 1) goto out;
    ok = 1;

out:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int crypto_decrypt_gcm(const uint8_t key[SKY_KEY_BYTES], const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t *aad, size_t aad_len, const uint8_t nonce[SKY_NONCE_BYTES],
                       const uint8_t tag[SKY_TAG_BYTES], uint8_t *plaintext) {
    if (ciphertext_len > INT_MAX || aad_len > INT_MAX) return 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return 0;
    int ok = 0;
    int len = 0;
    int total = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, SKY_NONCE_BYTES, NULL) != 1) goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto out;
    if (aad_len > 0 && EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto out;
    if (ciphertext_len > 0 && EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) goto out;
    total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SKY_TAG_BYTES, (void *)tag) != 1) goto out;
    if (EVP_DecryptFinal_ex(ctx, plaintext + total, &len) != 1) goto out;
    ok = 1;

out:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

void crypto_cleanse(void *ptr, size_t len) {
    if (ptr != NULL && len > 0) OPENSSL_cleanse(ptr, len);
}

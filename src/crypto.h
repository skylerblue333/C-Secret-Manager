#ifndef SKY_SECRET_CRYPTO_H
#define SKY_SECRET_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define SKY_KEY_BYTES 32
#define SKY_NONCE_BYTES 12
#define SKY_TAG_BYTES 16

int crypto_parse_key_hex(const char *hex, uint8_t out[SKY_KEY_BYTES]);
int crypto_encrypt_gcm(const uint8_t key[SKY_KEY_BYTES], const uint8_t *plaintext, size_t plaintext_len,
                       const uint8_t *aad, size_t aad_len, uint8_t nonce[SKY_NONCE_BYTES],
                       uint8_t *ciphertext, uint8_t tag[SKY_TAG_BYTES]);
int crypto_decrypt_gcm(const uint8_t key[SKY_KEY_BYTES], const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t *aad, size_t aad_len, const uint8_t nonce[SKY_NONCE_BYTES],
                       const uint8_t tag[SKY_TAG_BYTES], uint8_t *plaintext);
void crypto_cleanse(void *ptr, size_t len);

#endif

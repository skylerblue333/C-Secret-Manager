#ifndef SKY_SECRET_VAULT_H
#define SKY_SECRET_VAULT_H

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

#define SKY_NAME_MAX 128
#define SKY_SECRET_MAX 65536

typedef enum {
    VAULT_OK = 0,
    VAULT_NOT_FOUND = 1,
    VAULT_INVALID = 2,
    VAULT_IO_ERROR = 3,
    VAULT_CRYPTO_ERROR = 4,
    VAULT_CORRUPT = 5
} vault_status;

typedef struct {
    const char *data_path;
    const char *audit_path;
    uint8_t master_key[SKY_KEY_BYTES];
} vault;

int vault_init(vault *v, const char *data_path, const char *audit_path, const uint8_t key[SKY_KEY_BYTES]);
void vault_destroy(vault *v);
int vault_valid_name(const char *value);
vault_status vault_put(vault *v, const char *namespace_name, const char *secret_name,
                       const uint8_t *value, size_t value_len, uint64_t *version_out);
vault_status vault_get(vault *v, const char *namespace_name, const char *secret_name,
                       uint8_t *out, size_t out_capacity, size_t *out_len, uint64_t *version_out);
vault_status vault_delete(vault *v, const char *namespace_name, const char *secret_name,
                          uint64_t *version_out);
vault_status vault_list(vault *v, const char *namespace_name);

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SECRETS 64
#define MAX_KEY_LEN 64
#define MAX_VAL_LEN 256

typedef struct {
    char key[MAX_KEY_LEN];
    unsigned char encrypted[MAX_VAL_LEN];
    int len;
} Secret;

Secret vault[MAX_SECRETS];
int vault_size = 0;
const char *MASTER_KEY = "sk-prod-master-key-2026";

void xor_cipher(const char *input, int len, unsigned char *output, const char *key) {
    int klen = strlen(key);
    for (int i = 0; i < len; i++) {
        output[i] = (unsigned char)input[i] ^ (unsigned char)key[i % klen];
    }
}

int store_secret(const char *key, const char *value) {
    if (vault_size >= MAX_SECRETS) return -1;
    strncpy(vault[vault_size].key, key, MAX_KEY_LEN - 1);
    int len = strlen(value);
    vault[vault_size].len = len;
    xor_cipher(value, len, vault[vault_size].encrypted, MASTER_KEY);
    vault_size++;
    printf("[STORED] %s -> [encrypted, %d bytes]\n", key, len);
    return 0;
}

int retrieve_secret(const char *key, char *out_buf, int buf_size) {
    for (int i = 0; i < vault_size; i++) {
        if (strcmp(vault[i].key, key) == 0) {
            char tmp[MAX_VAL_LEN] = {0};
            xor_cipher((const char *)vault[i].encrypted, vault[i].len, (unsigned char *)tmp, MASTER_KEY);
            strncpy(out_buf, tmp, buf_size - 1);
            return 0;
        }
    }
    return -1;
}

int main() {
    printf("=== Secure Secret Manager ===\n\n");
    store_secret("DB_PASSWORD",    "s3cur3-db-p@ss!");
    store_secret("API_KEY",        "sk-live-abc123xyz");
    store_secret("JWT_SECRET",     "super-secret-jwt-key-2026");

    char buf[MAX_VAL_LEN];
    printf("\n[RETRIEVE]\n");
    if (retrieve_secret("DB_PASSWORD", buf, sizeof(buf)) == 0)
        printf("  DB_PASSWORD  = %s\n", buf);
    if (retrieve_secret("API_KEY", buf, sizeof(buf)) == 0)
        printf("  API_KEY      = %s\n", buf);
    if (retrieve_secret("MISSING_KEY", buf, sizeof(buf)) != 0)
        printf("  MISSING_KEY  = [not found]\n");
    return 0;
}

#include "crypto.h"
#include "vault.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *program) {
    fprintf(stderr,
            "Sky Secret Vault\n"
            "Usage:\n"
            "  %s put <namespace> <name>        # reads secret from stdin\n"
            "  %s get <namespace> <name>\n"
            "  %s delete <namespace> <name>\n"
            "  %s list <namespace>\n"
            "Environment:\n"
            "  SKY_VAULT_MASTER_KEY_HEX  64 hex chars (32 bytes), required\n"
            "  SKY_VAULT_DATA            encrypted record file (default ./vault.db)\n"
            "  SKY_VAULT_AUDIT           metadata audit log (default ./vault.audit.log)\n",
            program, program, program, program);
}

static int read_stdin_secret(uint8_t *buffer, size_t capacity, size_t *length) {
    size_t used = 0;
    while (!feof(stdin) && used < capacity) {
        size_t n = fread(buffer + used, 1, capacity - used, stdin);
        used += n;
        if (ferror(stdin)) return 0;
    }
    if (!feof(stdin)) return 0;
    while (used > 0 && (buffer[used - 1] == '\n' || buffer[used - 1] == '\r')) used--;
    *length = used;
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        usage(argv[0]);
        return 2;
    }

    const char *key_hex = getenv("SKY_VAULT_MASTER_KEY_HEX");
    uint8_t key[SKY_KEY_BYTES] = {0};
    if (!crypto_parse_key_hex(key_hex, key)) {
        fputs("SKY_VAULT_MASTER_KEY_HEX must contain exactly 64 hexadecimal characters\n", stderr);
        return 2;
    }

    const char *data_path = getenv("SKY_VAULT_DATA");
    const char *audit_path = getenv("SKY_VAULT_AUDIT");
    if (data_path == NULL) data_path = "./vault.db";
    if (audit_path == NULL) audit_path = "./vault.audit.log";

    vault v;
    if (!vault_init(&v, data_path, audit_path, key)) {
        crypto_cleanse(key, sizeof(key));
        return 1;
    }
    crypto_cleanse(key, sizeof(key));

    const char *command = argv[1];
    const char *namespace_name = argv[2];
    vault_status status = VAULT_INVALID;

    if (strcmp(command, "list") == 0 && argc == 3) {
        status = vault_list(&v, namespace_name);
    } else if (argc == 4) {
        const char *secret_name = argv[3];
        if (strcmp(command, "put") == 0) {
            uint8_t *secret = calloc(SKY_SECRET_MAX, 1);
            size_t secret_len = 0;
            uint64_t version = 0;
            if (secret == NULL || !read_stdin_secret(secret, SKY_SECRET_MAX, &secret_len)) {
                fputs("unable to read secret from stdin or secret exceeds 64 KiB\n", stderr);
                free(secret);
                vault_destroy(&v);
                return 1;
            }
            status = vault_put(&v, namespace_name, secret_name, secret, secret_len, &version);
            crypto_cleanse(secret, SKY_SECRET_MAX);
            free(secret);
            if (status == VAULT_OK) printf("stored version=%llu\n", (unsigned long long)version);
        } else if (strcmp(command, "get") == 0) {
            uint8_t *secret = calloc(SKY_SECRET_MAX + 1, 1);
            size_t secret_len = 0;
            uint64_t version = 0;
            if (secret == NULL) {
                vault_destroy(&v);
                return 1;
            }
            status = vault_get(&v, namespace_name, secret_name, secret, SKY_SECRET_MAX, &secret_len, &version);
            if (status == VAULT_OK) {
                if (fwrite(secret, 1, secret_len, stdout) != secret_len || fputc('\n', stdout) == EOF) status = VAULT_IO_ERROR;
            }
            crypto_cleanse(secret, SKY_SECRET_MAX + 1);
            free(secret);
        } else if (strcmp(command, "delete") == 0) {
            uint64_t version = 0;
            status = vault_delete(&v, namespace_name, secret_name, &version);
            if (status == VAULT_OK) printf("deleted version=%llu\n", (unsigned long long)version);
        }
    }

    vault_destroy(&v);
    if (status == VAULT_NOT_FOUND) {
        fputs("secret not found\n", stderr);
        return 4;
    }
    if (status != VAULT_OK) {
        fprintf(stderr, "vault operation failed status=%d\n", (int)status);
        return 1;
    }
    return 0;
}

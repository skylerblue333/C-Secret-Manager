#define _POSIX_C_SOURCE 200809L
#include "vault.h"

#include "audit.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define RECORD_PREFIX "SV1"
#define LIST_MAX 1024

typedef struct {
    char name[SKY_NAME_MAX + 1];
    uint64_t version;
    int deleted;
} list_entry;

static int hex_encode(const uint8_t *input, size_t len, char *output, size_t capacity) {
    static const char digits[] = "0123456789abcdef";
    if (capacity < len * 2 + 1) return 0;
    for (size_t i = 0; i < len; ++i) {
        output[i * 2] = digits[input[i] >> 4];
        output[i * 2 + 1] = digits[input[i] & 0x0f];
    }
    output[len * 2] = '\0';
    return 1;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *input, uint8_t *output, size_t output_capacity, size_t *output_len) {
    size_t len = strlen(input);
    if ((len % 2) != 0 || len / 2 > output_capacity) return 0;
    for (size_t i = 0; i < len / 2; ++i) {
        int hi = hex_nibble(input[i * 2]);
        int lo = hex_nibble(input[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        output[i] = (uint8_t)((hi << 4) | lo);
    }
    *output_len = len / 2;
    return 1;
}

int vault_valid_name(const char *value) {
    if (value == NULL) return 0;
    size_t len = strlen(value);
    if (len == 0 || len > SKY_NAME_MAX) return 0;
    for (size_t i = 0; i < len; ++i) {
        char c = value[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '/')) {
            return 0;
        }
    }
    return 1;
}

int vault_init(vault *v, const char *data_path, const char *audit_path, const uint8_t key[SKY_KEY_BYTES]) {
    if (v == NULL || data_path == NULL || audit_path == NULL || key == NULL) return 0;
    memset(v, 0, sizeof(*v));
    v->data_path = data_path;
    v->audit_path = audit_path;
    memcpy(v->master_key, key, SKY_KEY_BYTES);
    return 1;
}

void vault_destroy(vault *v) {
    if (v != NULL) crypto_cleanse(v->master_key, sizeof(v->master_key));
}

static int parse_record(char *line, char **ns, char **name, uint64_t *version, int *deleted,
                        char **nonce_hex, char **tag_hex, char **cipher_hex) {
    char *save = NULL;
    char *prefix = strtok_r(line, "|", &save);
    *ns = strtok_r(NULL, "|", &save);
    *name = strtok_r(NULL, "|", &save);
    char *version_text = strtok_r(NULL, "|", &save);
    char *deleted_text = strtok_r(NULL, "|", &save);
    *nonce_hex = strtok_r(NULL, "|", &save);
    *tag_hex = strtok_r(NULL, "|", &save);
    *cipher_hex = strtok_r(NULL, "\r\n", &save);
    if (prefix == NULL || strcmp(prefix, RECORD_PREFIX) != 0 || *ns == NULL || *name == NULL ||
        version_text == NULL || deleted_text == NULL || *nonce_hex == NULL || *tag_hex == NULL || *cipher_hex == NULL) return 0;
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(version_text, &end, 10);
    if (errno != 0 || end == version_text || *end != '\0' || parsed == 0) return 0;
    if (!(strcmp(deleted_text, "0") == 0 || strcmp(deleted_text, "1") == 0)) return 0;
    *version = (uint64_t)parsed;
    *deleted = deleted_text[0] == '1';
    return vault_valid_name(*ns) && vault_valid_name(*name);
}

static vault_status latest_version_locked(FILE *file, const char *namespace_name, const char *secret_name,
                                          uint64_t *version, int *deleted, char **record_copy) {
    rewind(file);
    char *line = NULL;
    size_t cap = 0;
    uint64_t best = 0;
    int best_deleted = 0;
    char *best_line = NULL;
    while (getline(&line, &cap, file) >= 0) {
        char *candidate = strdup(line);
        if (candidate == NULL) {
            free(line);
            free(best_line);
            return VAULT_IO_ERROR;
        }
        char *ns = NULL, *name = NULL, *nonce = NULL, *tag = NULL, *cipher = NULL;
        uint64_t candidate_version = 0;
        int candidate_deleted = 0;
        if (parse_record(candidate, &ns, &name, &candidate_version, &candidate_deleted, &nonce, &tag, &cipher) &&
            strcmp(ns, namespace_name) == 0 && strcmp(name, secret_name) == 0 && candidate_version > best) {
            best = candidate_version;
            best_deleted = candidate_deleted;
            free(best_line);
            best_line = strdup(line);
            if (best_line == NULL) {
                free(candidate);
                free(line);
                return VAULT_IO_ERROR;
            }
        }
        free(candidate);
    }
    free(line);
    *version = best;
    *deleted = best_deleted;
    if (record_copy != NULL) *record_copy = best_line; else free(best_line);
    return best == 0 ? VAULT_NOT_FOUND : VAULT_OK;
}

static FILE *open_locked(const char *path, int *fd_out) {
    int fd = open(path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) return NULL;
    (void)fchmod(fd, S_IRUSR | S_IWUSR);
    if (flock(fd, LOCK_EX) != 0) {
        close(fd);
        return NULL;
    }
    FILE *file = fdopen(fd, "r+");
    if (file == NULL) {
        flock(fd, LOCK_UN);
        close(fd);
        return NULL;
    }
    *fd_out = fd;
    return file;
}

static void close_locked(FILE *file, int fd) {
    (void)fflush(file);
    (void)fsync(fd);
    (void)flock(fd, LOCK_UN);
    fclose(file);
}

static vault_status append_record(vault *v, const char *namespace_name, const char *secret_name,
                                  const uint8_t *value, size_t value_len, int deleted, uint64_t *version_out) {
    if (!vault_valid_name(namespace_name) || !vault_valid_name(secret_name) || value_len > SKY_SECRET_MAX || (!deleted && value == NULL)) return VAULT_INVALID;
    int fd = -1;
    FILE *file = open_locked(v->data_path, &fd);
    if (file == NULL) return VAULT_IO_ERROR;

    uint64_t previous = 0;
    int was_deleted = 0;
    vault_status latest = latest_version_locked(file, namespace_name, secret_name, &previous, &was_deleted, NULL);
    if (latest != VAULT_OK && latest != VAULT_NOT_FOUND) {
        close_locked(file, fd);
        return latest;
    }
    uint64_t version = previous + 1;

    uint8_t nonce[SKY_NONCE_BYTES] = {0};
    uint8_t tag[SKY_TAG_BYTES] = {0};
    uint8_t *ciphertext = NULL;
    char *cipher_hex = NULL;
    char nonce_hex[SKY_NONCE_BYTES * 2 + 1];
    char tag_hex[SKY_TAG_BYTES * 2 + 1];
    char aad[SKY_NAME_MAX * 2 + 64];
    int aad_len = snprintf(aad, sizeof(aad), "%s:%s:%llu", namespace_name, secret_name, (unsigned long long)version);
    if (aad_len < 0 || (size_t)aad_len >= sizeof(aad)) {
        close_locked(file, fd);
        return VAULT_INVALID;
    }

    if (!deleted) {
        ciphertext = calloc(value_len == 0 ? 1 : value_len, 1);
        cipher_hex = calloc(value_len * 2 + 1, 1);
        if (ciphertext == NULL || cipher_hex == NULL ||
            !crypto_encrypt_gcm(v->master_key, value, value_len, (const uint8_t *)aad, (size_t)aad_len, nonce, ciphertext, tag) ||
            !hex_encode(ciphertext, value_len, cipher_hex, value_len * 2 + 1)) {
            free(ciphertext);
            free(cipher_hex);
            close_locked(file, fd);
            return VAULT_CRYPTO_ERROR;
        }
    } else {
        cipher_hex = strdup("-");
        if (cipher_hex == NULL) {
            close_locked(file, fd);
            return VAULT_IO_ERROR;
        }
    }

    if (!hex_encode(nonce, sizeof(nonce), nonce_hex, sizeof(nonce_hex)) || !hex_encode(tag, sizeof(tag), tag_hex, sizeof(tag_hex))) {
        crypto_cleanse(ciphertext, value_len);
        free(ciphertext);
        free(cipher_hex);
        close_locked(file, fd);
        return VAULT_CRYPTO_ERROR;
    }

    if (fseek(file, 0, SEEK_END) != 0 ||
        fprintf(file, "%s|%s|%s|%llu|%d|%s|%s|%s\n", RECORD_PREFIX, namespace_name, secret_name,
                (unsigned long long)version, deleted, nonce_hex, tag_hex, cipher_hex) < 0 || fflush(file) != 0 || fsync(fd) != 0) {
        crypto_cleanse(ciphertext, value_len);
        free(ciphertext);
        free(cipher_hex);
        close_locked(file, fd);
        return VAULT_IO_ERROR;
    }

    crypto_cleanse(ciphertext, value_len);
    free(ciphertext);
    free(cipher_hex);
    close_locked(file, fd);
    if (version_out != NULL) *version_out = version;
    (void)audit_append(v->audit_path, deleted ? "delete" : (previous == 0 ? "create" : "rotate"), namespace_name, secret_name, "ok");
    return VAULT_OK;
}

vault_status vault_put(vault *v, const char *namespace_name, const char *secret_name,
                       const uint8_t *value, size_t value_len, uint64_t *version_out) {
    return append_record(v, namespace_name, secret_name, value, value_len, 0, version_out);
}

vault_status vault_delete(vault *v, const char *namespace_name, const char *secret_name, uint64_t *version_out) {
    if (!vault_valid_name(namespace_name) || !vault_valid_name(secret_name)) return VAULT_INVALID;
    uint8_t dummy = 0;
    return append_record(v, namespace_name, secret_name, &dummy, 0, 1, version_out);
}

vault_status vault_get(vault *v, const char *namespace_name, const char *secret_name,
                       uint8_t *out, size_t out_capacity, size_t *out_len, uint64_t *version_out) {
    if (!vault_valid_name(namespace_name) || !vault_valid_name(secret_name) || out == NULL || out_len == NULL) return VAULT_INVALID;
    int fd = -1;
    FILE *file = open_locked(v->data_path, &fd);
    if (file == NULL) return VAULT_IO_ERROR;
    uint64_t version = 0;
    int deleted = 0;
    char *record = NULL;
    vault_status latest = latest_version_locked(file, namespace_name, secret_name, &version, &deleted, &record);
    close_locked(file, fd);
    if (latest != VAULT_OK) return latest;
    if (deleted) {
        free(record);
        (void)audit_append(v->audit_path, "read", namespace_name, secret_name, "not_found");
        return VAULT_NOT_FOUND;
    }

    char *ns = NULL, *name = NULL, *nonce_hex = NULL, *tag_hex = NULL, *cipher_hex = NULL;
    uint64_t parsed_version = 0;
    int parsed_deleted = 0;
    if (!parse_record(record, &ns, &name, &parsed_version, &parsed_deleted, &nonce_hex, &tag_hex, &cipher_hex)) {
        free(record);
        return VAULT_CORRUPT;
    }

    size_t cipher_len = strlen(cipher_hex) / 2;
    if (cipher_len > out_capacity || cipher_len > SKY_SECRET_MAX) {
        free(record);
        return VAULT_INVALID;
    }
    uint8_t *ciphertext = calloc(cipher_len == 0 ? 1 : cipher_len, 1);
    uint8_t nonce[SKY_NONCE_BYTES];
    uint8_t tag[SKY_TAG_BYTES];
    size_t decoded = 0;
    if (ciphertext == NULL || !hex_decode(cipher_hex, ciphertext, cipher_len, &decoded) || decoded != cipher_len ||
        !hex_decode(nonce_hex, nonce, sizeof(nonce), &decoded) || decoded != sizeof(nonce) ||
        !hex_decode(tag_hex, tag, sizeof(tag), &decoded) || decoded != sizeof(tag)) {
        free(ciphertext);
        free(record);
        return VAULT_CORRUPT;
    }
    char aad[SKY_NAME_MAX * 2 + 64];
    int aad_len = snprintf(aad, sizeof(aad), "%s:%s:%llu", namespace_name, secret_name, (unsigned long long)version);
    if (aad_len < 0 || (size_t)aad_len >= sizeof(aad) ||
        !crypto_decrypt_gcm(v->master_key, ciphertext, cipher_len, (const uint8_t *)aad, (size_t)aad_len, nonce, tag, out)) {
        crypto_cleanse(ciphertext, cipher_len);
        free(ciphertext);
        free(record);
        (void)audit_append(v->audit_path, "read", namespace_name, secret_name, "decrypt_failed");
        return VAULT_CRYPTO_ERROR;
    }
    crypto_cleanse(ciphertext, cipher_len);
    free(ciphertext);
    free(record);
    *out_len = cipher_len;
    if (version_out != NULL) *version_out = version;
    (void)audit_append(v->audit_path, "read", namespace_name, secret_name, "ok");
    return VAULT_OK;
}

vault_status vault_list(vault *v, const char *namespace_name) {
    if (!vault_valid_name(namespace_name)) return VAULT_INVALID;
    int fd = -1;
    FILE *file = open_locked(v->data_path, &fd);
    if (file == NULL) return VAULT_IO_ERROR;
    list_entry entries[LIST_MAX];
    size_t count = 0;
    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, file) >= 0) {
        char *copy = strdup(line);
        if (copy == NULL) continue;
        char *ns = NULL, *name = NULL, *nonce = NULL, *tag = NULL, *cipher = NULL;
        uint64_t version = 0;
        int deleted = 0;
        if (parse_record(copy, &ns, &name, &version, &deleted, &nonce, &tag, &cipher) && strcmp(ns, namespace_name) == 0) {
            size_t i = 0;
            for (; i < count; ++i) if (strcmp(entries[i].name, name) == 0) break;
            if (i == count && count < LIST_MAX) {
                strncpy(entries[count].name, name, SKY_NAME_MAX);
                entries[count].name[SKY_NAME_MAX] = '\0';
                entries[count].version = 0;
                entries[count].deleted = 0;
                count++;
            }
            if (i < count && version > entries[i].version) {
                entries[i].version = version;
                entries[i].deleted = deleted;
            }
        }
        free(copy);
    }
    free(line);
    close_locked(file, fd);
    for (size_t i = 0; i < count; ++i) {
        if (!entries[i].deleted) printf("%s\tversion=%llu\n", entries[i].name, (unsigned long long)entries[i].version);
    }
    (void)audit_append(v->audit_path, "list", namespace_name, "_metadata", "ok");
    return VAULT_OK;
}

#define _POSIX_C_SOURCE 200809L
#include "key_loader.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void set_error(char *buffer, unsigned long capacity, const char *message) {
    if (buffer == NULL || capacity == 0) return;
    (void)snprintf(buffer, (size_t)capacity, "%s", message);
}

static int load_key_file(const char *path, uint8_t out[SKY_KEY_BYTES], char *error_buffer, unsigned long error_capacity) {
    struct stat st;
    if (stat(path, &st) != 0) {
        set_error(error_buffer, error_capacity, "unable to stat master-key file");
        return 0;
    }
    if (!S_ISREG(st.st_mode)) {
        set_error(error_buffer, error_capacity, "master-key path is not a regular file");
        return 0;
    }
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        set_error(error_buffer, error_capacity, "master-key file must not be accessible by group/other");
        return 0;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        set_error(error_buffer, error_capacity, "unable to open master-key file");
        return 0;
    }

    char hex[SKY_KEY_BYTES * 2 + 2];
    ssize_t n = read(fd, hex, sizeof(hex) - 1);
    int saved_errno = errno;
    close(fd);
    if (n < 0) {
        errno = saved_errno;
        set_error(error_buffer, error_capacity, "unable to read master-key file");
        return 0;
    }
    hex[n] = '\0';
    while (n > 0 && (hex[n - 1] == '\n' || hex[n - 1] == '\r')) {
        hex[n - 1] = '\0';
        --n;
    }
    if (!crypto_parse_key_hex(hex, out)) {
        crypto_cleanse(hex, sizeof(hex));
        set_error(error_buffer, error_capacity, "master-key file must contain exactly 64 hexadecimal characters");
        return 0;
    }
    crypto_cleanse(hex, sizeof(hex));
    return 1;
}

int key_load_from_runtime(uint8_t out[SKY_KEY_BYTES], char *error_buffer, unsigned long error_capacity) {
    if (out == NULL) return 0;
    const char *key_file = getenv("SKY_VAULT_MASTER_KEY_FILE");
    const char *key_hex = getenv("SKY_VAULT_MASTER_KEY_HEX");

    if (key_file != NULL && *key_file != '\0') {
        if (key_hex != NULL && *key_hex != '\0') {
            set_error(error_buffer, error_capacity, "set only one of SKY_VAULT_MASTER_KEY_FILE or SKY_VAULT_MASTER_KEY_HEX");
            return 0;
        }
        return load_key_file(key_file, out, error_buffer, error_capacity);
    }

    if (key_hex == NULL || !crypto_parse_key_hex(key_hex, out)) {
        set_error(error_buffer, error_capacity, "provide a 64-character hex key via SKY_VAULT_MASTER_KEY_FILE or SKY_VAULT_MASTER_KEY_HEX");
        return 0;
    }
    return 1;
}

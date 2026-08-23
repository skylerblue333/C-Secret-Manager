#include "audit.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static int valid_field(const char *value) {
    if (value == NULL || *value == '\0') return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        if (*p == '\n' || *p == '\r' || *p == '\t') return 0;
    }
    return 1;
}

int audit_append(const char *path, const char *action, const char *namespace_name, const char *secret_name, const char *result) {
    if (path == NULL || !valid_field(action) || !valid_field(namespace_name) || !valid_field(secret_name) || !valid_field(result)) return 0;

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) return 0;
    (void)fchmod(fd, S_IRUSR | S_IWUSR);

    time_t now = time(NULL);
    struct tm tm_value;
    if (gmtime_r(&now, &tm_value) == NULL) {
        close(fd);
        return 0;
    }

    char timestamp[32];
    if (strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_value) == 0) {
        close(fd);
        return 0;
    }

    char line[768];
    int written = snprintf(line, sizeof(line), "%s action=%s namespace=%s secret=%s result=%s\n",
                           timestamp, action, namespace_name, secret_name, result);
    if (written < 0 || (size_t)written >= sizeof(line)) {
        close(fd);
        return 0;
    }

    ssize_t n = write(fd, line, (size_t)written);
    int ok = (n == written && fsync(fd) == 0);
    close(fd);
    return ok;
}

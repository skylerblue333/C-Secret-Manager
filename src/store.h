#ifndef SECRET_STORE_H
#define SECRET_STORE_H

#include <stddef.h>

#define STORE_KEY_MAX 64
#define STORE_MAX_ITEMS 1024

typedef enum {
    STORE_OK = 0,
    STORE_FULL = -1,
    STORE_INVALID = -2,
    STORE_DUPLICATE = -3,
    STORE_NOT_FOUND = -4
} StoreResult;

void store_reset(void);
int add_item(const char *key, int value);
int find_item(const char *key);
StoreResult get_item(const char *key, int *value);
size_t store_count(void);

#endif

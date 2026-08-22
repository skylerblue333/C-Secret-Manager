#include "store.h"

#include <string.h>

typedef struct {
    char key[STORE_KEY_MAX];
    int value;
} Item;

static Item store[STORE_MAX_ITEMS];
static size_t store_size = 0;

void store_reset(void) {
    memset(store, 0, sizeof(store));
    store_size = 0;
}

static int index_for_key(const char *key) {
    if (key == NULL || key[0] == '\0' || strlen(key) >= STORE_KEY_MAX) return -1;
    for (size_t i = 0; i < store_size; i++) {
        if (strcmp(store[i].key, key) == 0) return (int)i;
    }
    return -1;
}

int add_item(const char *key, int value) {
    if (key == NULL || key[0] == '\0' || strlen(key) >= STORE_KEY_MAX) return STORE_INVALID;
    if (index_for_key(key) >= 0) return STORE_DUPLICATE;
    if (store_size >= STORE_MAX_ITEMS) return STORE_FULL;
    memcpy(store[store_size].key, key, strlen(key) + 1);
    store[store_size].value = value;
    return (int)store_size++;
}

StoreResult get_item(const char *key, int *value) {
    if (value == NULL || key == NULL || key[0] == '\0' || strlen(key) >= STORE_KEY_MAX) return STORE_INVALID;
    int index = index_for_key(key);
    if (index < 0) return STORE_NOT_FOUND;
    *value = store[index].value;
    return STORE_OK;
}

int find_item(const char *key) {
    int value = 0;
    return get_item(key, &value) == STORE_OK ? value : STORE_NOT_FOUND;
}

size_t store_count(void) { return store_size; }

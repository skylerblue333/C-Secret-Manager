#include "../src/store.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    store_reset();
    assert(store_count() == 0);
    assert(add_item("test_key", 42) == 0);
    assert(find_item("test_key") == 42);
    assert(find_item("missing") == STORE_NOT_FOUND);
    assert(add_item("test_key", 99) == STORE_DUPLICATE);
    assert(add_item(NULL, 1) == STORE_INVALID);
    char long_key[STORE_KEY_MAX + 1];
    memset(long_key, 'x', STORE_KEY_MAX);
    long_key[STORE_KEY_MAX] = '\0';
    assert(add_item(long_key, 1) == STORE_INVALID);
    int value = 0;
    assert(get_item("missing", &value) == STORE_NOT_FOUND);
    assert(get_item("test_key", &value) == STORE_OK && value == 42);
    store_reset();
    assert(store_count() == 0);
    puts("secret store tests passed");
    return 0;
}

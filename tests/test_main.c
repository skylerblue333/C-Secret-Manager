#include <stdio.h>
#include <assert.h>
#include <string.h>

#define MAX_ITEMS 1024

typedef struct {
    char key[64];
    int value;
} Item;

Item store[MAX_ITEMS];
int store_size = 0;

int add_item(const char* key, int value) {
    if (store_size >= MAX_ITEMS) return -1;
    strncpy(store[store_size].key, key, 63);
    store[store_size].value = value;
    store_size++;
    return store_size - 1;
}

int find_item(const char* key) {
    for (int i = 0; i < store_size; i++) {
        if (strcmp(store[i].key, key) == 0) return store[i].value;
    }
    return -1;
}

int main() {
    add_item("test_key", 42);
    assert(find_item("test_key") == 42);
    assert(find_item("missing") == -1);
    printf("All tests passed!\n");
    return 0;
}

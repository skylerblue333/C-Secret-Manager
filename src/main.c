#include "store.h"

#include <stdio.h>

int main(void) {
    store_reset();
    if (add_item("alpha", 100) < STORE_OK ||
        add_item("beta", 200) < STORE_OK ||
        add_item("gamma", 300) < STORE_OK) {
        fputs("failed to initialize store\n", stderr);
        return 1;
    }

    printf("In-memory store initialized with %zu items\n", store_count());
    for (const char *key = "alpha"; key != NULL; key = NULL) {
        int value = 0;
        if (get_item(key, &value) != STORE_OK) return 1;
        printf("%s = %d\n", key, value);
    }
    return 0;
}

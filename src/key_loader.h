#ifndef SKY_SECRET_KEY_LOADER_H
#define SKY_SECRET_KEY_LOADER_H

#include <stdint.h>
#include "crypto.h"

int key_load_from_runtime(uint8_t out[SKY_KEY_BYTES], char *error_buffer, unsigned long error_capacity);

#endif

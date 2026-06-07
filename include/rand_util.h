#ifndef RAND_UTIL_H
#define RAND_UTIL_H

#include <stdint.h>
#include <stddef.h>

int rand_bytes(uint8_t *buf, size_t len);
const char *rand_source(void);

#endif

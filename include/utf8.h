#ifndef UTF8_H
#define UTF8_H

#include <stdint.h>
#include <stddef.h>

int utf8_encode(const uint32_t *codepoints, size_t len, uint8_t *out, size_t *out_len);
int utf8_decode(const uint8_t *in, size_t in_len, uint32_t *codepoints, size_t *len);

#endif

#ifndef BASE64_H
#define BASE64_H

#include <stdint.h>
#include <stddef.h>

int base64_encode(const uint8_t *data, size_t data_len, char *out, size_t *out_len);
int base64_decode(const char *in, size_t in_len, uint8_t *data, size_t *data_len);

#endif

#ifndef RIPEMD160_H
#define RIPEMD160_H

#include <stdint.h>
#include <stddef.h>

#define RIPEMD160_DIGEST_SIZE 20

int ripemd160(const uint8_t *msg, size_t msg_len, uint8_t digest[RIPEMD160_DIGEST_SIZE]);

#endif

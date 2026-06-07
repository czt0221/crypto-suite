#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>
#include <stddef.h>

#define SHA3_DIGEST_SIZE 32

int sha3(const uint8_t *msg, size_t msg_len, uint8_t digest[SHA3_DIGEST_SIZE]);

#endif

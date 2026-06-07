#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_SIZE 32

int sha256(const uint8_t *msg, size_t msg_len, uint8_t digest[SHA256_DIGEST_SIZE]);

#endif

#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <stddef.h>

#define SHA1_DIGEST_SIZE 20

int sha1(const uint8_t *msg, size_t msg_len, uint8_t digest[SHA1_DIGEST_SIZE]);

#endif

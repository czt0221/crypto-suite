#ifndef HMACSHA256_H
#define HMACSHA256_H

#include <stdint.h>
#include <stddef.h>

#define HMACSHA256_MAC_SIZE 32

int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t mac[HMACSHA256_MAC_SIZE]);

#endif

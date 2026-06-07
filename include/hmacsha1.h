#ifndef HMACSHA1_H
#define HMACSHA1_H

#include <stdint.h>
#include <stddef.h>

#define HMACSHA1_MAC_SIZE 20

int hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t mac[HMACSHA1_MAC_SIZE]);

#endif

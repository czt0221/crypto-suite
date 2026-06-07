#ifndef PBKDF2_H
#define PBKDF2_H

#include <stdint.h>
#include <stddef.h>

int pbkdf2(const uint8_t *pass, size_t pass_len, const uint8_t *salt, size_t salt_len, unsigned int iter, uint8_t *key, size_t key_len);
int pbkdf2_sha256(const uint8_t *pass, size_t pass_len, const uint8_t *salt, size_t salt_len, unsigned int iter, uint8_t *key, size_t key_len);

#endif

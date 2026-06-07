#ifndef RC6_H
#define RC6_H

#include <stdint.h>
#include <stddef.h>

#define RC6_BLOCK_SIZE 16
#define RC6_KEY_SIZE   16

int rc6_ecb_encrypt(const uint8_t key[RC6_KEY_SIZE], const uint8_t *plain, size_t plain_len, uint8_t *cipher, size_t *cipher_len);
int rc6_ecb_decrypt(const uint8_t key[RC6_KEY_SIZE], const uint8_t *cipher, size_t cipher_len, uint8_t *plain, size_t *plain_len);
int rc6_cbc_encrypt(const uint8_t key[RC6_KEY_SIZE], const uint8_t iv[RC6_BLOCK_SIZE], const uint8_t *plain, size_t plain_len, uint8_t *cipher, size_t *cipher_len);
int rc6_cbc_decrypt(const uint8_t key[RC6_KEY_SIZE], const uint8_t iv[RC6_BLOCK_SIZE], const uint8_t *cipher, size_t cipher_len, uint8_t *plain, size_t *plain_len);

#endif

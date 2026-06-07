#ifndef SM4_H
#define SM4_H

#include <stdint.h>
#include <stddef.h>

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE   16

int sm4_ecb_encrypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t *plain, size_t plain_len, uint8_t *cipher, size_t *cipher_len);
int sm4_ecb_decrypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t *cipher, size_t cipher_len, uint8_t *plain, size_t *plain_len);
int sm4_cbc_encrypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[SM4_BLOCK_SIZE], const uint8_t *plain, size_t plain_len, uint8_t *cipher, size_t *cipher_len);
int sm4_cbc_decrypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[SM4_BLOCK_SIZE], const uint8_t *cipher, size_t cipher_len, uint8_t *plain, size_t *plain_len);

#endif

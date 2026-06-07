#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE   16

int aes_ecb_encrypt(const uint8_t key[AES_KEY_SIZE], const uint8_t *plain, size_t plain_len, uint8_t *cipher, size_t *cipher_len);
int aes_ecb_decrypt(const uint8_t key[AES_KEY_SIZE], const uint8_t *cipher, size_t cipher_len, uint8_t *plain, size_t *plain_len);
int aes_cbc_encrypt(const uint8_t key[AES_KEY_SIZE], const uint8_t iv[AES_BLOCK_SIZE], const uint8_t *plain, size_t plain_len, uint8_t *cipher, size_t *cipher_len);
int aes_cbc_decrypt(const uint8_t key[AES_KEY_SIZE], const uint8_t iv[AES_BLOCK_SIZE], const uint8_t *cipher, size_t cipher_len, uint8_t *plain, size_t *plain_len);

#endif

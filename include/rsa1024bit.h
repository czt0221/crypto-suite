#ifndef RSA1024BIT_H
#define RSA1024BIT_H

#include <stdint.h>
#include <stddef.h>

#define RSA_PLAIN_MAX 117
#define RSA_PRI_RAW_SIZE 580
#define RSA_PUB_RAW_SIZE 132

int rsa_gen_keypair(uint8_t *pri, size_t *pri_len, uint8_t *pub, size_t *pub_len);
int rsa_encrypt(const uint8_t *pub, size_t pub_len, const uint8_t *plain, size_t plain_len, uint8_t *cipher, size_t *cipher_len);
int rsa_decrypt(const uint8_t *pri, size_t pri_len, const uint8_t *cipher, size_t cipher_len, uint8_t *plain, size_t *plain_len);
int rsa_priv_to_pem(const uint8_t *pri, size_t pri_len, char *pem, size_t *pem_len);
int rsa_pub_to_pem(const uint8_t *pub, size_t pub_len, char *pem, size_t *pem_len);

#endif

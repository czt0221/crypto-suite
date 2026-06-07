#ifndef ECC160BIT_H
#define ECC160BIT_H

#include <stdint.h>
#include <stddef.h>

#define ECC_BYTES 20

int ecc_gen_keypair(uint8_t *pri, size_t *pri_len, uint8_t *pub, size_t *pub_len);
int ecc_pub_to_pem(const uint8_t *pub, size_t pub_len, char *pem, size_t *pem_len);
int ecc_pri_to_pem(const uint8_t *pri, size_t pri_len, const uint8_t *pub, size_t pub_len, char *pem, size_t *pem_len);

#endif

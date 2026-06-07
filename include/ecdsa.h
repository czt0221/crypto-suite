#ifndef ECDSA_H
#define ECDSA_H

#include <stdint.h>
#include <stddef.h>

int ecdsa_sign(const uint8_t *pri, size_t pri_len, const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len);
int ecdsa_verify(const uint8_t *pub, size_t pub_len, const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len);

#endif

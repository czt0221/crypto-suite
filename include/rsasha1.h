#ifndef RSASHA1_H
#define RSASHA1_H

#include <stdint.h>
#include <stddef.h>

int rsa_sha1_sign(const uint8_t *pri, size_t pri_len, const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len);
int rsa_sha1_verify(const uint8_t *pub, size_t pub_len, const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len);

#endif

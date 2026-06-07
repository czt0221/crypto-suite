#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdint.h>
#include <stddef.h>

#define BN_MAX_LIMBS 64

typedef struct {
    uint32_t d[BN_MAX_LIMBS];
    int len;
} bn_t;

void bn_zero(bn_t *a);
int bn_is_zero(const bn_t *a);
void bn_from_int(bn_t *a, uint32_t v);
int bn_from_bytes(bn_t *a, const uint8_t *buf, size_t len);
void bn_to_bytes(const bn_t *a, uint8_t *buf, size_t len);
int bn_cmp(const bn_t *a, const bn_t *b);
void bn_add(bn_t *r, const bn_t *a, const bn_t *b);
void bn_sub(bn_t *r, const bn_t *a, const bn_t *b);
void bn_mul(bn_t *r, const bn_t *a, const bn_t *b);
void bn_div(bn_t *q, bn_t *rem, const bn_t *a, const bn_t *b);
void bn_mod(bn_t *r, const bn_t *a, const bn_t *m);
void bn_mod_exp(bn_t *r, const bn_t *a, const bn_t *e, const bn_t *m);
void bn_mod_inv(bn_t *r, const bn_t *a, const bn_t *m);
int bn_is_prime(const bn_t *a);
int bn_random(bn_t *r, int bits);

#endif

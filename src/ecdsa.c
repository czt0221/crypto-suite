#include "crypto.h"
#include "ecdsa.h"
#include "bignum.h"
#include "sha1.h"
#include "rand_util.h"
#include <string.h>
#include <stdio.h>

#define ECC_BYTES 20
#define ECC_BITS 160

static const uint8_t N_BYTES[] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0xF4, 0xC8, 0xF9, 0x27, 0xAE,
    0xD3, 0xCA, 0x75, 0x22, 0x57
};

static const uint8_t P_BYTES[ECC_BYTES] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x7F, 0xFF, 0xFF, 0xFF
};

static const uint8_t GX_BYTES[ECC_BYTES] = {
    0x4A, 0x96, 0xB5, 0x68, 0x8E, 0xF5, 0x73, 0x28,
    0x46, 0x64, 0x69, 0x89, 0x68, 0xC3, 0x8B, 0xB9,
    0x13, 0xCB, 0xFC, 0x82
};

static const uint8_t GY_BYTES[ECC_BYTES] = {
    0x23, 0xA6, 0x28, 0x55, 0x31, 0x68, 0x94, 0x7D,
    0x59, 0xDC, 0xC9, 0x12, 0x04, 0x23, 0x51, 0x37,
    0x7A, 0xC5, 0xFB, 0x32
};

typedef struct {
    bn_t x, y, z;
} jac_point;

static void fp_add(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m)
{
    bn_add(r, a, b);
    if (bn_cmp(r, m) >= 0) bn_sub(r, r, m);
}

static void fp_sub(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m)
{
    if (bn_cmp(a, b) >= 0) {
        bn_sub(r, a, b);
    } else {
        bn_t tmp;
        bn_sub(&tmp, b, a);
        bn_sub(r, m, &tmp);
    }
}

static void fp_mul(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m)
{
    bn_mul(r, a, b);
    bn_mod(r, r, m);
}

static void fp_sqr(bn_t *r, const bn_t *a, const bn_t *m)
{
    bn_mul(r, a, a);
    bn_mod(r, r, m);
}

static int bn_bit_len(const bn_t *a)
{
    if (a->len == 0 || (a->len == 1 && a->d[0] == 0)) return 0;
    uint32_t top = a->d[a->len - 1];
    int bits = (a->len - 1) * 32;
    while (top) { bits++; top >>= 1; }
    return bits;
}

static void mod_n_mul(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *n)
{
    bn_mul(r, a, b);
    bn_mod(r, r, n);
}

static void mod_n_add(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *n)
{
    bn_add(r, a, b);
    if (bn_cmp(r, n) >= 0) bn_sub(r, r, n);
}

static void point_double(jac_point *r, const jac_point *p, const bn_t *m)
{
    bn_t t1, t2, t3, t4, three;
    bn_t sy = p->y;

    if (bn_is_zero(&p->z)) {
        *r = *p;
        return;
    }

    bn_from_int(&three, 3);

    fp_sqr(&t1, &p->z, m);
    fp_sub(&t2, &p->x, &t1, m);
    fp_add(&t1, &p->x, &t1, m);
    fp_mul(&t1, &t2, &t1, m);
    fp_mul(&t1, &t1, &three, m);

    fp_sqr(&t2, &p->y, m);
    fp_mul(&t3, &p->x, &t2, m);
    bn_from_int(&t4, 4);
    fp_mul(&t3, &t3, &t4, m);

    fp_sqr(&t4, &t2, m);
    bn_from_int(&t2, 8);
    fp_mul(&t4, &t4, &t2, m);

    fp_sqr(&r->x, &t1, m);
    fp_add(&t2, &t3, &t3, m);
    fp_sub(&r->x, &r->x, &t2, m);

    fp_sub(&t2, &t3, &r->x, m);
    fp_mul(&t2, &t1, &t2, m);
    fp_sub(&r->y, &t2, &t4, m);

    fp_mul(&r->z, &sy, &p->z, m);
    fp_add(&r->z, &r->z, &r->z, m);
}

static void point_add_mixed(jac_point *r, const jac_point *p1, const jac_point *p2, const bn_t *m)
{
    bn_t t1, t2, t3, t4, t5, t6, t7, t8, t9;

    if (bn_is_zero(&p1->z)) {
        r->x = p2->x;
        r->y = p2->y;
        bn_from_int(&r->z, 1);
        return;
    }

    fp_sqr(&t1, &p1->z, m);
    fp_mul(&t2, &p1->z, &t1, m);
    fp_mul(&t3, &p2->x, &t1, m);
    fp_mul(&t4, &p2->y, &t2, m);

    fp_sub(&t5, &t3, &p1->x, m);
    fp_sub(&t6, &t4, &p1->y, m);

    if (bn_is_zero(&t5)) {
        if (bn_is_zero(&t6)) {
            point_double(r, p1, m);
            return;
        }
        bn_zero(&r->z);
        return;
    }

    fp_sqr(&t7, &t5, m);
    fp_mul(&t8, &t5, &t7, m);
    fp_mul(&t9, &p1->x, &t7, m);

    fp_sqr(&r->x, &t6, m);
    fp_sub(&r->x, &r->x, &t8, m);
    fp_add(&t1, &t9, &t9, m);
    fp_sub(&r->x, &r->x, &t1, m);

    fp_sub(&t1, &t9, &r->x, m);
    fp_mul(&t1, &t6, &t1, m);
    fp_mul(&t2, &p1->y, &t8, m);
    fp_sub(&r->y, &t1, &t2, m);

    fp_mul(&r->z, &p1->z, &t5, m);
}

static void point_add(jac_point *r, const jac_point *p1, const jac_point *p2, const bn_t *m)
{
    bn_t u1, u2, s1, s2, h, h2, h3, rr, t;

    if (bn_is_zero(&p1->z)) {
        *r = *p2;
        return;
    }
    if (bn_is_zero(&p2->z)) {
        *r = *p1;
        return;
    }

    fp_sqr(&h, &p2->z, m);
    fp_mul(&u1, &p1->x, &h, m);
    fp_mul(&h3, &h, &p2->z, m);
    fp_mul(&s1, &p1->y, &h3, m);

    fp_sqr(&h, &p1->z, m);
    fp_mul(&u2, &p2->x, &h, m);
    fp_mul(&h3, &h, &p1->z, m);
    fp_mul(&s2, &p2->y, &h3, m);

    if (bn_cmp(&u1, &u2) == 0) {
        if (bn_cmp(&s1, &s2) == 0) {
            point_double(r, p1, m);
            return;
        }
        bn_zero(&r->z);
        return;
    }

    fp_sub(&h, &u2, &u1, m);
    fp_sub(&rr, &s2, &s1, m);

    fp_sqr(&h2, &h, m);
    fp_mul(&h3, &h2, &h, m);

    fp_sqr(&r->x, &rr, m);
    fp_sub(&r->x, &r->x, &h3, m);
    fp_mul(&t, &u1, &h2, m);
    fp_add(&t, &t, &t, m);
    fp_sub(&r->x, &r->x, &t, m);

    fp_mul(&t, &u1, &h2, m);
    fp_sub(&t, &t, &r->x, m);
    fp_mul(&t, &rr, &t, m);
    fp_mul(&u1, &s1, &h3, m);
    fp_sub(&r->y, &t, &u1, m);

    fp_mul(&r->z, &p1->z, &p2->z, m);
    fp_mul(&r->z, &r->z, &h, m);
}

static void scalar_mult(jac_point *r, const jac_point *g, const bn_t *k, const bn_t *m)
{
    jac_point q;
    bn_zero(&q.z);

    int bits = bn_bit_len(k);

    for (int i = bits - 1; i >= 0; i--) {
        point_double(&q, &q, m);
        if (k->d[i / 32] & (1u << (i % 32))) {
            point_add_mixed(&q, &q, g, m);
        }
    }

    *r = q;
}

static void jac_to_affine(bn_t *x, bn_t *y, const jac_point *p, const bn_t *m)
{
    bn_t z_inv, z_inv_sq;
    bn_mod_inv(&z_inv, &p->z, m);
    fp_sqr(&z_inv_sq, &z_inv, m);
    fp_mul(x, &p->x, &z_inv_sq, m);
    fp_mul(&z_inv_sq, &z_inv_sq, &z_inv, m);
    fp_mul(y, &p->y, &z_inv_sq, m);
}

int ecdsa_sign(const uint8_t *pri, size_t pri_len, const uint8_t *msg, size_t msg_len,
               uint8_t *sig, size_t *sig_len)
{
    bn_t prime, order, gx, gy, priv_bn, h_bn, k, k_inv, r, s, t1;
    jac_point g, pt;
    uint8_t hash[SHA1_DIGEST_SIZE];
    bn_t zero;

    if (!pri || !msg || !sig || !sig_len) return CRYPTO_ERR;
    if (pri_len != ECC_BYTES) return CRYPTO_ERR;
    if (*sig_len < ECC_BYTES * 2) return CRYPTO_ERR;

    sha1(msg, msg_len, hash);

    bn_from_bytes(&prime, P_BYTES, ECC_BYTES);
    bn_from_bytes(&order, N_BYTES, sizeof(N_BYTES));
    bn_from_bytes(&gx, GX_BYTES, ECC_BYTES);
    bn_from_bytes(&gy, GY_BYTES, ECC_BYTES);
    bn_from_bytes(&priv_bn, pri, pri_len);
    bn_from_bytes(&h_bn, hash, SHA1_DIGEST_SIZE);
    bn_from_int(&zero, 0);

    g.x = gx;
    g.y = gy;
    bn_from_int(&g.z, 1);

    for (;;) {
        bn_random(&k, ECC_BITS);
        if (bn_is_zero(&k)) continue;

        scalar_mult(&pt, &g, &k, &prime);
        jac_to_affine(&r, &t1, &pt, &prime);

        bn_mod(&r, &r, &order);
        if (bn_is_zero(&r)) continue;

        bn_mod_inv(&k_inv, &k, &order);

        mod_n_mul(&t1, &r, &priv_bn, &order);
        mod_n_add(&t1, &h_bn, &t1, &order);
        mod_n_mul(&s, &k_inv, &t1, &order);

        if (bn_is_zero(&s)) continue;

        break;
    }

    bn_to_bytes(&r, sig, ECC_BYTES);
    bn_to_bytes(&s, sig + ECC_BYTES, ECC_BYTES);
    *sig_len = ECC_BYTES * 2;

    return CRYPTO_OK;
}

int ecdsa_verify(const uint8_t *pub, size_t pub_len, const uint8_t *msg, size_t msg_len,
                 const uint8_t *sig, size_t sig_len)
{
    bn_t prime, order, gx, gy, r, s, w, u1, u2, h_bn, t, x1;
    jac_point g, q, p1, p2, pt;
    uint8_t hash[SHA1_DIGEST_SIZE];

    if (!pub || !msg || !sig) return CRYPTO_ERR;
    if (pub_len != ECC_BYTES * 2) return CRYPTO_ERR;
    if (sig_len != ECC_BYTES * 2) return CRYPTO_ERR;

    bn_from_bytes(&prime, P_BYTES, ECC_BYTES);
    bn_from_bytes(&order, N_BYTES, sizeof(N_BYTES));
    bn_from_bytes(&gx, GX_BYTES, ECC_BYTES);
    bn_from_bytes(&gy, GY_BYTES, ECC_BYTES);

    bn_from_bytes(&r, sig, ECC_BYTES);
    bn_from_bytes(&s, sig + ECC_BYTES, ECC_BYTES);

    bn_from_int(&t, 1);

    if (bn_cmp(&r, &t) < 0 || bn_cmp(&s, &t) < 0) return CRYPTO_ERR;
    if (bn_cmp(&r, &order) >= 0 || bn_cmp(&s, &order) >= 0) return CRYPTO_ERR;

    sha1(msg, msg_len, hash);
    bn_from_bytes(&h_bn, hash, SHA1_DIGEST_SIZE);

    bn_mod_inv(&w, &s, &order);

    mod_n_mul(&u1, &h_bn, &w, &order);
    mod_n_mul(&u2, &r, &w, &order);

    g.x = gx;
    g.y = gy;
    bn_from_int(&g.z, 1);

    bn_from_bytes(&q.x, pub, ECC_BYTES);
    bn_from_bytes(&q.y, pub + ECC_BYTES, ECC_BYTES);
    bn_from_int(&q.z, 1);

    scalar_mult(&p1, &g, &u1, &prime);
    scalar_mult(&p2, &q, &u2, &prime);
    point_add(&pt, &p1, &p2, &prime);

    jac_to_affine(&x1, &t, &pt, &prime);
    bn_mod(&x1, &x1, &order);

    if (bn_cmp(&x1, &r) != 0) return CRYPTO_ERR;

    return CRYPTO_OK;
}

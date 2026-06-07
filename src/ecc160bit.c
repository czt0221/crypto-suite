#include "crypto.h"
#include "ecc160bit.h"
#include "bignum.h"
#include "rand_util.h"
#include <string.h>

#define ECC_BITS 160

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

static void scalar_mult(jac_point *r, const jac_point *g, const bn_t *k, const bn_t *m)
{
    jac_point q;
    bn_zero(&q.z);

    int bits = bn_bit_len(k);

    for (int i = bits - 1; i >= 0; i--) {
        point_double(&q, &q, m);
        if (k->d[i / 32] & ((uint32_t)1 << (i % 32))) {
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

int ecc_gen_keypair(uint8_t *pri, size_t *pri_len, uint8_t *pub, size_t *pub_len)
{
    bn_t prime, gx, gy, priv;
    jac_point g, result;

    bn_from_bytes(&prime, P_BYTES, ECC_BYTES);
    bn_from_bytes(&gx, GX_BYTES, ECC_BYTES);
    bn_from_bytes(&gy, GY_BYTES, ECC_BYTES);

    do {
        bn_random(&priv, ECC_BITS);
    } while (bn_is_zero(&priv));

    g.x = gx;
    g.y = gy;
    bn_from_int(&g.z, 1);

    scalar_mult(&result, &g, &priv, &prime);

    jac_to_affine(&result.x, &result.y, &result, &prime);

    if (pri && pri_len) {
        bn_to_bytes(&priv, pri, ECC_BYTES);
        *pri_len = ECC_BYTES;
    }
    if (pub && pub_len) {
        bn_to_bytes(&result.x, pub, ECC_BYTES);
        bn_to_bytes(&result.y, pub + ECC_BYTES, ECC_BYTES);
        *pub_len = ECC_BYTES * 2;
    }

    return CRYPTO_OK;
}

int ecc_pub_to_pem(const uint8_t *pub, size_t pub_len, char *pem, size_t *pem_len)
{
    if (pub_len != ECC_BYTES * 2) return CRYPTO_ERR;

    uint8_t der[96];
    int off = 0;

    der[off++] = 0x30;
    int spki_len_off = off++;

    der[off++] = 0x30;
    der[off++] = 0x10;

    der[off++] = 0x06; der[off++] = 0x07;
    der[off++] = 0x2A; der[off++] = 0x86; der[off++] = 0x48;
    der[off++] = 0xCE; der[off++] = 0x3D; der[off++] = 0x02;
    der[off++] = 0x01;

    der[off++] = 0x06; der[off++] = 0x05;
    der[off++] = 0x2B; der[off++] = 0x81; der[off++] = 0x04;
    der[off++] = 0x00; der[off++] = 0x08;

    der[off++] = 0x03;
    der[off++] = 0x2A;
    der[off++] = 0x00;
    der[off++] = 0x04;
    memcpy(der + off, pub, ECC_BYTES); off += ECC_BYTES;
    memcpy(der + off, pub + ECC_BYTES, ECC_BYTES); off += ECC_BYTES;

    der[spki_len_off] = off - spki_len_off - 1;
    int der_len = off;

    size_t b64_len;
    base64_encode(der, der_len, NULL, &b64_len);
    size_t lines = (b64_len + 63) / 64;
    size_t total = 11 + 10 + 6 + b64_len + lines + 9 + 10 + 6;
    if (pem == NULL) {
        *pem_len = total;
        return CRYPTO_OK;
    }
    if (*pem_len < total) return CRYPTO_ERR;

    char b64[512];
    base64_encode(der, der_len, b64, &b64_len);

    char *p = pem;
    memcpy(p, "-----BEGIN ", 11); p += 11;
    memcpy(p, "PUBLIC KEY", 10); p += 10;
    memcpy(p, "-----\n", 6); p += 6;
    for (size_t i = 0; i < b64_len; i += 64) {
        size_t chunk = (b64_len - i < 64) ? b64_len - i : 64;
        memcpy(p, b64 + i, chunk); p += chunk;
        *p++ = '\n';
    }
    memcpy(p, "-----END ", 9); p += 9;
    memcpy(p, "PUBLIC KEY", 10); p += 10;
    memcpy(p, "-----\n", 6); p += 6;
    *p = '\0';
    *pem_len = (size_t)(p - pem);
    return CRYPTO_OK;
}

int ecc_pri_to_pem(const uint8_t *pri, size_t pri_len, const uint8_t *pub, size_t pub_len,
                   char *pem, size_t *pem_len)
{
    if (pri_len != ECC_BYTES || pub_len != ECC_BYTES * 2) return CRYPTO_ERR;

    uint8_t der[128];
    int off = 0;

    der[off++] = 0x30;
    int seq_len_off = off++;

    der[off++] = 0x02; der[off++] = 0x01; der[off++] = 0x01;

    der[off++] = 0x04; der[off++] = ECC_BYTES;
    memcpy(der + off, pri, ECC_BYTES); off += ECC_BYTES;

    der[off++] = 0xA0; der[off++] = 0x07;
    der[off++] = 0x06; der[off++] = 0x05;
    der[off++] = 0x2B; der[off++] = 0x81; der[off++] = 0x04;
    der[off++] = 0x00; der[off++] = 0x08;

    der[off++] = 0xA1;
    int a1_len_off = off++;
    der[off++] = 0x03; der[off++] = 0x2A; der[off++] = 0x00;
    der[off++] = 0x04;
    memcpy(der + off, pub, ECC_BYTES); off += ECC_BYTES;
    memcpy(der + off, pub + ECC_BYTES, ECC_BYTES); off += ECC_BYTES;
    der[a1_len_off] = off - a1_len_off - 1;

    der[seq_len_off] = off - seq_len_off - 1;
    int der_len = off;

    size_t b64_len;
    base64_encode(der, der_len, NULL, &b64_len);
    size_t lines = (b64_len + 63) / 64;
    size_t total = 11 + 16 + 6 + b64_len + lines + 9 + 16 + 6;
    if (pem == NULL) {
        *pem_len = total;
        return CRYPTO_OK;
    }
    if (*pem_len < total) return CRYPTO_ERR;

    char b64[512];
    base64_encode(der, der_len, b64, &b64_len);

    char *p = pem;
    memcpy(p, "-----BEGIN ", 11); p += 11;
    memcpy(p, "EC PRIVATE KEY", 14); p += 14;
    memcpy(p, "-----\n", 6); p += 6;
    for (size_t i = 0; i < b64_len; i += 64) {
        size_t chunk = (b64_len - i < 64) ? b64_len - i : 64;
        memcpy(p, b64 + i, chunk); p += chunk;
        *p++ = '\n';
    }
    memcpy(p, "-----END ", 9); p += 9;
    memcpy(p, "EC PRIVATE KEY", 14); p += 14;
    memcpy(p, "-----\n", 6); p += 6;
    *p = '\0';
    *pem_len = (size_t)(p - pem);
    return CRYPTO_OK;
}

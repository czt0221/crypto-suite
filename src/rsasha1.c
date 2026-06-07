#include "crypto.h"
#include "rsasha1.h"
#include "bignum.h"
#include "sha1.h"
#include <string.h>

#define RSA_BYTES 128
#define RSA_PRI_RAW_SIZE 580
#define RSA_PUB_RAW_SIZE 132
#define DIGESTINFO_LEN 35
#define HASH_LEN 20

static const unsigned char DIGESTINFO_PREFIX[DIGESTINFO_LEN - HASH_LEN] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};

static void parse_pri(const uint8_t *pri, bn_t *p, bn_t *q, bn_t *n,
                      bn_t *e, bn_t *d, bn_t *dp, bn_t *dq, bn_t *qinv)
{
    bn_from_bytes(p, pri, 64); pri += 64;
    bn_from_bytes(q, pri, 64); pri += 64;
    bn_from_bytes(n, pri, 128); pri += 128;
    bn_from_bytes(e, pri, 4); pri += 4;
    bn_from_bytes(d, pri, 128); pri += 128;
    bn_from_bytes(dp, pri, 64); pri += 64;
    bn_from_bytes(dq, pri, 64); pri += 64;
    bn_from_bytes(qinv, pri, 64);
}

static void parse_pub(const uint8_t *pub, bn_t *n, bn_t *e)
{
    bn_from_bytes(n, pub, 128);
    bn_from_bytes(e, pub + 128, 4);
}

static void crt_decrypt(bn_t *m, const bn_t *c, const bn_t *p, const bn_t *q,
                        const bn_t *dp, const bn_t *dq, const bn_t *qinv)
{
    bn_t m1, m2, h, tmp;
    bn_mod_exp(&m1, c, dp, p);
    bn_mod_exp(&m2, c, dq, q);
    if (bn_cmp(&m1, &m2) >= 0)
        bn_sub(&tmp, &m1, &m2);
    else {
        bn_sub(&tmp, &m2, &m1);
        bn_sub(&tmp, p, &tmp);
    }
    bn_mul(&h, qinv, &tmp);
    bn_mod(&h, &h, p);
    bn_mul(&tmp, &h, q);
    bn_add(m, &m2, &tmp);
}

static int build_pkcs1_v1p5_type1(uint8_t *padded, const uint8_t *hash)
{
    uint8_t digestinfo[DIGESTINFO_LEN];
    memcpy(digestinfo, DIGESTINFO_PREFIX, sizeof(DIGESTINFO_PREFIX));
    memcpy(digestinfo + sizeof(DIGESTINFO_PREFIX), hash, HASH_LEN);
    int ps_len = RSA_BYTES - 3 - DIGESTINFO_LEN;
    padded[0] = 0x00;
    padded[1] = 0x01;
    memset(padded + 2, 0xFF, ps_len);
    padded[2 + ps_len] = 0x00;
    memcpy(padded + 3 + ps_len, digestinfo, DIGESTINFO_LEN);
    return CRYPTO_OK;
}

static int check_pkcs1_v1p5_type1(const uint8_t *padded, const uint8_t *hash)
{
    if (padded[0] != 0x00 || padded[1] != 0x01) return CRYPTO_ERR;
    int ps_len = RSA_BYTES - 3 - DIGESTINFO_LEN;
    for (int i = 0; i < ps_len; i++) {
        if (padded[2 + i] != 0xFF) return CRYPTO_ERR;
    }
    if (padded[2 + ps_len] != 0x00) return CRYPTO_ERR;
    uint8_t digestinfo[DIGESTINFO_LEN];
    memcpy(digestinfo, DIGESTINFO_PREFIX, sizeof(DIGESTINFO_PREFIX));
    memcpy(digestinfo + sizeof(DIGESTINFO_PREFIX), hash, HASH_LEN);
    if (memcmp(padded + 3 + ps_len, digestinfo, DIGESTINFO_LEN) != 0) return CRYPTO_ERR;
    return CRYPTO_OK;
}

int rsa_sha1_sign(const uint8_t *pri, size_t pri_len, const uint8_t *msg, size_t msg_len,
                  uint8_t *sig, size_t *sig_len)
{
    bn_t p, q, n, e, d, dp, dq, qinv, m, c;
    uint8_t hash[HASH_LEN];
    uint8_t padded[RSA_BYTES];
    if (pri_len < RSA_PRI_RAW_SIZE) return CRYPTO_ERR;
    sha1(msg, msg_len, hash);
    parse_pri(pri, &p, &q, &n, &e, &d, &dp, &dq, &qinv);
    build_pkcs1_v1p5_type1(padded, hash);
    bn_from_bytes(&m, padded, RSA_BYTES);
    if (bn_cmp(&m, &n) >= 0) return CRYPTO_ERR;
    crt_decrypt(&c, &m, &p, &q, &dp, &dq, &qinv);
    if (sig) {
        bn_to_bytes(&c, sig, RSA_BYTES);
    }
    if (sig_len) *sig_len = RSA_BYTES;
    return CRYPTO_OK;
}

int rsa_sha1_verify(const uint8_t *pub, size_t pub_len, const uint8_t *msg, size_t msg_len,
                    const uint8_t *sig, size_t sig_len)
{
    bn_t n, e, c, m;
    uint8_t hash[HASH_LEN];
    uint8_t padded[RSA_BYTES];
    if (pub_len < RSA_PUB_RAW_SIZE) return CRYPTO_ERR;
    if (sig_len != RSA_BYTES) return CRYPTO_ERR;
    sha1(msg, msg_len, hash);
    parse_pub(pub, &n, &e);
    bn_from_bytes(&c, sig, RSA_BYTES);
    if (bn_cmp(&c, &n) >= 0) return CRYPTO_ERR;
    bn_mod_exp(&m, &c, &e, &n);
    bn_to_bytes(&m, padded, RSA_BYTES);
    return check_pkcs1_v1p5_type1(padded, hash);
}

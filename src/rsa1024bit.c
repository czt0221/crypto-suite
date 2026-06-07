#include "crypto.h"
#include "rsa1024bit.h"
#include "bignum.h"
#include "rand_util.h"
#include <string.h>

#define RSA_BYTES 128
#define RSA_BITS 1024

static const unsigned char OID_RSA[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};

static int gen_prime(bn_t *p, int bits)
{
    int bytes = (bits + 7) / 8;
    uint8_t buf[128];
    int attempts = 0;
    do {
        if (rand_bytes(buf, bytes) != CRYPTO_OK) return CRYPTO_ERR;
        buf[0] |= 0xC0;
        buf[bytes - 1] |= 1;
        bn_from_bytes(p, buf, bytes);
        if (bn_is_prime(p)) return CRYPTO_OK;
        if (++attempts > 10000) return CRYPTO_ERR;
    } while (1);
}

static int bn_min_bytes(const bn_t *a)
{
    if (a->len == 0 || (a->len == 1 && a->d[0] == 0)) return 1;
    uint32_t top = a->d[a->len - 1];
    int bits = (a->len - 1) * 32;
    uint32_t t = top;
    while (t) { bits++; t >>= 1; }
    return (bits + 7) / 8;
}

static int bn_write_minimal(const bn_t *a, uint8_t *buf)
{
    int nbytes = bn_min_bytes(a);
    bn_to_bytes(a, buf, nbytes);
    return nbytes;
}

static int write_der_len(uint8_t *buf, int len)
{
    if (len < 128) {
        buf[0] = (uint8_t)len;
        return 1;
    }
    if (len < 256) {
        buf[0] = 0x81;
        buf[1] = (uint8_t)len;
        return 2;
    }
    buf[0] = 0x82;
    buf[1] = (uint8_t)((len >> 8) & 0xFF);
    buf[2] = (uint8_t)(len & 0xFF);
    return 3;
}

static int write_der_int(uint8_t *buf, const bn_t *v)
{
    uint8_t tmp[256];
    int vlen = bn_write_minimal(v, tmp);
    int add_zero = (tmp[0] & 0x80) ? 1 : 0;
    int total_val = vlen + add_zero;
    int pos = 0;
    buf[pos++] = 0x02;
    pos += write_der_len(buf + pos, total_val);
    if (add_zero) buf[pos++] = 0x00;
    memcpy(buf + pos, tmp, vlen);
    return pos + vlen;
}

static int build_priv_der(const bn_t *n, const bn_t *e, const bn_t *d,
                          const bn_t *p, const bn_t *q,
                          const bn_t *dp, const bn_t *dq, const bn_t *qinv,
                          uint8_t *out)
{
    uint8_t inner[1024];
    int pos = 0;
    bn_t zero;
    bn_from_int(&zero, 0);
    pos += write_der_int(inner + pos, &zero);
    pos += write_der_int(inner + pos, n);
    pos += write_der_int(inner + pos, e);
    pos += write_der_int(inner + pos, d);
    pos += write_der_int(inner + pos, p);
    pos += write_der_int(inner + pos, q);
    pos += write_der_int(inner + pos, dp);
    pos += write_der_int(inner + pos, dq);
    pos += write_der_int(inner + pos, qinv);
    int o = 0;
    out[o++] = 0x30;
    o += write_der_len(out + o, pos);
    memcpy(out + o, inner, pos);
    return o + pos;
}

static int build_spki_der(const bn_t *n, const bn_t *e, uint8_t *out)
{
    uint8_t rsa_pub[512];
    int rp = 0;
    rp += write_der_int(rsa_pub + rp, n);
    rp += write_der_int(rsa_pub + rp, e);
    uint8_t rsa_pub_seq[512];
    int rps = 0;
    rsa_pub_seq[rps++] = 0x30;
    rps += write_der_len(rsa_pub_seq + rps, rp);
    memcpy(rsa_pub_seq + rps, rsa_pub, rp);
    rps += rp;
    uint8_t alg[32];
    int ap = 0;
    alg[ap++] = 0x30;
    alg[ap++] = 0x0D;
    alg[ap++] = 0x06;
    alg[ap++] = 0x09;
    memcpy(alg + ap, OID_RSA, 9);
    ap += 9;
    alg[ap++] = 0x05;
    alg[ap++] = 0x00;
    uint8_t bitstr[512];
    int bp = 0;
    bitstr[bp++] = 0x03;
    bp += write_der_len(bitstr + bp, rps + 1);
    bitstr[bp++] = 0x00;
    memcpy(bitstr + bp, rsa_pub_seq, rps);
    bp += rps;
    uint8_t inner[1024];
    int ip = 0;
    memcpy(inner + ip, alg, ap);
    ip += ap;
    memcpy(inner + ip, bitstr, bp);
    ip += bp;
    int o = 0;
    out[o++] = 0x30;
    o += write_der_len(out + o, ip);
    memcpy(out + o, inner, ip);
    return o + ip;
}

static int pem_encode(const uint8_t *der, int der_len,
                      const char *header, int header_len,
                      char *pem, size_t *pem_len)
{
    size_t b64_len;
    base64_encode(der, der_len, NULL, &b64_len);
    size_t lines = (b64_len + 63) / 64;
    size_t total = 11 + header_len + 6 + b64_len + lines + 9 + header_len + 6;
    if (pem == NULL) {
        *pem_len = total;
        return CRYPTO_OK;
    }
    if (*pem_len < total) return CRYPTO_ERR;
    char b64[2048];
    base64_encode(der, der_len, b64, &b64_len);
    char *p = pem;
    memcpy(p, "-----BEGIN ", 11); p += 11;
    memcpy(p, header, header_len); p += header_len;
    memcpy(p, "-----\n", 6); p += 6;
    for (size_t i = 0; i < b64_len; i += 64) {
        size_t chunk = (b64_len - i < 64) ? b64_len - i : 64;
        memcpy(p, b64 + i, chunk); p += chunk;
        *p++ = '\n';
    }
    memcpy(p, "-----END ", 9); p += 9;
    memcpy(p, header, header_len); p += header_len;
    memcpy(p, "-----\n", 6); p += 6;
    *p = '\0';
    *pem_len = (size_t)(p - pem);
    return CRYPTO_OK;
}

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

static int pkcs1_pad(uint8_t *padded, const uint8_t *plain, size_t plain_len)
{
    if (plain_len > RSA_PLAIN_MAX) return CRYPTO_ERR;
    int ps_len = RSA_BYTES - 3 - (int)plain_len;
    padded[0] = 0x00;
    padded[1] = 0x02;
    if (rand_bytes(padded + 2, ps_len) != CRYPTO_OK) return CRYPTO_ERR;
    for (int i = 0; i < ps_len; i++) {
        while (padded[2 + i] == 0x00) {
            if (rand_bytes(padded + 2 + i, 1) != CRYPTO_OK) return CRYPTO_ERR;
        }
    }
    padded[2 + ps_len] = 0x00;
    memcpy(padded + 3 + ps_len, plain, plain_len);
    return CRYPTO_OK;
}

static int pkcs1_unpad(const uint8_t *padded, size_t padded_len,
                       uint8_t *plain, size_t *plain_len)
{
    if (padded_len != (size_t)RSA_BYTES) return CRYPTO_ERR;
    if (padded[0] != 0x00 || padded[1] != 0x02) return CRYPTO_ERR;
    int sep = -1;
    for (int i = 2; i < RSA_BYTES; i++) {
        if (padded[i] == 0x00) { sep = i; break; }
    }
    if (sep < 2) return CRYPTO_ERR;
    int msg_len = RSA_BYTES - sep - 1;
    if (msg_len > RSA_PLAIN_MAX) return CRYPTO_ERR;
    if (msg_len < 0) return CRYPTO_ERR;
    *plain_len = (size_t)msg_len;
    memcpy(plain, padded + sep + 1, msg_len);
    return CRYPTO_OK;
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

int rsa_gen_keypair(uint8_t *pri, size_t *pri_len,
                    uint8_t *pub, size_t *pub_len)
{
    bn_t p, q, n, e, d, phi, dp, dq, qinv, p1, q1, one, tmp;
    int retry;
    do {
        retry = 0;
        if (gen_prime(&p, 512) != CRYPTO_OK) return CRYPTO_ERR;
        do {
            if (gen_prime(&q, 512) != CRYPTO_OK) return CRYPTO_ERR;
        } while (bn_cmp(&p, &q) == 0);
        if (bn_cmp(&p, &q) < 0) { bn_t t = p; p = q; q = t; }
        bn_mul(&n, &p, &q);
        bn_from_int(&one, 1);
        bn_sub(&p1, &p, &one);
        bn_sub(&q1, &q, &one);
        bn_mul(&phi, &p1, &q1);
        bn_from_int(&e, 65537);
        bn_mod_inv(&d, &e, &phi);
        bn_mul(&tmp, &e, &d);
        bn_mod(&tmp, &tmp, &phi);
        if (!(tmp.len == 1 && tmp.d[0] == 1)) retry = 1;
    } while (retry);
    bn_mod(&dp, &d, &p1);
    bn_mod(&dq, &d, &q1);
    bn_mod_inv(&qinv, &q, &p);
    if (pri) {
        uint8_t *pp = pri;
        bn_to_bytes(&p, pp, 64); pp += 64;
        bn_to_bytes(&q, pp, 64); pp += 64;
        bn_to_bytes(&n, pp, 128); pp += 128;
        bn_to_bytes(&e, pp, 4); pp += 4;
        bn_to_bytes(&d, pp, 128); pp += 128;
        bn_to_bytes(&dp, pp, 64); pp += 64;
        bn_to_bytes(&dq, pp, 64); pp += 64;
        bn_to_bytes(&qinv, pp, 64);
    }
    if (pri_len) *pri_len = RSA_PRI_RAW_SIZE;
    if (pub) {
        bn_to_bytes(&n, pub, 128);
        bn_to_bytes(&e, pub + 128, 4);
    }
    if (pub_len) *pub_len = RSA_PUB_RAW_SIZE;
    return CRYPTO_OK;
}

int rsa_encrypt(const uint8_t *pub, size_t pub_len,
                const uint8_t *plain, size_t plain_len,
                uint8_t *cipher, size_t *cipher_len)
{
    bn_t n, e, m, c;
    uint8_t padded[RSA_BYTES];
    if (pub_len < (size_t)RSA_PUB_RAW_SIZE) return CRYPTO_ERR;
    if (pkcs1_pad(padded, plain, plain_len) != CRYPTO_OK) return CRYPTO_ERR;
    parse_pub(pub, &n, &e);
    bn_from_bytes(&m, padded, RSA_BYTES);
    bn_mod_exp(&c, &m, &e, &n);
    if (cipher) {
        bn_to_bytes(&c, cipher, RSA_BYTES);
    }
    if (cipher_len) *cipher_len = RSA_BYTES;
    return CRYPTO_OK;
}

int rsa_decrypt(const uint8_t *pri, size_t pri_len,
                const uint8_t *cipher, size_t cipher_len,
                uint8_t *plain, size_t *plain_len)
{
    bn_t p, q, n, e, d, dp, dq, qinv, c, m;
    uint8_t m_bytes[RSA_BYTES];
    if (pri_len < (size_t)RSA_PRI_RAW_SIZE) return CRYPTO_ERR;
    if (cipher_len != (size_t)RSA_BYTES) return CRYPTO_ERR;
    parse_pri(pri, &p, &q, &n, &e, &d, &dp, &dq, &qinv);
    bn_from_bytes(&c, cipher, RSA_BYTES);
    if (bn_cmp(&c, &n) >= 0) return CRYPTO_ERR;
    crt_decrypt(&m, &c, &p, &q, &dp, &dq, &qinv);
    bn_to_bytes(&m, m_bytes, RSA_BYTES);
    return pkcs1_unpad(m_bytes, RSA_BYTES, plain, plain_len);
}

int rsa_priv_to_pem(const uint8_t *pri, size_t pri_len,
                    char *pem, size_t *pem_len)
{
    bn_t p, q, n, e, d, dp, dq, qinv;
    if (pri_len < RSA_PRI_RAW_SIZE) return CRYPTO_ERR;
    parse_pri(pri, &p, &q, &n, &e, &d, &dp, &dq, &qinv);
    uint8_t der[2048];
    int der_len = build_priv_der(&n, &e, &d, &p, &q, &dp, &dq, &qinv, der);
    return pem_encode(der, der_len, "RSA PRIVATE KEY", 15, pem, pem_len);
}

int rsa_pub_to_pem(const uint8_t *pub, size_t pub_len,
                   char *pem, size_t *pem_len)
{
    bn_t n, e;
    if (pub_len < RSA_PUB_RAW_SIZE) return CRYPTO_ERR;
    parse_pub(pub, &n, &e);
    uint8_t der[2048];
    int der_len = build_spki_der(&n, &e, der);
    return pem_encode(der, der_len, "PUBLIC KEY", 10, pem, pem_len);
}

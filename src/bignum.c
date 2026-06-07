#include "crypto.h"
#include "bignum.h"
#include "rand_util.h"
#include <string.h>

void bn_zero(bn_t *a)
{
    memset(a->d, 0, sizeof(a->d));
    a->len = 0;
}

int bn_is_zero(const bn_t *a)
{
    for (int i = 0; i < a->len; i++)
        if (a->d[i] != 0) return 0;
    return 1;
}

void bn_from_int(bn_t *a, uint32_t v)
{
    bn_zero(a);
    a->d[0] = v;
    a->len = 1;
}

int bn_from_bytes(bn_t *a, const uint8_t *buf, size_t len)
{
    bn_zero(a);
    size_t n = (len + 3) / 4;
    if (n > BN_MAX_LIMBS) return CRYPTO_ERR;
    for (size_t i = 0; i < len; i++)
        a->d[(len - 1 - i) / 4] |= (uint32_t)buf[i] << (((len - 1 - i) % 4) * 8);
    a->len = (int)n;
    while (a->len > 0 && a->d[a->len - 1] == 0) a->len--;
    if (a->len == 0) a->len = 1;
    return CRYPTO_OK;
}

void bn_to_bytes(const bn_t *a, uint8_t *buf, size_t len)
{
    memset(buf, 0, len);
    for (int i = 0; i < a->len * 4 && (size_t)i < len; i++)
        buf[len - 1 - i] = (uint8_t)(a->d[i / 4] >> ((i % 4) * 8));
}

int bn_cmp(const bn_t *a, const bn_t *b)
{
    if (a->len != b->len) return a->len - b->len;
    for (int i = a->len - 1; i >= 0; i--)
        if (a->d[i] != b->d[i]) return (a->d[i] > b->d[i]) ? 1 : -1;
    return 0;
}

void bn_add(bn_t *r, const bn_t *a, const bn_t *b)
{
    uint64_t carry = 0;
    int max_len = (a->len > b->len) ? a->len : b->len;
    bn_t t; bn_zero(&t);
    for (int i = 0; i < max_len; i++)
    {
        carry += (i < a->len) ? a->d[i] : 0;
        carry += (i < b->len) ? b->d[i] : 0;
        t.d[i] = (uint32_t)carry;
        carry >>= 32;
    }
    if (carry) t.d[max_len++] = (uint32_t)carry;
    t.len = max_len;
    *r = t;
}

void bn_sub(bn_t *r, const bn_t *a, const bn_t *b)
{
    uint64_t borrow = 0;
    bn_t t; bn_zero(&t);
    int max_len = (a->len > b->len) ? a->len : b->len;
    for (int i = 0; i < max_len; i++)
    {
        uint64_t av = (i < a->len) ? a->d[i] : 0;
        uint64_t bv = (i < b->len) ? b->d[i] : 0;
        uint64_t diff = av - bv - borrow;
        if (diff > 0xFFFFFFFFULL) { diff += 0x100000000ULL; borrow = 1; }
        else borrow = 0;
        t.d[i] = (uint32_t)diff;
    }
    t.len = max_len;
    while (t.len > 0 && t.d[t.len - 1] == 0) t.len--;
    if (t.len == 0) t.len = 1;
    *r = t;
}

void bn_mul(bn_t *r, const bn_t *a, const bn_t *b)
{
    bn_t t; bn_zero(&t);
    for (int i = 0; i < a->len; i++)
    {
        uint64_t carry = 0;
        for (int j = 0; j < b->len || carry; j++)
        {
            uint64_t prod = t.d[i + j] + (uint64_t)a->d[i] * (j < b->len ? b->d[j] : 0) + carry;
            t.d[i + j] = (uint32_t)prod;
            carry = prod >> 32;
        }
    }
    t.len = a->len + b->len;
    while (t.len > 0 && t.d[t.len - 1] == 0) t.len--;
    if (t.len == 0) t.len = 1;
    *r = t;
}

static int bn_bitlen(const bn_t *a)
{
    if (a->len == 0 || (a->len == 1 && a->d[0] == 0)) return 0;
    uint32_t top = a->d[a->len - 1];
    int bits = 0;
    while (top) { top >>= 1; bits++; }
    return (a->len - 1) * 32 + bits;
}

static void bn_shl1(bn_t *r, const bn_t *a)
{
    uint32_t carry = 0;
    bn_t t; bn_zero(&t);
    int i;
    for (i = 0; i < a->len; i++)
    {
        uint32_t v = (a->d[i] << 1) | carry;
        t.d[i] = v;
        carry = a->d[i] >> 31;
    }
    if (carry) t.d[i++] = carry;
    t.len = i > 0 ? i : 1;
    *r = t;
}

static void bn_shr1(bn_t *r, const bn_t *a)
{
    uint32_t carry = 0;
    bn_t t = *a;
    for (int i = t.len - 1; i >= 0; i--)
    {
        uint32_t v = (carry << 31) | (t.d[i] >> 1);
        carry = t.d[i] & 1;
        t.d[i] = v;
    }
    while (t.len > 0 && t.d[t.len - 1] == 0) t.len--;
    if (t.len == 0) t.len = 1;
    *r = t;
}

void bn_div(bn_t *q, bn_t *rem, const bn_t *a, const bn_t *b)
{
    bn_zero(q);
    if (bn_is_zero(b)) return;
    if (bn_cmp(a, b) < 0) { *rem = *a; return; }

    bn_t r = *a;
    bn_t d = *b;
    int shift = bn_bitlen(&r) - bn_bitlen(&d);
    for (int s = 0; s < shift; s++)
        bn_shl1(&d, &d);

    bn_t qt; bn_zero(&qt);
    qt.len = 1;

    for (int i = shift; i >= 0; i--)
    {
        bn_shl1(&qt, &qt);
        if (bn_cmp(&r, &d) >= 0)
        {
            bn_sub(&r, &r, &d);
            qt.d[0] |= 1;
        }
        bn_shr1(&d, &d);
    }

    *q = qt;
    *rem = r;
}

void bn_mod(bn_t *r, const bn_t *a, const bn_t *m)
{
    bn_t q, rem;
    bn_div(&q, &rem, a, m);
    *r = rem;
}

#ifdef __SIZEOF_INT128__
typedef unsigned __int128 uint128_t;
#else
#error "__int128 not available — required for Montgomery multiplication"
#endif

/* 
 * Montgomery multiplication (CIOS method)
 * Computes r = a * b * R^(-1) mod n
 * R = 2^(32 * nl) where nl = number of limbs in n
 * n0_inv = -n[0]^(-1) mod 2^32
 */
static void mont_mul(bn_t *r, const bn_t *a, const bn_t *b,
                     const bn_t *n, uint32_t n0_inv)
{
    int nl = n->len;
    /* 1. 完整乘法 T = a * b (最多 2*nl 个 limb) */
    uint32_t T[BN_MAX_LIMBS * 2 + 2];
    memset(T, 0, sizeof(T[0]) * (nl * 2 + 2));

    for (int i = 0; i < a->len; i++) {
        uint64_t carry = 0;
        uint64_t ai = a->d[i];
        for (int j = 0; j < b->len; j++) {
            uint128_t p = (uint128_t)T[i + j] + (uint128_t)ai * b->d[j] + carry;
            T[i + j] = (uint32_t)p;
            carry = (uint64_t)(p >> 32);
        }
        if (carry) {
            uint128_t p = (uint128_t)T[i + b->len] + carry;
            T[i + b->len] = (uint32_t)p;
            carry = (uint64_t)(p >> 32);
            if (carry) T[i + b->len + 1] += (uint32_t)carry;
        }
    }

    /* 2. Montgomery 规约（逐词消去低位） */
    for (int i = 0; i < nl; i++) {
        uint32_t mi = (uint32_t)(T[0] * n0_inv);
        uint64_t carry = 0;
        for (int j = 0; j < nl; j++) {
            uint128_t p = (uint128_t)T[j] + (uint128_t)mi * n->d[j] + carry;
            T[j] = (uint32_t)p;
            carry = (uint64_t)(p >> 32);
        }
        /* carry 传播到 T[nl] 及以上 */
        int k = nl;
        while (carry) {
            uint128_t p = (uint128_t)T[k] + carry;
            T[k] = (uint32_t)p;
            carry = (uint64_t)(p >> 32);
            k++;
        }
        /* 右移 1 word (除以 2^32) */
        for (int j = 0; j < nl * 2; j++)
            T[j] = T[j + 1];
        T[nl * 2] = 0;
    }

    /* 3. 取出结果，含 T[nl] 作为第 nl 个 limb（可能 0 或 1） */
    bn_t res; bn_zero(&res);
    int top = nl + 1;
    while (top > 0 && T[top - 1] == 0) top--;
    for (int j = 0; j < top; j++)
        res.d[j] = T[j];
    res.len = top > 0 ? top : 1;

    while (bn_cmp(&res, n) >= 0)
        bn_sub(&res, &res, n);
    *r = res;
}

static uint32_t mont_n0_inv(uint32_t n0)
{
    uint32_t x = 1;
    x = x * (2 - n0 * x);
    x = x * (2 - n0 * x);
    x = x * (2 - n0 * x);
    x = x * (2 - n0 * x);
    x = x * (2 - n0 * x);
    return ~x + 1;
}

void bn_mod_exp(bn_t *r, const bn_t *a, const bn_t *e, const bn_t *m)
{
    int nl = m->len;
    if (nl > BN_MAX_LIMBS) { bn_from_int(r, 0); return; }

    uint32_t n0_inv = mont_n0_inv(m->d[0]);

    bn_t R_mod; bn_zero(&R_mod);
    R_mod.d[0] = 1; R_mod.len = 1;
    for (int i = 0; i < 32 * nl; i++)
    {
        bn_shl1(&R_mod, &R_mod);
        if (bn_cmp(&R_mod, m) >= 0)
            bn_sub(&R_mod, &R_mod, m);
    }

    bn_t R2_mod = R_mod;
    for (int i = 0; i < 32 * nl; i++)
    {
        bn_shl1(&R2_mod, &R2_mod);
        if (bn_cmp(&R2_mod, m) >= 0)
            bn_sub(&R2_mod, &R2_mod, m);
    }

    bn_t a_reduced;
    if (bn_cmp(a, m) >= 0)
        bn_mod(&a_reduced, a, m);
    else
        a_reduced = *a;

    bn_t a_mont, result_mont;
    mont_mul(&a_mont, &a_reduced, &R2_mod, m, n0_inv);
    result_mont = R_mod;

    bn_t exp = *e;
    while (!bn_is_zero(&exp))
    {
        if (exp.d[0] & 1)
            mont_mul(&result_mont, &result_mont, &a_mont, m, n0_inv);
        mont_mul(&a_mont, &a_mont, &a_mont, m, n0_inv);
        uint64_t carry = 0;
        for (int i = exp.len - 1; i >= 0; i--)
        {
            uint64_t val = ((uint64_t)carry << 32) | exp.d[i];
            exp.d[i] = (uint32_t)(val >> 1);
            carry = val & 1;
        }
        while (exp.len > 0 && exp.d[exp.len - 1] == 0) exp.len--;
        if (exp.len == 0) exp.len = 1;
    }

    bn_t one; bn_from_int(&one, 1);
    mont_mul(r, &result_mont, &one, m, n0_inv);
}

void bn_mod_inv(bn_t *r, const bn_t *a, const bn_t *m)
{
    bn_t t0, t1, r0, r1, q, rem, tmp;

    bn_from_int(&t0, 0);
    bn_from_int(&t1, 1);
    r0 = *m;
    r1 = *a;

    while (!(r1.len == 1 && r1.d[0] == 0))
    {
        bn_div(&q, &rem, &r0, &r1);
        bn_mul(&tmp, &q, &t1);
        bn_mod(&tmp, &tmp, m);
        if (bn_cmp(&t0, &tmp) >= 0)
            bn_sub(&tmp, &t0, &tmp);
        else
        {
            bn_sub(&tmp, m, &tmp);
            bn_add(&tmp, &tmp, &t0);
        }
        r0 = r1;
        r1 = rem;
        t0 = t1;
        t1 = tmp;
    }

    if (bn_cmp(&t0, m) >= 0)
        bn_mod(r, &t0, m);
    else
    {
        bn_t zero; bn_from_int(&zero, 0);
        if (bn_cmp(&t0, &zero) < 0)
            bn_add(r, &t0, m);
        else
            *r = t0;
    }
}

static int trial_div_test(const bn_t *a)
{
    static const uint32_t small[] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
        59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
        163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251 };
    for (size_t i = 0; i < sizeof(small)/sizeof(small[0]); i++)
    {
        if (a->len == 1 && a->d[0] == small[i]) continue;
        bn_t d = { { small[i] }, 1 };
        bn_t q, rem;
        bn_div(&q, &rem, a, &d);
        if (rem.len == 1 && rem.d[0] == 0) return 0;
    }
    return 1;
}

int bn_is_prime(const bn_t *a)
{
    if (a->len == 1 && (a->d[0] == 0 || a->d[0] == 1)) return 0;
    if ((a->d[0] & 1) == 0) return (a->len == 1 && a->d[0] == 2) ? 1 : 0;

    if (!trial_div_test(a)) return 0;

    bn_t d = *a;
    d.d[0] -= 1;
    // handle borrow in case d.d[0] was 0
    for (int bi = 0; bi < d.len - 1 && d.d[bi] == 0xFFFFFFFF; bi++) {
        d.d[bi] = 0;
        d.d[bi + 1]--;
    }
    while (d.len > 0 && d.d[d.len - 1] == 0) { d.len--; }
    if (d.len == 0) d.len = 1;
    int s = 0;
    while ((d.d[0] & 1) == 0) {
        uint64_t carry = 0;
        for (int i = d.len - 1; i >= 0; i--) {
            uint64_t val = ((uint64_t)carry << 32) | d.d[i];
            d.d[i] = (uint32_t)(val >> 1);
            carry = val & 1;
        }
        while (d.len > 0 && d.d[d.len - 1] == 0) d.len--;
        if (d.len == 0) d.len = 1;
        s++;
    }

    static const uint32_t witnesses[] = { 2, 3, 5 };
    for (int wi = 0; wi < 3; wi++)
    {
        uint32_t w = witnesses[wi];
        bn_t a_val; bn_from_int(&a_val, w);
        if (bn_cmp(&a_val, a) >= 0) continue;

        bn_t x;
        bn_mod_exp(&x, &a_val, &d, a);
        if (x.len == 1 && x.d[0] == 1) continue;
        bn_t nm1 = *a; nm1.d[0] -= 1;
        if (bn_cmp(&x, &nm1) == 0) continue;

        int cont = 0;
        for (int r = 1; r < s; r++)
        {
            bn_mul(&x, &x, &x);
            bn_mod(&x, &x, a);
            if (x.len == 1 && x.d[0] == 1) return 0;
            bn_t nm1 = *a; nm1.d[0] -= 1;
            if (bn_cmp(&x, &nm1) == 0) { cont = 1; break; }
        }
        if (cont) continue;
        return 0;
    }
    return 1;
}

int bn_random(bn_t *r, int bits)
{
    int bytes = (bits + 7) / 8;
    uint8_t buf[128];
    if ((size_t)bytes > sizeof(buf) || bits > BN_MAX_LIMBS * 32) return CRYPTO_ERR;
    if (rand_bytes(buf, bytes) != CRYPTO_OK) return CRYPTO_ERR;
    buf[0] &= (uint8_t)(0xFF >> (bytes * 8 - bits));
    buf[0] |= (uint8_t)(1 << ((bytes * 8 - bits) % 8));
    bn_from_bytes(r, buf, bytes);
    return CRYPTO_OK;
}

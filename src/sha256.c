#include "crypto.h"
#include "sha256.h"
#include <string.h>

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR32(x, n)  ((x) >> (n))

#define CH(x, y, z)    (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x) (ROTR32((x),  2) ^ ROTR32((x), 13) ^ ROTR32((x), 22))
#define SIG1(x) (ROTR32((x),  6) ^ ROTR32((x), 11) ^ ROTR32((x), 25))
#define sig0(x) (ROTR32((x),  7) ^ ROTR32((x), 18) ^ SHR32((x),  3))
#define sig1(x) (ROTR32((x), 17) ^ ROTR32((x), 19) ^ SHR32((x), 10))

static const uint32_t H[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static const uint32_t K[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

static uint32_t load32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void store32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void compress(uint32_t h[8], const uint8_t block[64])
{
    uint32_t W[64];
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    uint32_t t1, t2;

    for (int i = 0; i < 16; i++)
        W[i] = load32be(block + i * 4);

    for (int i = 16; i < 64; i++)
        W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];

    for (int i = 0; i < 64; i++)
    {
        t1 = hh + SIG1(e) + CH(e, f, g) + K[i] + W[i];
        t2 = SIG0(a) + MAJ(a, b, c);
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

int sha256(const uint8_t *msg, size_t msg_len, uint8_t digest[SHA256_DIGEST_SIZE])
{
    uint32_t h[8] = {H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]};
    uint64_t bits = (uint64_t)msg_len * 8;
    uint8_t block[64];
    size_t pos;

    for (pos = 0; pos + 64 <= msg_len; pos += 64)
        compress(h, msg + pos);

    size_t rem = msg_len - pos;
    memset(block, 0, 64);
    memcpy(block, msg + pos, rem);
    block[rem] = 0x80;

    if (rem >= 56)
    {
        compress(h, block);
        memset(block, 0, 64);
    }

    for (int i = 0; i < 8; i++)
        block[56 + i] = (uint8_t)(bits >> (56 - i * 8));

    compress(h, block);

    for (int i = 0; i < 8; i++)
        store32be(digest + i * 4, h[i]);

    return CRYPTO_OK;
}

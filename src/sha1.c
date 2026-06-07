#include "crypto.h"
#include "sha1.h"
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static const uint32_t H[5] = {
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
};

static const uint32_t K[4] = {
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
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

static void compress(uint32_t h[5], const uint8_t block[64])
{
    uint32_t W[80];
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    uint32_t temp;

    for (int i = 0; i < 16; i++)
        W[i] = load32be(block + i * 4);

    for (int i = 16; i < 80; i++)
        W[i] = ROTL32(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);

    for (int i = 0; i < 80; i++)
    {
        uint32_t f;
        uint32_t k;
        if (i < 20)      { f = (b & c) | (~b & d); k = K[0]; }
        else if (i < 40) { f = b ^ c ^ d;          k = K[1]; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = K[2]; }
        else             { f = b ^ c ^ d;          k = K[3]; }

        temp = ROTL32(a, 5) + f + e + k + W[i];
        e = d;
        d = c;
        c = ROTL32(b, 30);
        b = a;
        a = temp;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

int sha1(const uint8_t *msg, size_t msg_len, uint8_t digest[SHA1_DIGEST_SIZE])
{
    uint32_t h[5] = {H[0], H[1], H[2], H[3], H[4]};
    uint64_t bits = (uint64_t)msg_len * 8;
    uint8_t block[64];
    size_t pos;
    size_t i;

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

    for (i = 0; i < 8; i++)
        block[56 + i] = (uint8_t)(bits >> (56 - i * 8));

    compress(h, block);

    for (i = 0; i < 5; i++)
        store32be(digest + i * 4, h[i]);

    return CRYPTO_OK;
}

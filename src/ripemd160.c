#include "crypto.h"
#include "ripemd160.h"
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static const uint32_t IV[5] = {
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
};

static const uint32_t KL[5] = { 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
static const uint32_t KR[5] = { 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

static const uint8_t WL[80] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
     3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
     1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
     4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13,
};

static const uint8_t SL[80] = {
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6,
};

static const uint8_t WR[80] = {
     5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
     6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
     8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11,
};

static const uint8_t SR[80] = {
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11,
};

static uint32_t load32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

#define F1(x, y, z) ((x) ^ (y) ^ (z))
#define F2(x, y, z) ((((y) ^ (z)) & (x)) ^ (z))
#define F3(x, y, z) ((~((y)) | (x)) ^ (z))
#define F4(x, y, z) ((((x) ^ (y)) & (z)) ^ (y))
#define F5(x, y, z) ((~((z)) | (y)) ^ (x))

static void compress(uint32_t h[5], const uint8_t block[64])
{
    uint32_t X[16];
    uint32_t al, bl, cl, dl, el;
    uint32_t ar, br, cr, dr, er;

    for (int i = 0; i < 16; i++)
        X[i] = load32le(block + i * 4);

    al = ar = h[0]; bl = br = h[1];
    cl = cr = h[2]; dl = dr = h[3]; el = er = h[4];

    for (int i = 0; i < 80; i++)
    {
        int gi = i / 16;

        switch (gi)
        {
        case 0:
            al += F1(bl, cl, dl) + X[WL[i]] + KL[0];
            ar += F5(br, cr, dr) + X[WR[i]] + KR[0];
            break;
        case 1:
            al += F2(bl, cl, dl) + X[WL[i]] + KL[1];
            ar += F4(br, cr, dr) + X[WR[i]] + KR[1];
            break;
        case 2:
            al += F3(bl, cl, dl) + X[WL[i]] + KL[2];
            ar += F3(br, cr, dr) + X[WR[i]] + KR[2];
            break;
        case 3:
            al += F4(bl, cl, dl) + X[WL[i]] + KL[3];
            ar += F2(br, cr, dr) + X[WR[i]] + KR[3];
            break;
        case 4:
            al += F5(bl, cl, dl) + X[WL[i]] + KL[4];
            ar += F1(br, cr, dr) + X[WR[i]] + KR[4];
            break;
        }

        al = ROTL32(al, SL[i]) + el;
        ar = ROTL32(ar, SR[i]) + er;

        cl = ROTL32(cl, 10);
        cr = ROTL32(cr, 10);

        { uint32_t t = el; el = dl; dl = cl; cl = bl; bl = al; al = t; }
        { uint32_t t = er; er = dr; dr = cr; cr = br; br = ar; ar = t; }
    }

    uint32_t t = h[0] + bl + cr;
    h[0] = h[1] + cl + dr;
    h[1] = h[2] + dl + er;
    h[2] = h[3] + el + ar;
    h[3] = h[4] + al + br;
    h[4] = t;
}

int ripemd160(const uint8_t *msg, size_t msg_len, uint8_t digest[RIPEMD160_DIGEST_SIZE])
{
    uint32_t h[5] = {IV[0], IV[1], IV[2], IV[3], IV[4]};
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
        block[56 + i] = (uint8_t)(bits >> (i * 8));

    compress(h, block);

    for (int i = 0; i < 5; i++)
        store32le(digest + i * 4, h[i]);

    return CRYPTO_OK;
}

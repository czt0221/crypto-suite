#include "crypto.h"
#include "sha3.h"
#include <string.h>

#define SHA3_RATE 136
#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const unsigned char RHO[5][5] = {
    {  0,  1, 62, 28, 27 },
    { 36, 44,  6, 55, 20 },
    {  3, 10, 43, 25, 39 },
    { 41, 45, 15, 21,  8 },
    { 18,  2, 61, 56, 14 }
};

static uint64_t load64le(const uint8_t *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static void store64le(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}

static void keccak_f1600(uint64_t A[5][5])
{
    for (int r = 0; r < 24; r++)
    {
        uint64_t C[5], D[5];

        C[0] = A[0][0] ^ A[1][0] ^ A[2][0] ^ A[3][0] ^ A[4][0];
        C[1] = A[0][1] ^ A[1][1] ^ A[2][1] ^ A[3][1] ^ A[4][1];
        C[2] = A[0][2] ^ A[1][2] ^ A[2][2] ^ A[3][2] ^ A[4][2];
        C[3] = A[0][3] ^ A[1][3] ^ A[2][3] ^ A[3][3] ^ A[4][3];
        C[4] = A[0][4] ^ A[1][4] ^ A[2][4] ^ A[3][4] ^ A[4][4];

        D[0] = ROTL64(C[1], 1) ^ C[4];
        D[1] = ROTL64(C[2], 1) ^ C[0];
        D[2] = ROTL64(C[3], 1) ^ C[1];
        D[3] = ROTL64(C[4], 1) ^ C[2];
        D[4] = ROTL64(C[0], 1) ^ C[3];

        for (int y = 0; y < 5; y++)
            for (int x = 0; x < 5; x++)
                A[y][x] ^= D[x];

        for (int y = 0; y < 5; y++)
            for (int x = 0; x < 5; x++)
                A[y][x] = ROTL64(A[y][x], RHO[y][x]);

        {
            uint64_t T[5][5];
            memcpy(T, A, sizeof(T));
            for (int y = 0; y < 5; y++)
                for (int x = 0; x < 5; x++)
                    A[y][x] = T[x][(3 * y + x) % 5];
        }

        for (int y = 0; y < 5; y++)
        {
            uint64_t t[5];
            t[0] = A[y][0] ^ (~A[y][1] & A[y][2]);
            t[1] = A[y][1] ^ (~A[y][2] & A[y][3]);
            t[2] = A[y][2] ^ (~A[y][3] & A[y][4]);
            t[3] = A[y][3] ^ (~A[y][4] & A[y][0]);
            t[4] = A[y][4] ^ (~A[y][0] & A[y][1]);
            A[y][0] = t[0]; A[y][1] = t[1]; A[y][2] = t[2]; A[y][3] = t[3]; A[y][4] = t[4];
        }

        A[0][0] ^= RC[r];
    }
}

int sha3(const uint8_t *msg, size_t msg_len, uint8_t digest[SHA3_DIGEST_SIZE])
{
    uint64_t A[5][5] = {0};
    uint8_t buf[SHA3_RATE];
    size_t pos;

    for (pos = 0; pos + SHA3_RATE <= msg_len; pos += SHA3_RATE)
    {
        for (int i = 0; i < SHA3_RATE / 8; i++)
        {
            uint64_t *p = (uint64_t *)A;
            p[i] ^= load64le(msg + pos + i * 8);
        }
        keccak_f1600(A);
    }

    size_t rem = msg_len - pos;
    memset(buf, 0, SHA3_RATE);
    memcpy(buf, msg + pos, rem);
    buf[rem] = 0x06;
    buf[SHA3_RATE - 1] |= 0x80;

    for (int i = 0; i < SHA3_RATE / 8; i++)
    {
        uint64_t *p = (uint64_t *)A;
        p[i] ^= load64le(buf + i * 8);
    }
    keccak_f1600(A);

    for (int i = 0; i < SHA3_DIGEST_SIZE / 8; i++)
        store64le(digest + i * 8, ((uint64_t *)A)[i]);

    return CRYPTO_OK;
}

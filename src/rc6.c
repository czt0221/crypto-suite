#include "crypto.h"
#include "rc6.h"
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROUNDS 20

static const uint32_t P32 = 0xB7E15163;
static const uint32_t Q32 = 0x9E3779B9;

static uint32_t load32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void key_setup(const uint8_t key[16], uint32_t S[2 * ROUNDS + 4])
{
    uint32_t L[4];
    for (int i = 0; i < 4; i++) L[i] = load32le(key + i * 4);

    S[0] = P32;
    for (int i = 1; i < 2 * ROUNDS + 4; i++)
        S[i] = S[i - 1] + Q32;

    uint32_t A = 0, B = 0;
    int v = 3 * ((2 * ROUNDS + 4) > 4 ? (2 * ROUNDS + 4) : 4);
    int i = 0, j = 0;
    for (int k = 0; k < v; k++)
    {
        A = S[i] = ROTL32(S[i] + A + B, 3);
        B = L[j] = ROTL32(L[j] + A + B, ((int)(A + B)) & 31);
        i = (i + 1) % (2 * ROUNDS + 4);
        j = (j + 1) % 4;
    }
}

static void rc6_encrypt_block(const uint32_t S[2 * ROUNDS + 4], const uint8_t in[16], uint8_t out[16])
{
    uint32_t A = load32le(in);
    uint32_t B = load32le(in + 4);
    uint32_t C = load32le(in + 8);
    uint32_t D = load32le(in + 12);

    B += S[0];
    D += S[1];

    for (int r = 1; r <= ROUNDS; r++)
    {
        uint32_t t = ROTL32(B * (2 * B + 1), 5);
        uint32_t u = ROTL32(D * (2 * D + 1), 5);
        A = ROTL32(A ^ t, (int)(u & 31)) + S[2 * r];
        C = ROTL32(C ^ u, (int)(t & 31)) + S[2 * r + 1];

        uint32_t tmp = A; A = B; B = C; C = D; D = tmp;
    }

    A += S[2 * ROUNDS + 2];
    C += S[2 * ROUNDS + 3];

    store32le(out, A);
    store32le(out + 4, B);
    store32le(out + 8, C);
    store32le(out + 12, D);
}

static void rc6_decrypt_block(const uint32_t S[2 * ROUNDS + 4], const uint8_t in[16], uint8_t out[16])
{
    uint32_t A = load32le(in);
    uint32_t B = load32le(in + 4);
    uint32_t C = load32le(in + 8);
    uint32_t D = load32le(in + 12);

    C -= S[2 * ROUNDS + 3];
    A -= S[2 * ROUNDS + 2];

    for (int r = ROUNDS; r >= 1; r--)
    {
        uint32_t tmp = D; D = C; C = B; B = A; A = tmp;

        uint32_t t = ROTL32(B * (2 * B + 1), 5);
        uint32_t u = ROTL32(D * (2 * D + 1), 5);
        C = ROTR32(C - S[2 * r + 1], (int)(t & 31)) ^ u;
        A = ROTR32(A - S[2 * r], (int)(u & 31)) ^ t;
    }

    D -= S[1];
    B -= S[0];

    store32le(out, A);
    store32le(out + 4, B);
    store32le(out + 8, C);
    store32le(out + 12, D);
}

static int rc6_crypt(const uint8_t key[RC6_KEY_SIZE], const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len, int encrypt, int mode, const uint8_t iv[RC6_BLOCK_SIZE])
{
    uint32_t S[44];

    if (in_len % 16 != 0) return CRYPTO_ERR;
    if (*out_len < in_len) return CRYPTO_ERR;

    key_setup(key, S);

    if (mode == 0)
    {
        for (size_t i = 0; i < in_len; i += 16)
        {
            if (encrypt) rc6_encrypt_block(S, in + i, out + i);
            else         rc6_decrypt_block(S, in + i, out + i);
        }
    }
    else
    {
        uint8_t fb[16];
        uint8_t blk[16];

        if (encrypt)
        {
            memcpy(fb, iv, 16);
            for (size_t i = 0; i < in_len; i += 16)
            {
                for (int j = 0; j < 16; j++) blk[j] = in[i + j] ^ fb[j];
                rc6_encrypt_block(S, blk, out + i);
                memcpy(fb, out + i, 16);
            }
        }
        else
        {
            memcpy(fb, iv, 16);
            for (size_t i = 0; i < in_len; i += 16)
            {
                rc6_decrypt_block(S, in + i, blk);
                for (int j = 0; j < 16; j++) out[i + j] = blk[j] ^ fb[j];
                memcpy(fb, in + i, 16);
            }
        }
    }

    *out_len = in_len;
    return CRYPTO_OK;
}

int rc6_ecb_encrypt(const uint8_t key[RC6_KEY_SIZE], const uint8_t *plain, size_t plain_len, uint8_t *cipher, size_t *cipher_len)
{ return rc6_crypt(key, plain, plain_len, cipher, cipher_len, 1, 0, NULL); }

int rc6_ecb_decrypt(const uint8_t key[RC6_KEY_SIZE], const uint8_t *cipher, size_t cipher_len, uint8_t *plain, size_t *plain_len)
{ return rc6_crypt(key, cipher, cipher_len, plain, plain_len, 0, 0, NULL); }

int rc6_cbc_encrypt(const uint8_t key[RC6_KEY_SIZE], const uint8_t iv[RC6_BLOCK_SIZE], const uint8_t *plain, size_t plain_len, uint8_t *cipher, size_t *cipher_len)
{ return rc6_crypt(key, plain, plain_len, cipher, cipher_len, 1, 1, iv); }

int rc6_cbc_decrypt(const uint8_t key[RC6_KEY_SIZE], const uint8_t iv[RC6_BLOCK_SIZE], const uint8_t *cipher, size_t cipher_len, uint8_t *plain, size_t *plain_len)
{ return rc6_crypt(key, cipher, cipher_len, plain, plain_len, 0, 1, iv); }

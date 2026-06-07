#include "crypto.h"
#include "sm4.h"
#include <string.h>

static const uint8_t S[256] = {
    0xD6,0x90,0xE9,0xFE,0xCC,0xE1,0x3D,0xB7,0x16,0xB6,0x14,0xC2,0x28,0xFB,0x2C,0x05,
    0x2B,0x67,0x9A,0x76,0x2A,0xBE,0x04,0xC3,0xAA,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9C,0x42,0x50,0xF4,0x91,0xEF,0x98,0x7A,0x33,0x54,0x0B,0x43,0xED,0xCF,0xAC,0x62,
    0xE4,0xB3,0x1C,0xA9,0xC9,0x08,0xE8,0x95,0x80,0xDF,0x94,0xFA,0x75,0x8F,0x3F,0xA6,
    0x47,0x07,0xA7,0xFC,0xF3,0x73,0x17,0xBA,0x83,0x59,0x3C,0x19,0xE6,0x85,0x4F,0xA8,
    0x68,0x6B,0x81,0xB2,0x71,0x64,0xDA,0x8B,0xF8,0xEB,0x0F,0x4B,0x70,0x56,0x9D,0x35,
    0x1E,0x24,0x0E,0x5E,0x63,0x58,0xD1,0xA2,0x25,0x22,0x7C,0x3B,0x01,0x21,0x78,0x87,
    0xD4,0x00,0x46,0x57,0x9F,0xD3,0x27,0x52,0x4C,0x36,0x02,0xE7,0xA0,0xC4,0xC8,0x9E,
    0xEA,0xBF,0x8A,0xD2,0x40,0xC7,0x38,0xB5,0xA3,0xF7,0xF2,0xCE,0xF9,0x61,0x15,0xA1,
    0xE0,0xAE,0x5D,0xA4,0x9B,0x34,0x1A,0x55,0xAD,0x93,0x32,0x30,0xF5,0x8C,0xB1,0xE3,
    0x1D,0xF6,0xE2,0x2E,0x82,0x66,0xCA,0x60,0xC0,0x29,0x23,0xAB,0x0D,0x53,0x4E,0x6F,
    0xD5,0xDB,0x37,0x45,0xDE,0xFD,0x8E,0x2F,0x03,0xFF,0x6A,0x72,0x6D,0x6C,0x5B,0x51,
    0x8D,0x1B,0xAF,0x92,0xBB,0xDD,0xBC,0x7F,0x11,0xD9,0x5C,0x41,0x1F,0x10,0x5A,0xD8,
    0x0A,0xC1,0x31,0x88,0xA5,0xCD,0x7B,0xBD,0x2D,0x74,0xD0,0x12,0xB8,0xE5,0xB4,0xB0,
    0x89,0x69,0x97,0x4A,0x0C,0x96,0x77,0x7E,0x65,0xB9,0xF1,0x09,0xC5,0x6E,0xC6,0x84,
    0x18,0xF0,0x7D,0xEC,0x3A,0xDC,0x4D,0x20,0x79,0xEE,0x5F,0x3E,0xD7,0xCB,0x39,0x48,
};

static const uint32_t FK[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };

static const uint32_t CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
};

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static uint32_t tau(uint32_t x)
{
    return ((uint32_t)S[(x >> 24) & 0xFF] << 24) |
           ((uint32_t)S[(x >> 16) & 0xFF] << 16) |
           ((uint32_t)S[(x >> 8) & 0xFF] << 8) |
           (uint32_t)S[x & 0xFF];
}

static uint32_t T(uint32_t x)
{
    x = tau(x);
    return x ^ ROTL32(x, 2) ^ ROTL32(x, 10) ^ ROTL32(x, 18) ^ ROTL32(x, 24);
}

static uint32_t T_key(uint32_t x)
{
    x = tau(x);
    return x ^ ROTL32(x, 13) ^ ROTL32(x, 23);
}

static uint32_t load32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void store32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static void sm4_encrypt_block(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16])
{
    uint32_t b[4];
    b[0] = load32be(in);
    b[1] = load32be(in + 4);
    b[2] = load32be(in + 8);
    b[3] = load32be(in + 12);

    for (int i = 0; i < 32; i++)
    {
        uint32_t t = b[1] ^ b[2] ^ b[3] ^ rk[i];
        t = T(t);
        uint32_t tmp = b[0] ^ t;
        b[0] = b[1]; b[1] = b[2]; b[2] = b[3]; b[3] = tmp;
    }

    store32be(out, b[3]);
    store32be(out + 4, b[2]);
    store32be(out + 8, b[1]);
    store32be(out + 12, b[0]);
}

static void sm4_decrypt_block(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16])
{
    uint32_t b[4];
    b[0] = load32be(in);
    b[1] = load32be(in + 4);
    b[2] = load32be(in + 8);
    b[3] = load32be(in + 12);

    for (int i = 0; i < 32; i++)
    {
        uint32_t t = b[1] ^ b[2] ^ b[3] ^ rk[31 - i];
        t = T(t);
        uint32_t tmp = b[0] ^ t;
        b[0] = b[1]; b[1] = b[2]; b[2] = b[3]; b[3] = tmp;
    }

    store32be(out, b[3]);
    store32be(out + 4, b[2]);
    store32be(out + 8, b[1]);
    store32be(out + 12, b[0]);
}

static int sm4_crypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len, int encrypt, int mode, const uint8_t iv[SM4_BLOCK_SIZE])
{
    uint32_t rk[32];
    uint32_t K[4];

    if (in_len % 16 != 0) return CRYPTO_ERR;
    if (*out_len < in_len) return CRYPTO_ERR;

    K[0] = load32be(key) ^ FK[0];
    K[1] = load32be(key + 4) ^ FK[1];
    K[2] = load32be(key + 8) ^ FK[2];
    K[3] = load32be(key + 12) ^ FK[3];

    for (int i = 0; i < 32; i++)
    {
        uint32_t t = K[1] ^ K[2] ^ K[3] ^ CK[i];
        t = T_key(t);
        rk[i] = K[0] ^ t;
        K[0] = K[1]; K[1] = K[2]; K[2] = K[3]; K[3] = rk[i];
    }

    if (mode == 0)
    {
        for (size_t i = 0; i < in_len; i += 16)
        {
            if (encrypt) sm4_encrypt_block(rk, in + i, out + i);
            else         sm4_decrypt_block(rk, in + i, out + i);
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
                sm4_encrypt_block(rk, blk, out + i);
                memcpy(fb, out + i, 16);
            }
        }
        else
        {
            memcpy(fb, iv, 16);
            for (size_t i = 0; i < in_len; i += 16)
            {
                sm4_decrypt_block(rk, in + i, blk);
                for (int j = 0; j < 16; j++) out[i + j] = blk[j] ^ fb[j];
                memcpy(fb, in + i, 16);
            }
        }
    }

    *out_len = in_len;
    return CRYPTO_OK;
}

int sm4_ecb_encrypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t *plain, size_t plain_len, uint8_t *cipher, size_t *cipher_len)
{ return sm4_crypt(key, plain, plain_len, cipher, cipher_len, 1, 0, NULL); }

int sm4_ecb_decrypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t *cipher, size_t cipher_len, uint8_t *plain, size_t *plain_len)
{ return sm4_crypt(key, cipher, cipher_len, plain, plain_len, 0, 0, NULL); }

int sm4_cbc_encrypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[SM4_BLOCK_SIZE], const uint8_t *plain, size_t plain_len, uint8_t *cipher, size_t *cipher_len)
{ return sm4_crypt(key, plain, plain_len, cipher, cipher_len, 1, 1, iv); }

int sm4_cbc_decrypt(const uint8_t key[SM4_KEY_SIZE], const uint8_t iv[SM4_BLOCK_SIZE], const uint8_t *cipher, size_t cipher_len, uint8_t *plain, size_t *plain_len)
{ return sm4_crypt(key, cipher, cipher_len, plain, plain_len, 0, 1, iv); }

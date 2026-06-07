#include "crypto.h"
#include "pbkdf2.h"
#include "hmacsha1.h"
#include "hmacsha256.h"
#include <string.h>

typedef int (*hmac_func)(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*);

static int pbkdf2_generic(const uint8_t *pass, size_t pass_len,
                          const uint8_t *salt, size_t salt_len,
                          unsigned int iter, hmac_func hmac, size_t hlen,
                          uint8_t *key, size_t key_len)
{
    uint8_t *out = key;
    size_t out_len = key_len;

    for (uint32_t block = 1; out_len > 0; block++)
    {
        uint8_t salt_block[128];
        size_t salt_block_len = salt_len + 4;
        memcpy(salt_block, salt, salt_len);
        salt_block[salt_len + 0] = (uint8_t)(block >> 24);
        salt_block[salt_len + 1] = (uint8_t)(block >> 16);
        salt_block[salt_len + 2] = (uint8_t)(block >> 8);
        salt_block[salt_len + 3] = (uint8_t)block;

        uint8_t U[32], T[32];
        hmac(pass, pass_len, salt_block, salt_block_len, U);
        memcpy(T, U, hlen);

        for (unsigned int i = 1; i < iter; i++)
        {
            uint8_t temp[32];
            hmac(pass, pass_len, U, hlen, temp);
            memcpy(U, temp, hlen);
            for (size_t j = 0; j < hlen; j++)
                T[j] ^= U[j];
        }

        size_t copy = (out_len < hlen) ? out_len : hlen;
        memcpy(out, T, copy);
        out += copy;
        out_len -= copy;
    }

    return CRYPTO_OK;
}

int pbkdf2(const uint8_t *pass, size_t pass_len,
           const uint8_t *salt, size_t salt_len,
           unsigned int iter, uint8_t *key, size_t key_len)
{
    return pbkdf2_generic(pass, pass_len, salt, salt_len, iter,
                          (hmac_func)hmac_sha1, 20, key, key_len);
}

int pbkdf2_sha256(const uint8_t *pass, size_t pass_len,
                  const uint8_t *salt, size_t salt_len,
                  unsigned int iter, uint8_t *key, size_t key_len)
{
    return pbkdf2_generic(pass, pass_len, salt, salt_len, iter,
                          (hmac_func)hmac_sha256, 32, key, key_len);
}

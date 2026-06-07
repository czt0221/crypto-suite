#include "crypto.h"
#include "hmacsha1.h"
#include "sha1.h"
#include <string.h>

int hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t mac[HMACSHA1_MAC_SIZE])
{
    uint8_t k[64];
    uint8_t digest[SHA1_DIGEST_SIZE];
    uint8_t ipad[64], opad[64];
    size_t i;

    memset(k, 0, 64);
    if (key_len > 64)
    {
        sha1(key, key_len, digest);
        memcpy(k, digest, SHA1_DIGEST_SIZE);
    }
    else
        memcpy(k, key, key_len);

    for (i = 0; i < 64; i++)
    {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    uint8_t combined[512];
    memcpy(combined, ipad, 64);
    memcpy(combined + 64, msg, msg_len);
    sha1(combined, 64 + msg_len, digest);

    memcpy(combined, opad, 64);
    memcpy(combined + 64, digest, SHA1_DIGEST_SIZE);
    sha1(combined, 64 + SHA1_DIGEST_SIZE, mac);

    return CRYPTO_OK;
}

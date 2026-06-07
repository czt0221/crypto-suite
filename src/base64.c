#include "crypto.h"
#include "base64.h"

static const char b64_tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_encode(const uint8_t *data, size_t data_len, char *out, size_t *out_len)
{
    size_t req = ((data_len + 2) / 3) * 4;

    if (out == NULL)
    {
        *out_len = req + 1;
        return CRYPTO_OK;
    }
    if (*out_len < req + 1)
        return CRYPTO_ERR;

    size_t o = 0;
    for (size_t i = 0; i + 3 <= data_len; i += 3)
    {
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i+1] << 8) | data[i+2];
        out[o++] = b64_tab[(v >> 18) & 0x3F];
        out[o++] = b64_tab[(v >> 12) & 0x3F];
        out[o++] = b64_tab[(v >> 6) & 0x3F];
        out[o++] = b64_tab[v & 0x3F];
    }

    size_t rem = data_len - (data_len / 3) * 3;
    if (rem == 1)
    {
        uint32_t v = (uint32_t)data[data_len - 1] << 16;
        out[o++] = b64_tab[(v >> 18) & 0x3F];
        out[o++] = b64_tab[(v >> 12) & 0x3F];
        out[o++] = '=';
        out[o++] = '=';
    }
    else if (rem == 2)
    {
        uint32_t v = ((uint32_t)data[data_len - 2] << 16) | ((uint32_t)data[data_len - 1] << 8);
        out[o++] = b64_tab[(v >> 18) & 0x3F];
        out[o++] = b64_tab[(v >> 12) & 0x3F];
        out[o++] = b64_tab[(v >> 6) & 0x3F];
        out[o++] = '=';
    }

    out[o] = '\0';
    *out_len = o;
    return CRYPTO_OK;
}

static int b64_idx(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int base64_decode(const char *in, size_t in_len, uint8_t *data, size_t *data_len)
{
    if (in_len % 4 != 0)
        return CRYPTO_ERR;

    size_t pad = 0;
    if (in_len > 0 && in[in_len - 1] == '=') pad++;
    if (in_len > 1 && in[in_len - 2] == '=') pad++;

    size_t req = (in_len / 4) * 3 - pad;
    if (data == NULL)
    {
        *data_len = req;
        return CRYPTO_OK;
    }
    if (*data_len < req)
        return CRYPTO_ERR;

    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 4)
    {
        int v0 = b64_idx(in[i]);
        int v1 = b64_idx(in[i+1]);
        int v2 = (in[i+2] == '=') ? 0 : b64_idx(in[i+2]);
        int v3 = (in[i+3] == '=') ? 0 : b64_idx(in[i+3]);

        if (v0 < 0 || v1 < 0) return CRYPTO_ERR;
        if (in[i+2] != '=' && v2 < 0) return CRYPTO_ERR;
        if (in[i+3] != '=' && v3 < 0) return CRYPTO_ERR;

        uint32_t v = ((uint32_t)v0 << 18) | ((uint32_t)v1 << 12) | ((uint32_t)v2 << 6) | (uint32_t)v3;
        data[o++] = (uint8_t)(v >> 16);
        if (in[i+2] != '=') data[o++] = (uint8_t)(v >> 8);
        if (in[i+3] != '=') data[o++] = (uint8_t)v;
    }

    *data_len = req;
    return CRYPTO_OK;
}

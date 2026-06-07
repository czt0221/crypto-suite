#include "crypto.h"
#include "utf8.h"

int utf8_encode(const uint32_t *codepoints, size_t len, uint8_t *out, size_t *out_len)
{
    size_t req = 0;
    for (size_t i = 0; i < len; i++)
    {
        uint32_t cp = codepoints[i];
        if (cp <= 0x7F)       req += 1;
        else if (cp <= 0x7FF) req += 2;
        else if (cp <= 0xFFFF) req += 3;
        else if (cp <= 0x10FFFF) req += 4;
        else return CRYPTO_ERR;
    }

    if (out == NULL)
    {
        *out_len = req;
        return CRYPTO_OK;
    }
    if (*out_len < req)
        return CRYPTO_ERR;

    size_t o = 0;
    for (size_t i = 0; i < len; i++)
    {
        uint32_t cp = codepoints[i];
        if (cp <= 0x7F)
        {
            out[o++] = (uint8_t)cp;
        }
        else if (cp <= 0x7FF)
        {
            out[o++] = (uint8_t)(0xC0 | (cp >> 6));
            out[o++] = (uint8_t)(0x80 | (cp & 0x3F));
        }
        else if (cp <= 0xFFFF)
        {
            out[o++] = (uint8_t)(0xE0 | (cp >> 12));
            out[o++] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
            out[o++] = (uint8_t)(0x80 | (cp & 0x3F));
        }
        else
        {
            out[o++] = (uint8_t)(0xF0 | (cp >> 18));
            out[o++] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
            out[o++] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
            out[o++] = (uint8_t)(0x80 | (cp & 0x3F));
        }
    }

    *out_len = req;
    return CRYPTO_OK;
}

int utf8_decode(const uint8_t *in, size_t in_len, uint32_t *codepoints, size_t *len)
{
    size_t count = 0;
    size_t i = 0;

    if (codepoints == NULL)
    {
        while (i < in_len)
        {
            uint8_t b = in[i];
            if (b <= 0x7F)       i += 1;
            else if (b <= 0xDF)  i += 2;
            else if (b <= 0xEF)  i += 3;
            else if (b <= 0xF7)  i += 4;
            else return CRYPTO_ERR;
            count++;
        }
        if (i > in_len) return CRYPTO_ERR;
        *len = count;
        return CRYPTO_OK;
    }

    if (*len < count && count > 0)
        return CRYPTO_ERR;

    i = 0;
    while (i < in_len)
    {
        uint8_t b = in[i];
        uint32_t cp;
        size_t seq;

        if (b <= 0x7F)
        {
            cp = b;
            seq = 1;
        }
        else if (b <= 0xDF)
        {
            if (i + 1 >= in_len || (in[i+1] & 0xC0) != 0x80) return CRYPTO_ERR;
            cp = ((uint32_t)(b & 0x1F) << 6) | (in[i+1] & 0x3F);
            seq = 2;
        }
        else if (b <= 0xEF)
        {
            if (i + 2 >= in_len || (in[i+1] & 0xC0) != 0x80 || (in[i+2] & 0xC0) != 0x80) return CRYPTO_ERR;
            cp = ((uint32_t)(b & 0x0F) << 12) | ((uint32_t)(in[i+1] & 0x3F) << 6) | (in[i+2] & 0x3F);
            seq = 3;
        }
        else if (b <= 0xF7)
        {
            if (i + 3 >= in_len || (in[i+1] & 0xC0) != 0x80 || (in[i+2] & 0xC0) != 0x80 || (in[i+3] & 0xC0) != 0x80) return CRYPTO_ERR;
            cp = ((uint32_t)(b & 0x07) << 18) | ((uint32_t)(in[i+1] & 0x3F) << 12) | ((uint32_t)(in[i+2] & 0x3F) << 6) | (in[i+3] & 0x3F);
            seq = 4;
        }
        else
            return CRYPTO_ERR;

        codepoints[count++] = cp;
        i += seq;
    }

    *len = count;
    return CRYPTO_OK;
}

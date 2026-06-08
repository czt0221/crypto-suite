#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, size_t hex_len, uint8_t *out, size_t *out_len)
{
    if (hex_len % 2 != 0) return CRYPTO_ERR;
    size_t len = hex_len / 2;
    for (size_t i = 0; i < len; i++) {
        int hv = hex_val(hex[i * 2]), lv = hex_val(hex[i * 2 + 1]);
        if (hv < 0 || lv < 0) return CRYPTO_ERR;
        out[i] = (uint8_t)((hv << 4) | lv);
    }
    *out_len = len;
    return CRYPTO_OK;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf(
            "Usage: crypto <command> [args...]\n"
            "Commands:\n"
            "  hash sha1|sha256|sha3-256|ripemd160 <hex>\n"
            "  hmac sha1|sha256 <key-hex> <msg-hex>\n"
            "  pbkdf2 <pass-hex> <salt-hex> <iter> <dklen> [sha1|sha256]\n"
            "  base64 enc|dec <hex>\n"
            "  utf8 enc|dec <hex>\n"
            "  aes-ecb enc|dec <key-hex> <data-hex>\n"
            "  aes-cbc enc|dec <key-hex> <iv-hex> <data-hex>\n"
            "  sm4-ecb enc|dec <key-hex> <data-hex>\n"
            "  sm4-cbc enc|dec <key-hex> <iv-hex> <data-hex>\n"
            "  rc6-ecb enc|dec <key-hex> <data-hex>\n"
            "  rc6-cbc enc|dec <key-hex> <iv-hex> <data-hex>\n"
            "  rsa gen\n"
            "  rsa enc <pub-hex> <plain-hex>\n"
            "  rsa dec <pri-hex> <cipher-hex>\n"
            "  ecc gen\n"
            "  ecc pub-to-pem <pub-hex>\n"
            "  rsasha1 sign <pri-hex> <msg-hex>\n"
            "  rsasha1 verify <pub-hex> <msg-hex> <sig-hex>\n"
            "  ecdsa sign <pri-hex> <msg-hex>\n"
            "  ecdsa verify <pub-hex> <msg-hex> <sig-hex>\n");
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "hash") == 0 && argc >= 4)
    {
        const char *algo = argv[2];
        uint8_t msg[4096]; size_t msg_len;
        if (hex_to_bytes(argv[3], strlen(argv[3]), msg, &msg_len) != CRYPTO_OK)
            { fprintf(stderr, "Bad hex\n"); return 1; }
        if (strcmp(algo, "sha1") == 0)
        {
            uint8_t d[20]; sha1(msg, msg_len, d);
            print_hex(d, 20); printf("\n");
        }
        else if (strcmp(algo, "sha256") == 0)
        {
            uint8_t d[32]; sha256(msg, msg_len, d);
            print_hex(d, 32); printf("\n");
        }
        else if (strcmp(algo, "sha3-256") == 0)
        {
            uint8_t d[32]; sha3(msg, msg_len, d);
            print_hex(d, 32); printf("\n");
        }
        else if (strcmp(algo, "ripemd160") == 0)
        {
            uint8_t d[20]; ripemd160(msg, msg_len, d);
            print_hex(d, 20); printf("\n");
        }
        else { fprintf(stderr, "Unknown hash\n"); return 1; }
    }
    else if (strcmp(cmd, "hmac") == 0 && argc >= 5)
    {
        const char *algo = argv[2];
        uint8_t key[256]; size_t key_len;
        uint8_t msg[4096]; size_t msg_len;
        if (hex_to_bytes(argv[3], strlen(argv[3]), key, &key_len) != CRYPTO_OK ||
            hex_to_bytes(argv[4], strlen(argv[4]), msg, &msg_len) != CRYPTO_OK)
            { fprintf(stderr, "Bad hex\n"); return 1; }
        if (strcmp(algo, "sha1") == 0)
        {
            uint8_t mac[20]; hmac_sha1(key, key_len, msg, msg_len, mac);
            print_hex(mac, 20); printf("\n");
        }
        else if (strcmp(algo, "sha256") == 0)
        {
            uint8_t mac[32]; hmac_sha256(key, key_len, msg, msg_len, mac);
            print_hex(mac, 32); printf("\n");
        }
        else { fprintf(stderr, "Unknown hmac\n"); return 1; }
    }
    else if (strcmp(cmd, "pbkdf2") == 0 && argc >= 6)
    {
        uint8_t pass[256]; size_t pass_len;
        uint8_t salt[256]; size_t salt_len;
        if (hex_to_bytes(argv[2], strlen(argv[2]), pass, &pass_len) != CRYPTO_OK ||
            hex_to_bytes(argv[3], strlen(argv[3]), salt, &salt_len) != CRYPTO_OK)
            { fprintf(stderr, "Bad hex\n"); return 1; }
        unsigned int iter = (unsigned int)atoi(argv[4]);
        size_t dklen = (size_t)atoi(argv[5]);
        uint8_t key[256]; memset(key, 0, sizeof(key));
        int use_sha256 = (argc >= 7 && strcmp(argv[6], "sha256") == 0);
        int r = use_sha256
            ? pbkdf2_sha256(pass, pass_len, salt, salt_len, iter, key, dklen)
            : pbkdf2(pass, pass_len, salt, salt_len, iter, key, dklen);
        if (r != CRYPTO_OK)
            { fprintf(stderr, "PBKDF2 failed\n"); return 1; }
        print_hex(key, dklen); printf("\n");
    }
    else     if (strcmp(cmd, "base64") == 0 && argc >= 4)
    {
        const char *op = argv[2];
        if (strcmp(op, "enc") == 0)
        {
            uint8_t data[4096]; size_t data_len;
            if (hex_to_bytes(argv[3], strlen(argv[3]), data, &data_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad hex\n"); return 1; }
            char out[8192]; size_t out_len = sizeof(out);
            if (base64_encode(data, data_len, out, &out_len) != CRYPTO_OK)
                { fprintf(stderr, "Base64 encode failed\n"); return 1; }
            printf("%.*s\n", (int)out_len, out);
        }
        else if (strcmp(op, "dec") == 0)
        {
            uint8_t data[8192]; size_t data_len = sizeof(data);
            if (base64_decode(argv[3], strlen(argv[3]), data, &data_len) != CRYPTO_OK)
                { fprintf(stderr, "Base64 decode failed\n"); return 1; }
            print_hex(data, data_len); printf("\n");
        }
        else { fprintf(stderr, "base64: enc or dec\n"); return 1; }
    }
    else if (strcmp(cmd, "utf8") == 0 && argc >= 4)
    {
        const char *op = argv[2];
        if (strcmp(op, "enc") == 0)
        {
            uint32_t cp[1024]; size_t cp_len = sizeof(cp)/sizeof(cp[0]);
            size_t hex_len = strlen(argv[3]);
            size_t byte_len = hex_len / 2;
            uint8_t *tmp = (uint8_t*)malloc(byte_len);
            size_t tmp_len;
            if (hex_to_bytes(argv[3], hex_len, tmp, &tmp_len) != CRYPTO_OK ||
                utf8_decode(tmp, tmp_len, cp, &cp_len) != CRYPTO_OK)
                { free(tmp); fprintf(stderr, "Bad input\n"); return 1; }
            free(tmp);
            for (size_t i = 0; i < cp_len; i++) printf("U+%04X ", cp[i]);
            printf("\n");
        }
        else if (strcmp(op, "dec") == 0)
        {
            uint32_t cp[1024]; size_t cp_len = 0;
            char *p = argv[3]; while (*p) {
                while (*p == ' ') p++;
                if (!*p) break;
                if (p[0] == 'U' && p[1] == '+') {
                    cp[cp_len++] = (uint32_t)strtoul(p+2, &p, 16);
                } else { fprintf(stderr, "Bad utf8 format\n"); return 1; }
            }
            uint8_t out[4096]; size_t out_len = sizeof(out);
            if (utf8_encode(cp, cp_len, out, &out_len) != CRYPTO_OK)
                { fprintf(stderr, "UTF-8 encode failed\n"); return 1; }
            print_hex(out, out_len); printf("\n");
        }
        else { fprintf(stderr, "utf8: enc or dec\n"); return 1; }
    }
#define CMD_CIPHER_ECB(name, prefix, KEY_SIZE) \
    else if (strcmp(cmd, name) == 0 && argc >= 5) \
    { \
        const char *op = argv[2]; \
        uint8_t key[KEY_SIZE]; size_t key_len; \
        if (hex_to_bytes(argv[3], strlen(argv[3]), key, &key_len) != CRYPTO_OK || key_len != KEY_SIZE) \
            { fprintf(stderr, "Bad key\n"); return 1; } \
        uint8_t data[4096]; size_t data_len; \
        if (hex_to_bytes(argv[4], strlen(argv[4]), data, &data_len) != CRYPTO_OK) \
            { fprintf(stderr, "Bad data\n"); return 1; } \
        uint8_t out[8192]; size_t out_len = sizeof(out); \
        int r; \
        if (strcmp(op, "enc") == 0) r = prefix ## _ecb_encrypt(key, data, data_len, out, &out_len); \
        else if (strcmp(op, "dec") == 0) r = prefix ## _ecb_decrypt(key, data, data_len, out, &out_len); \
        else { fprintf(stderr, "enc or dec\n"); return 1; } \
        if (r != CRYPTO_OK) { fprintf(stderr, "Crypto failed\n"); return 1; } \
        print_hex(out, out_len); printf("\n"); \
    }
#define CMD_CIPHER_CBC(name, prefix, KEY_SIZE, BLOCK_SIZE) \
    else if (strcmp(cmd, name) == 0 && argc >= 6) \
    { \
        const char *op = argv[2]; \
        uint8_t key[KEY_SIZE]; size_t key_len; \
        if (hex_to_bytes(argv[3], strlen(argv[3]), key, &key_len) != CRYPTO_OK || key_len != KEY_SIZE) \
            { fprintf(stderr, "Bad key\n"); return 1; } \
        uint8_t iv[BLOCK_SIZE]; size_t iv_len; \
        if (hex_to_bytes(argv[4], strlen(argv[4]), iv, &iv_len) != CRYPTO_OK || iv_len != BLOCK_SIZE) \
            { fprintf(stderr, "Bad iv\n"); return 1; } \
        uint8_t data[4096]; size_t data_len; \
        if (hex_to_bytes(argv[5], strlen(argv[5]), data, &data_len) != CRYPTO_OK) \
            { fprintf(stderr, "Bad data\n"); return 1; } \
        uint8_t out[8192]; size_t out_len = sizeof(out); \
        int r; \
        if (strcmp(op, "enc") == 0) r = prefix ## _cbc_encrypt(key, iv, data, data_len, out, &out_len); \
        else if (strcmp(op, "dec") == 0) r = prefix ## _cbc_decrypt(key, iv, data, data_len, out, &out_len); \
        else { fprintf(stderr, "enc or dec\n"); return 1; } \
        if (r != CRYPTO_OK) { fprintf(stderr, "Crypto failed\n"); return 1; } \
        print_hex(out, out_len); printf("\n"); \
    }
    CMD_CIPHER_ECB("aes-ecb", aes, 16)
    CMD_CIPHER_CBC("aes-cbc", aes, 16, 16)
    CMD_CIPHER_ECB("sm4-ecb", sm4, 16)
    CMD_CIPHER_CBC("sm4-cbc", sm4, 16, 16)
    CMD_CIPHER_ECB("rc6-ecb", rc6, 16)
    CMD_CIPHER_CBC("rc6-cbc", rc6, 16, 16)

    else if (strcmp(cmd, "rsa") == 0 && argc >= 3)
    {
        if (strcmp(argv[2], "gen") == 0)
        {
            uint8_t pri[RSA_PRI_RAW_SIZE]; size_t pri_len = sizeof(pri);
            uint8_t pub[RSA_PUB_RAW_SIZE]; size_t pub_len = sizeof(pub);
            if (rsa_gen_keypair(pri, &pri_len, pub, &pub_len) != CRYPTO_OK)
                { fprintf(stderr, "RSA gen failed\n"); return 1; }
            char pem[8192]; size_t pem_len = sizeof(pem);
            if (rsa_priv_to_pem(pri, pri_len, pem, &pem_len) == CRYPTO_OK)
                printf("PRIVATE:\n%.*s\n", (int)pem_len, pem);
            pem_len = sizeof(pem);
            if (rsa_pub_to_pem(pub, pub_len, pem, &pem_len) == CRYPTO_OK)
                printf("PUBLIC:\n%.*s\n", (int)pem_len, pem);
            printf("PRI_RAW: "); print_hex(pri, pri_len); printf("\n");
            printf("PUB_RAW: "); print_hex(pub, pub_len); printf("\n");
        }
        else if (strcmp(argv[2], "enc") == 0 && argc >= 5)
        {
            uint8_t pub[RSA_PUB_RAW_SIZE]; size_t pub_len;
            uint8_t plain[RSA_PLAIN_MAX]; size_t plain_len;
            if (hex_to_bytes(argv[3], strlen(argv[3]), pub, &pub_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad pub\n"); return 1; }
            if (hex_to_bytes(argv[4], strlen(argv[4]), plain, &plain_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad plain\n"); return 1; }
            uint8_t cipher[128]; size_t cipher_len;
            if (rsa_encrypt(pub, pub_len, plain, plain_len, cipher, &cipher_len) != CRYPTO_OK)
                { fprintf(stderr, "Encrypt failed\n"); return 1; }
            print_hex(cipher, cipher_len); printf("\n");
        }
        else if (strcmp(argv[2], "dec") == 0 && argc >= 5)
        {
            uint8_t pri[RSA_PRI_RAW_SIZE]; size_t pri_len;
            uint8_t cipher[128]; size_t cipher_len;
            if (hex_to_bytes(argv[3], strlen(argv[3]), pri, &pri_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad pri\n"); return 1; }
            if (hex_to_bytes(argv[4], strlen(argv[4]), cipher, &cipher_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad cipher\n"); return 1; }
            uint8_t plain[128]; size_t plain_len;
            if (rsa_decrypt(pri, pri_len, cipher, cipher_len, plain, &plain_len) != CRYPTO_OK)
                { fprintf(stderr, "Decrypt failed\n"); return 1; }
            print_hex(plain, plain_len); printf("\n");
        }
        else { fprintf(stderr, "rsa: gen, enc, or dec\n"); return 1; }
    }
    else if (strcmp(cmd, "ecc") == 0 && argc >= 3)
    {
        if (strcmp(argv[2], "gen") == 0)
        {
            uint8_t pri[20]; size_t pri_len = sizeof(pri);
            uint8_t pub[40]; size_t pub_len = sizeof(pub);
            if (ecc_gen_keypair(pri, &pri_len, pub, &pub_len) != CRYPTO_OK)
                { fprintf(stderr, "ECC gen failed\n"); return 1; }
            printf("PRI: "); print_hex(pri, pri_len); printf("\n");
            printf("PUB: "); print_hex(pub, pub_len); printf("\n");
        }
        else if (strcmp(argv[2], "pub-to-pem") == 0 && argc >= 4)
        {
            uint8_t pub[40]; size_t pub_len;
            if (hex_to_bytes(argv[3], strlen(argv[3]), pub, &pub_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad hex\n"); return 1; }
            char pem[2048]; size_t pem_len = sizeof(pem);
            if (ecc_pub_to_pem(pub, pub_len, pem, &pem_len) != CRYPTO_OK)
                { fprintf(stderr, "PEM failed\n"); return 1; }
            printf("%.*s", (int)pem_len, pem);
        }
        else { fprintf(stderr, "ecc: gen or pub-to-pem\n"); return 1; }
    }
    else if (strcmp(cmd, "rsasha1") == 0 && argc >= 4)
    {
        if (strcmp(argv[2], "sign") == 0 && argc >= 5)
        {
            uint8_t pri[RSA_PRI_RAW_SIZE]; size_t pri_len;
            uint8_t msg[4096]; size_t msg_len;
            if (hex_to_bytes(argv[3], strlen(argv[3]), pri, &pri_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad pri\n"); return 1; }
            if (hex_to_bytes(argv[4], strlen(argv[4]), msg, &msg_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad msg\n"); return 1; }
            uint8_t sig[128]; size_t sig_len = sizeof(sig);
            if (rsa_sha1_sign(pri, pri_len, msg, msg_len, sig, &sig_len) != CRYPTO_OK)
                { fprintf(stderr, "Sign failed\n"); return 1; }
            print_hex(sig, sig_len); printf("\n");
        }
        else if (strcmp(argv[2], "verify") == 0 && argc >= 6)
        {
            uint8_t pub[RSA_PUB_RAW_SIZE]; size_t pub_len;
            uint8_t msg[4096]; size_t msg_len;
            uint8_t sig[128]; size_t sig_len;
            if (hex_to_bytes(argv[3], strlen(argv[3]), pub, &pub_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad pub\n"); return 1; }
            if (hex_to_bytes(argv[4], strlen(argv[4]), msg, &msg_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad msg\n"); return 1; }
            if (hex_to_bytes(argv[5], strlen(argv[5]), sig, &sig_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad sig\n"); return 1; }
            printf("%s\n", rsa_sha1_verify(pub, pub_len, msg, msg_len, sig, sig_len) == CRYPTO_OK ? "VALID" : "INVALID");
        }
        else { fprintf(stderr, "rsasha1: sign or verify\n"); return 1; }
    }
    else if (strcmp(cmd, "ecdsa") == 0 && argc >= 4)
    {
        if (strcmp(argv[2], "sign") == 0 && argc >= 5)
        {
            uint8_t pri[20]; size_t pri_len;
            uint8_t msg[4096]; size_t msg_len;
            if (hex_to_bytes(argv[3], strlen(argv[3]), pri, &pri_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad pri\n"); return 1; }
            if (hex_to_bytes(argv[4], strlen(argv[4]), msg, &msg_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad msg\n"); return 1; }
            uint8_t sig[40]; size_t sig_len = sizeof(sig);
            if (ecdsa_sign(pri, pri_len, msg, msg_len, sig, &sig_len) != CRYPTO_OK)
                { fprintf(stderr, "Sign failed\n"); return 1; }
            print_hex(sig, sig_len); printf("\n");
        }
        else if (strcmp(argv[2], "verify") == 0 && argc >= 6)
        {
            uint8_t pub[40]; size_t pub_len;
            uint8_t msg[4096]; size_t msg_len;
            uint8_t sig[40]; size_t sig_len;
            if (hex_to_bytes(argv[3], strlen(argv[3]), pub, &pub_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad pub\n"); return 1; }
            if (hex_to_bytes(argv[4], strlen(argv[4]), msg, &msg_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad msg\n"); return 1; }
            if (hex_to_bytes(argv[5], strlen(argv[5]), sig, &sig_len) != CRYPTO_OK)
                { fprintf(stderr, "Bad sig\n"); return 1; }
            printf("%s\n", ecdsa_verify(pub, pub_len, msg, msg_len, sig, sig_len) == CRYPTO_OK ? "VALID" : "INVALID");
        }
        else { fprintf(stderr, "ecdsa: sign or verify\n"); return 1; }
    }
    else
    {
        fprintf(stderr, "Unknown command\n");
        return 1;
    }
    return 0;
}

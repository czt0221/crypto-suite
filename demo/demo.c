#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define GREEN "\033[32m"
#define RED   "\033[31m"
#define RESET "\033[0m"
#define PASS  "PASS"
#define FAIL  "FAIL"

#if defined(_WIN32)
#define RDERR "2>nul"
#define POPEN_RD "rb"
#else
#define RDERR "2>/dev/null"
#define POPEN_RD "r"
#endif

static const char *MSG = "Crypto-Suite TEST!";
static const size_t MSG_LEN = 19;
#define BS 16

static int tests_passed, tests_total, modules_passed, modules_total;

static void test_start(int n, int total, const char *name)
{
    modules_total = total;
    printf("\n[%d/%d] %s\n", n, total, name);
    tests_passed = 0; tests_total = 0;
}

static void test(const char *desc, int cond)
{
    tests_total++;
    if (cond) tests_passed++;
    printf("  %s%s%s %s\n", cond ? GREEN : RED, cond ? PASS : FAIL, RESET, desc);
}

static int test_done(void)
{
    if (tests_passed == tests_total) { modules_passed++; return 1; }
    return 0;
}

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("  %s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

static void hex_from_bytes(char *hex, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        sprintf(hex + i * 2, "%02x", data[i]);
}

static int openssl_run(const char *cmd, const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t out_cap)
{
    FILE *f = fopen("_ossl_tmp", "wb");
    if (!f) return -1;
    if (in && in_len) fwrite(in, 1, in_len, f);
    fclose(f);

    char buf[4096];
    snprintf(buf, sizeof(buf), "%s < _ossl_tmp", cmd);

    FILE *fp = popen(buf, POPEN_RD);
    if (!fp) { remove("_ossl_tmp"); return -1; }
    size_t n = out ? fread(out, 1, out_cap, fp) : 0;
    int rc = pclose(fp);
    remove("_ossl_tmp");
    return (rc == 0) ? (int)n : -1;
}

static int openssl_exec(const char *cmd, uint8_t *out, size_t out_cap)
{
    FILE *fp = popen(cmd, POPEN_RD);
    if (!fp) return -1;
    size_t n = out ? fread(out, 1, out_cap, fp) : 0;
    int rc = pclose(fp);
    return (rc == 0) ? (int)n : -1;
}

static void write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f) { fwrite(data, 1, len, f); fclose(f); }
}

static int file_exists(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f) { fclose(f); return 1; }
    return 0;
}

static int read_file(const char *path, uint8_t *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return (int)n;
}

static int ossl_to_file(const char *in_path, const char *out_path, const char *key_path, int encrypt)
{
    char cmd[1024];
    if (encrypt)
        snprintf(cmd, sizeof(cmd),
            "openssl pkeyutl -encrypt -pubin -inkey \"%s\" -in \"%s\" -out \"%s\" -pkeyopt pad-mode:pkcs1 " RDERR,
            key_path, in_path, out_path);
    else
        snprintf(cmd, sizeof(cmd),
            "openssl pkeyutl -decrypt -inkey \"%s\" -in \"%s\" -out \"%s\" " RDERR,
            key_path, in_path, out_path);
    return system(cmd);
}

static size_t pkcs7_pad(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap)
{
    size_t pad_len = BS - (in_len % BS);
    size_t total = in_len + pad_len;
    if (total > out_cap) return 0;
    memcpy(out, in, in_len);
    memset(out + in_len, (uint8_t)pad_len, pad_len);
    return total;
}

static size_t pkcs7_unpad(const uint8_t *data, size_t len)
{
    if (len == 0 || len % BS != 0) return 0;
    uint8_t pad = data[len - 1];
    if (pad < 1 || pad > BS || pad > len) return 0;
    for (size_t i = len - pad; i < len; i++)
        if (data[i] != pad) return 0;
    return len - pad;
}

static int der_encode_sig(const uint8_t raw[40], uint8_t der[80])
{
    int r_len = 20; while (r_len > 1 && raw[20 - r_len] == 0) r_len--;
    int s_len = 20; while (s_len > 1 && raw[40 - s_len] == 0) s_len--;
    int r_enc = (raw[20 - r_len] & 0x80) ? r_len + 1 : r_len;
    int s_enc = (raw[40 - s_len] & 0x80) ? s_len + 1 : s_len;

    int off = 0;
    der[off++] = 0x30; int seq_off = off++;
    der[off++] = 0x02; der[off++] = (uint8_t)r_enc;
    if (r_enc > r_len) der[off++] = 0x00;
    memcpy(der + off, raw + 20 - r_len, r_len); off += r_len;
    der[off++] = 0x02; der[off++] = (uint8_t)s_enc;
    if (s_enc > s_len) der[off++] = 0x00;
    memcpy(der + off, raw + 40 - s_len, s_len); off += s_len;
    der[seq_off] = off - seq_off - 1;
    return off;
}

static int der_decode_sig(const uint8_t *der, int der_len, uint8_t raw[40])
{
    if (der_len < 8 || der[0] != 0x30) return -1;
    int seq_len = der[1];
    int off = 2;
    if (off + seq_len > der_len) return -1;
    memset(raw, 0, 40);
    for (int part = 0; part < 2; part++) {
        if (off >= der_len || der[off] != 0x02) return -1;
        off++; int ilen = der[off++];
        if (off + ilen > der_len || ilen > 22) return -1;
        int start = off;
        while (start < off + ilen && der[start] == 0x00) start++;
        int ncopy = off + ilen - start;
        if (ncopy > 20) ncopy = 20;
        memcpy(raw + part * 20 + 20 - ncopy, der + start, ncopy);
        off += ilen;
    }
    return 0;
}

int main(void)
{
    printf("===== Crypto-Suite Demo =====\n");

    /* ======== 1/16 AES-128 ======== */
    test_start(1, 16, "AES-128");
    {
        uint8_t key[16], iv[16], buf[64], cipher[64], dec[64], ossl[64];
        size_t clen, dlen;
        rand_bytes(key, sizeof(key));
        rand_bytes(iv, sizeof(iv));
        printf("  plain: \"%s\"\n", MSG);
        print_hex("key", key, sizeof(key));

        size_t plen = pkcs7_pad((const uint8_t*)MSG, MSG_LEN, buf, sizeof(buf));
        char keyhex[33]; hex_from_bytes(keyhex, key, 16);

        printf("  [ECB]\n");
        clen = sizeof(cipher);
        int r = aes_ecb_encrypt(key, buf, plen, cipher, &clen);
        print_hex("crypto cipher", cipher, clen);
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "openssl enc -e -aes-128-ecb -K %s", keyhex);
        int n = openssl_run(cmd, (const uint8_t*)MSG, MSG_LEN, ossl, sizeof(ossl));
        if (n > 0) print_hex("openssl cipher", ossl, n);
        test("AES-128 ECB encrypt", r == CRYPTO_OK && n > 0 && (size_t)n == clen && memcmp(cipher, ossl, clen) == 0);
        dlen = sizeof(dec);
        r = aes_ecb_decrypt(key, cipher, clen, dec, &dlen);
        test("AES-128 ECB decrypt", r == CRYPTO_OK && pkcs7_unpad(dec, dlen) == MSG_LEN && memcmp(dec, MSG, MSG_LEN) == 0);

        printf("  [CBC]\n");
        print_hex("IV", iv, sizeof(iv));
        clen = sizeof(cipher);
        r = aes_cbc_encrypt(key, iv, buf, plen, cipher, &clen);
        print_hex("crypto cipher", cipher, clen);
        char ivhex[33]; hex_from_bytes(ivhex, iv, 16);
        snprintf(cmd, sizeof(cmd), "openssl enc -e -aes-128-cbc -K %s -iv %s", keyhex, ivhex);
        n = openssl_run(cmd, (const uint8_t*)MSG, MSG_LEN, ossl, sizeof(ossl));
        if (n > 0) print_hex("openssl cipher", ossl, n);
        test("AES-128 CBC encrypt", r == CRYPTO_OK && n > 0 && (size_t)n == clen && memcmp(cipher, ossl, clen) == 0);
        dlen = sizeof(dec);
        r = aes_cbc_decrypt(key, iv, cipher, clen, dec, &dlen);
        test("AES-128 CBC decrypt", r == CRYPTO_OK && pkcs7_unpad(dec, dlen) == MSG_LEN && memcmp(dec, MSG, MSG_LEN) == 0);
    }
    test_done();

    /* ======== 2/16 SM4 ======== */
    test_start(2, 16, "SM4");
    {
        uint8_t key[16], iv[16], buf[64], cipher[64], dec[64], ossl[64];
        size_t clen, dlen;
        rand_bytes(key, sizeof(key));
        rand_bytes(iv, sizeof(iv));
        printf("  plain: \"%s\"\n", MSG);
        print_hex("key", key, sizeof(key));

        size_t plen = pkcs7_pad((const uint8_t*)MSG, MSG_LEN, buf, sizeof(buf));
        char keyhex[33]; hex_from_bytes(keyhex, key, 16);

        printf("  [ECB]\n");
        clen = sizeof(cipher);
        int r = sm4_ecb_encrypt(key, buf, plen, cipher, &clen);
        print_hex("crypto cipher", cipher, clen);
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "openssl enc -e -sm4-ecb -K %s", keyhex);
        int n = openssl_run(cmd, (const uint8_t*)MSG, MSG_LEN, ossl, sizeof(ossl));
        if (n > 0) print_hex("openssl cipher", ossl, n);
        test("SM4 ECB encrypt", r == CRYPTO_OK && n > 0 && (size_t)n == clen && memcmp(cipher, ossl, clen) == 0);
        dlen = sizeof(dec);
        r = sm4_ecb_decrypt(key, cipher, clen, dec, &dlen);
        test("SM4 ECB decrypt", r == CRYPTO_OK && pkcs7_unpad(dec, dlen) == MSG_LEN && memcmp(dec, MSG, MSG_LEN) == 0);

        printf("  [CBC]\n");
        print_hex("IV", iv, sizeof(iv));
        clen = sizeof(cipher);
        r = sm4_cbc_encrypt(key, iv, buf, plen, cipher, &clen);
        print_hex("crypto cipher", cipher, clen);
        char ivhex[33]; hex_from_bytes(ivhex, iv, 16);
        snprintf(cmd, sizeof(cmd), "openssl enc -e -sm4-cbc -K %s -iv %s", keyhex, ivhex);
        n = openssl_run(cmd, (const uint8_t*)MSG, MSG_LEN, ossl, sizeof(ossl));
        if (n > 0) print_hex("openssl cipher", ossl, n);
        test("SM4 CBC encrypt", r == CRYPTO_OK && n > 0 && (size_t)n == clen && memcmp(cipher, ossl, clen) == 0);
        dlen = sizeof(dec);
        r = sm4_cbc_decrypt(key, iv, cipher, clen, dec, &dlen);
        test("SM4 CBC decrypt", r == CRYPTO_OK && pkcs7_unpad(dec, dlen) == MSG_LEN && memcmp(dec, MSG, MSG_LEN) == 0);
    }
    test_done();

    /* ======== 3/16 RC6 ======== */
    test_start(3, 16, "RC6");
    {
        uint8_t key[16], iv[16], buf[64], cipher[64], dec[64];
        size_t clen, dlen;
        rand_bytes(key, sizeof(key));
        rand_bytes(iv, sizeof(iv));
        printf("  plain: \"%s\"\n", MSG);
        print_hex("key", key, sizeof(key));

        size_t plen = pkcs7_pad((const uint8_t*)MSG, MSG_LEN, buf, sizeof(buf));

        printf("  [ECB]\n");
        clen = sizeof(cipher);
        int r = rc6_ecb_encrypt(key, buf, plen, cipher, &clen);
        print_hex("crypto cipher", cipher, clen);
        dlen = sizeof(dec);
        r = rc6_ecb_decrypt(key, cipher, clen, dec, &dlen);
        test("RC6 ECB roundtrip (self-verify openssl不支持)", r == CRYPTO_OK && pkcs7_unpad(dec, dlen) == MSG_LEN && memcmp(dec, MSG, MSG_LEN) == 0);

        printf("  [CBC]\n");
        print_hex("IV", iv, sizeof(iv));
        clen = sizeof(cipher);
        r = rc6_cbc_encrypt(key, iv, buf, plen, cipher, &clen);
        print_hex("crypto cipher", cipher, clen);
        dlen = sizeof(dec);
        r = rc6_cbc_decrypt(key, iv, cipher, clen, dec, &dlen);
        test("RC6 CBC roundtrip (self-verify openssl不支持)", r == CRYPTO_OK && pkcs7_unpad(dec, dlen) == MSG_LEN && memcmp(dec, MSG, MSG_LEN) == 0);
    }
    test_done();

    /* ======== 4/16 SHA-1 ======== */
    test_start(4, 16, "SHA-1");
    {
        uint8_t d[20], ossl[20];
        printf("  message: \"%s\"\n", MSG);
        sha1((const uint8_t*)MSG, MSG_LEN, d);
        print_hex("crypto hash", d, 20);
        int n = openssl_run("openssl dgst -sha1 -binary", (const uint8_t*)MSG, MSG_LEN, ossl, sizeof(ossl));
        if (n == 20) print_hex("openssl hash", ossl, 20);
        test("SHA-1", n == 20 && memcmp(d, ossl, 20) == 0);
    }
    test_done();

    /* ======== 5/16 SHA-256 ======== */
    test_start(5, 16, "SHA-256");
    {
        uint8_t d[32], ossl[32];
        printf("  message: \"%s\"\n", MSG);
        sha256((const uint8_t*)MSG, MSG_LEN, d);
        print_hex("crypto hash", d, 32);
        int n = openssl_run("openssl dgst -sha256 -binary", (const uint8_t*)MSG, MSG_LEN, ossl, sizeof(ossl));
        if (n == 32) print_hex("openssl hash", ossl, 32);
        test("SHA-256", n == 32 && memcmp(d, ossl, 32) == 0);
    }
    test_done();

    /* ======== 6/16 SHA3-256 ======== */
    test_start(6, 16, "SHA3-256");
    {
        uint8_t d[32], ossl[32];
        printf("  message: \"%s\"\n", MSG);
        sha3((const uint8_t*)MSG, MSG_LEN, d);
        print_hex("crypto hash", d, 32);
        int n = openssl_run("openssl dgst -sha3-256 -binary", (const uint8_t*)MSG, MSG_LEN, ossl, sizeof(ossl));
        if (n == 32) print_hex("openssl hash", ossl, 32);
        test("SHA3-256", n == 32 && memcmp(d, ossl, 32) == 0);
    }
    test_done();

    /* ======== 7/16 RIPEMD-160 ======== */
    test_start(7, 16, "RIPEMD-160");
    {
        uint8_t d[20], ossl[20];
        printf("  message: \"%s\"\n", MSG);
        ripemd160((const uint8_t*)MSG, MSG_LEN, d);
        print_hex("crypto hash", d, 20);
        int n = openssl_run("openssl dgst -ripemd160 -binary", (const uint8_t*)MSG, MSG_LEN, ossl, sizeof(ossl));
        if (n == 20) print_hex("openssl hash", ossl, 20);
        test("RIPEMD-160", n == 20 && memcmp(d, ossl, 20) == 0);
    }
    test_done();

    /* ======== 8/16 HMAC-SHA1 ======== */
    test_start(8, 16, "HMAC-SHA1");
    {
        uint8_t key[16], mac[20], ossl[20];
        rand_bytes(key, sizeof(key));
        printf("  message: \"%s\"\n", MSG);
        print_hex("key", key, sizeof(key));
        hmac_sha1(key, sizeof(key), (const uint8_t*)MSG, MSG_LEN, mac);
        print_hex("crypto MAC", mac, 20);
        char keyhex[33]; hex_from_bytes(keyhex, key, 16);
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "openssl dgst -sha1 -mac hmac -macopt hexkey:%s -binary", keyhex);
        int n = openssl_run(cmd, (const uint8_t*)MSG, MSG_LEN, ossl, sizeof(ossl));
        if (n == 20) print_hex("openssl MAC", ossl, 20);
        test("HMAC-SHA1", n == 20 && memcmp(mac, ossl, 20) == 0);
    }
    test_done();

    /* ======== 9/16 HMAC-SHA256 ======== */
    test_start(9, 16, "HMAC-SHA256");
    {
        uint8_t key[16], mac[32], ossl[32];
        rand_bytes(key, sizeof(key));
        printf("  message: \"%s\"\n", MSG);
        print_hex("key", key, sizeof(key));
        hmac_sha256(key, sizeof(key), (const uint8_t*)MSG, MSG_LEN, mac);
        print_hex("crypto MAC", mac, 32);
        char keyhex[33]; hex_from_bytes(keyhex, key, 16);
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "openssl dgst -sha256 -mac hmac -macopt hexkey:%s -binary", keyhex);
        int n = openssl_run(cmd, (const uint8_t*)MSG, MSG_LEN, ossl, sizeof(ossl));
        if (n == 32) print_hex("openssl MAC", ossl, 32);
        test("HMAC-SHA256", n == 32 && memcmp(mac, ossl, 32) == 0);
    }
    test_done();

    /* ======== 10/16 PBKDF2 ======== */
    test_start(10, 16, "PBKDF2");
    {
        uint8_t salt[16], key[32], ossl[32];
        rand_bytes(salt, sizeof(salt));
        printf("  password: \"%s\"\n", MSG);
        print_hex("salt", salt, sizeof(salt));
        printf("  iterations: 4096\n");

        printf("  [SHA1]\n");
        pbkdf2((const uint8_t*)MSG, MSG_LEN, salt, sizeof(salt), 4096, key, 32);
        print_hex("crypto derived key", key, 32);
        char salthex[33]; hex_from_bytes(salthex, salt, 16);
        char cmd[1024];
        snprintf(cmd, sizeof(cmd),
            "openssl kdf -keylen 32 -kdfopt digest:SHA1 -kdfopt iter:4096"
            " -kdfopt pass:\"%s\" -kdfopt hexsalt:%s -binary PBKDF2", MSG, salthex);
        int n = openssl_exec(cmd, ossl, sizeof(ossl));
        if (n == 32) print_hex("openssl derived key", ossl, 32);
        test("PBKDF2-HMAC-SHA1", n == 32 && memcmp(key, ossl, 32) == 0);

        printf("  [SHA256]\n");
        pbkdf2_sha256((const uint8_t*)MSG, MSG_LEN, salt, sizeof(salt), 4096, key, 32);
        print_hex("crypto sha256 derived key", key, 32);
        snprintf(cmd, sizeof(cmd),
            "openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt iter:4096"
            " -kdfopt pass:\"%s\" -kdfopt hexsalt:%s -binary PBKDF2", MSG, salthex);
        n = openssl_exec(cmd, ossl, sizeof(ossl));
        if (n == 32) print_hex("openssl sha256 derived key", ossl, 32);
        test("PBKDF2-HMAC-SHA256", n == 32 && memcmp(key, ossl, 32) == 0);
    }
    test_done();

    /* ======== 11/16 Base64 ======== */
    test_start(11, 16, "Base64");
    {
        char b64[64]; size_t b64_len = sizeof(b64);
        uint8_t raw[32]; size_t raw_len = sizeof(raw);
        printf("  plain: \"%s\"\n", MSG);
        base64_encode((const uint8_t*)MSG, MSG_LEN, b64, &b64_len);
        printf("  crypto base64: %.*s\n", (int)b64_len, b64);
        raw_len = sizeof(raw);
        base64_decode(b64, b64_len, raw, &raw_len);
        test("base64 roundtrip", raw_len == MSG_LEN && memcmp(raw, MSG, MSG_LEN) == 0);
    }
    test_done();

    /* ======== 12/16 UTF-8 ======== */
    test_start(12, 16, "UTF-8");
    {
        uint32_t cp[] = { 0x5BC6, 0x7801, 0x5DE5, 0x5177, 0x0020, 0x6D4B, 0x8BD5, 0xFF01 };
        uint8_t enc[32]; size_t enc_len = sizeof(enc);
        utf8_encode(cp, 8, enc, &enc_len);
        printf("  plain: \"密码工具 测试！\"\n");
        print_hex("crypto utf-8", enc, enc_len);
        uint32_t dec[16]; size_t dec_len = 16;
        utf8_decode(enc, enc_len, dec, &dec_len);
        test("UTF-8 roundtrip", dec_len == 8 && memcmp(dec, cp, 8 * 4) == 0);
    }
    test_done();

    /* ======== 13/16 RSA-1024 ======== */
    test_start(13, 16, "RSA-1024");
    {
        uint8_t pri[RSA_PRI_RAW_SIZE]; size_t pri_len;
        uint8_t pub[RSA_PUB_RAW_SIZE]; size_t pub_len;
        int r = rsa_gen_keypair(pri, &pri_len, pub, &pub_len);
        if (r == CRYPTO_OK)
        {
            printf("  plain: \"%s\"\n", MSG);

            char pem[4096]; size_t pem_len;

            pem_len = sizeof(pem);
            rsa_priv_to_pem(pri, pri_len, pem, &pem_len);
            write_file("_rsa_pri.pem", pem, pem_len);
            printf("  crypto private key:\n%s\n", pem);

            pem_len = sizeof(pem);
            rsa_pub_to_pem(pub, pub_len, pem, &pem_len);
            write_file("_rsa_pub.pem", pem, pem_len);
            printf("  crypto public key:\n%s\n", pem);

            test("RSA private key PEM export _rsa_pri.pem", file_exists("_rsa_pri.pem"));
            test("RSA public key PEM export _rsa_pub.pem", file_exists("_rsa_pub.pem"));

            uint8_t plain[64], cipher[128], dec[128], ossl_cipher[128], ossl_dec[128];
            size_t cipher_len, dec_len, ossl_cipher_len;
            size_t msg_rsa = strlen("Crypto-Suite TEST!");
            memcpy(plain, MSG, msg_rsa);

            /* crypto encrypt -> crypto decrypt */
            cipher_len = sizeof(cipher);
            rsa_encrypt(pub, pub_len, plain, msg_rsa, cipher, &cipher_len);
            print_hex("crypto cipher", cipher, cipher_len);
            dec_len = sizeof(dec);
            int en = rsa_decrypt(pri, pri_len, cipher, cipher_len, dec, &dec_len);
            test("RSA crypto encrypt -> crypto decrypt", en == CRYPTO_OK && dec_len == msg_rsa && memcmp(dec, plain, msg_rsa) == 0);

            /* openssl encrypt -> crypto decrypt */
            write_file("_rsa_ossl_plain", plain, msg_rsa);
            if (ossl_to_file("_rsa_ossl_plain", "_rsa_ossl_cipher", "_rsa_pub.pem", 1) == 0)
            {
                int rn = read_file("_rsa_ossl_cipher", ossl_cipher, sizeof(ossl_cipher));
                ossl_cipher_len = rn > 0 ? (size_t)rn : 0;
                if (rn > 0) print_hex("openssl cipher", ossl_cipher, ossl_cipher_len);
                dec_len = sizeof(dec);
                en = rsa_decrypt(pri, pri_len, ossl_cipher, ossl_cipher_len, dec, &dec_len);
                test("RSA openssl encrypt -> crypto decrypt", rn > 0 && en == CRYPTO_OK && dec_len == msg_rsa && memcmp(dec, plain, msg_rsa) == 0);
            }
            else test("RSA openssl encrypt -> crypto decrypt", 0);

            /* crypto encrypt -> openssl decrypt */
            write_file("_rsa_ossl_cipher", cipher, cipher_len);
            if (ossl_to_file("_rsa_ossl_cipher", "_rsa_ossl_plain_out", "_rsa_pri.pem", 0) == 0)
            {
                int rn = read_file("_rsa_ossl_plain_out", ossl_dec, sizeof(ossl_dec));
                test("RSA crypto encrypt -> openssl decrypt", rn > 0 && (size_t)rn == msg_rsa && memcmp(ossl_dec, plain, msg_rsa) == 0);
            }
            else test("RSA crypto encrypt -> openssl decrypt", 0);

            char cmd[512];
            int n;
            snprintf(cmd, sizeof(cmd),
                "openssl rsa -in _rsa_pri.pem -check -noout " RDERR);
            n = openssl_exec(cmd, NULL, 0);
            if (n >= 0) {
                snprintf(cmd, sizeof(cmd),
                    "openssl rsa -pubin -in _rsa_pub.pem -noout " RDERR);
                n = openssl_exec(cmd, NULL, 0);
            }
            test("RSA key openssl validation (配对与合法性验证)", n >= 0);
        }
    }
    test_done();

    /* ======== 14/16 ECC-160 ======== */
    test_start(14, 16, "ECC-160");
    {
        uint8_t pri[ECC_BYTES]; size_t pri_len;
        uint8_t pub[ECC_BYTES * 2]; size_t pub_len;
        int r = ecc_gen_keypair(pri, &pri_len, pub, &pub_len);
        if (r == CRYPTO_OK)
        {
            char pem[2048]; size_t pem_len;

            pem_len = sizeof(pem);
            ecc_pri_to_pem(pri, pri_len, pub, pub_len, pem, &pem_len);
            write_file("_ecc_pri.pem", pem, pem_len);
            printf("  crypto private key:\n%s\n", pem);

            pem_len = sizeof(pem);
            ecc_pub_to_pem(pub, pub_len, pem, &pem_len);
            write_file("_ecc_pub.pem", pem, pem_len);
            printf("  crypto public key:\n%s\n", pem);

            test("ECC private key PEM export _ecc_pri.pem", file_exists("_ecc_pri.pem"));
            test("ECC public key PEM export _ecc_pub.pem", file_exists("_ecc_pub.pem"));

            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                "openssl ec -in _ecc_pri.pem -check -noout " RDERR);
            int n = openssl_exec(cmd, NULL, 0);
            if (n >= 0) {
                snprintf(cmd, sizeof(cmd),
                    "openssl ec -pubin -in _ecc_pub.pem -noout " RDERR);
                n = openssl_exec(cmd, NULL, 0);
            }
            test("ECC key openssl validation (配对与合法性验证)", n >= 0);
        }
    }
    test_done();

    /* ======== 15/16 RSA-SHA1 ======== */
    test_start(15, 16, "RSA-SHA1");
    {
        uint8_t pri[RSA_PRI_RAW_SIZE]; size_t pri_len;
        uint8_t pub[RSA_PUB_RAW_SIZE]; size_t pub_len;
        rsa_gen_keypair(pri, &pri_len, pub, &pub_len);
        const uint8_t *msg = (const uint8_t*)MSG;
        size_t msg_len = MSG_LEN;
        printf("  message: \"%s\"\n", MSG);

        /* write PEMs for cross-verify */
        char pem[4096]; size_t pem_len;
        pem_len = sizeof(pem); rsa_priv_to_pem(pri, pri_len, pem, &pem_len);
        write_file("_rsasha1_pri.pem", pem, pem_len);
        pem_len = sizeof(pem); rsa_pub_to_pem(pub, pub_len, pem, &pem_len);
        write_file("_rsasha1_pub.pem", pem, pem_len);

        uint8_t sig[128]; size_t sig_len, ossl_sig_len;
        int r;

        /* crypto sign */
        sig_len = sizeof(sig);
        r = rsa_sha1_sign(pri, pri_len, msg, msg_len, sig, &sig_len);
        print_hex("crypto signature", sig, sig_len);

        /* openssl sign */
        uint8_t ossl_sig[128];
        char cmd[1024];
        snprintf(cmd, sizeof(cmd),
            "openssl dgst -sha1 -sign _rsasha1_pri.pem _rsasha1_msg " RDERR);
        write_file("_rsasha1_msg", msg, msg_len);
        int n = openssl_run(cmd, NULL, 0, ossl_sig, sizeof(ossl_sig));
        ossl_sig_len = n > 0 ? (size_t)n : 0;
        if (n > 0) print_hex("openssl signature", ossl_sig, ossl_sig_len);

        r = rsa_sha1_verify(pub, pub_len, msg, msg_len, sig, sig_len);
        test("RSA-SHA1 crypto sign -> crypto verify", r == CRYPTO_OK);

        /* crypto sign -> openssl verify */
        write_file("_rsasha1_sig", sig, sig_len);
        snprintf(cmd, sizeof(cmd),
            "openssl dgst -sha1 -verify _rsasha1_pub.pem -signature _rsasha1_sig _rsasha1_msg " RDERR);
        n = openssl_exec(cmd, NULL, 0);
        test("RSA-SHA1 crypto sign -> openssl verify", n >= 0);

        /* openssl sign -> crypto verify */
        n = (ossl_sig_len == 128) ? 1 : 0;
        int ok = n && (rsa_sha1_verify(pub, pub_len, msg, msg_len, ossl_sig, 128) == CRYPTO_OK);
        test("RSA-SHA1 openssl sign -> crypto verify", ok);

        sig[0] ^= 0x01;
        r = rsa_sha1_verify(pub, pub_len, msg, msg_len, sig, sig_len);
        test("RSA-SHA1 reject tampered sig", r == CRYPTO_ERR);
    }
    test_done();

    /* ======== 16/16 ECDSA ======== */
    test_start(16, 16, "ECDSA");
    {
        uint8_t pri[ECC_BYTES]; size_t pri_len;
        uint8_t pub[ECC_BYTES * 2]; size_t pub_len;
        ecc_gen_keypair(pri, &pri_len, pub, &pub_len);
        const uint8_t *msg = (const uint8_t*)MSG;
        size_t msg_len = MSG_LEN;
        printf("  message: \"%s\"\n", MSG);

        /* write PEMs for cross-verify */
        char pem[2048]; size_t pem_len;
        pem_len = sizeof(pem); ecc_pri_to_pem(pri, pri_len, pub, pub_len, pem, &pem_len);
        write_file("_ecdsa_pri.pem", pem, pem_len);
        pem_len = sizeof(pem); ecc_pub_to_pem(pub, pub_len, pem, &pem_len);
        write_file("_ecdsa_pub.pem", pem, pem_len);

        uint8_t sig[40]; size_t sig_len;
        uint8_t ossl_sig_der[80]; int ossl_der_len;
        int r;

        /* crypto sign */
        sig_len = sizeof(sig);
        r = ecdsa_sign(pri, pri_len, msg, msg_len, sig, &sig_len);
        print_hex("crypto signature", sig, sig_len);

        /* openssl sign */
        write_file("_ecdsa_msg", msg, msg_len);
        char cmd[1024];
        snprintf(cmd, sizeof(cmd),
            "openssl dgst -sha1 -sign _ecdsa_pri.pem _ecdsa_msg " RDERR);
        ossl_der_len = openssl_run(cmd, NULL, 0, ossl_sig_der, sizeof(ossl_sig_der));
        if (ossl_der_len > 0) print_hex("openssl signature", ossl_sig_der, (size_t)ossl_der_len);

        /* crypto sign -> crypto verify */
        r = ecdsa_verify(pub, pub_len, msg, msg_len, sig, sig_len);
        test("ECDSA crypto sign -> crypto verify", r == CRYPTO_OK);

        /* crypto sign -> openssl verify */
        uint8_t sig_der[80];
        int der_len = der_encode_sig(sig, sig_der);
        write_file("_ecdsa_sig", sig_der, (size_t)der_len);
        snprintf(cmd, sizeof(cmd),
            "openssl dgst -sha1 -verify _ecdsa_pub.pem -signature _ecdsa_sig _ecdsa_msg " RDERR);
        int n = openssl_exec(cmd, NULL, 0);
        test("ECDSA crypto sign -> openssl verify", n >= 0);

        /* openssl sign -> crypto verify */
        uint8_t ossl_raw[40];
        n = (ossl_der_len > 0 && der_decode_sig(ossl_sig_der, ossl_der_len, ossl_raw) == 0) ? 1 : 0;
        r = n ? ecdsa_verify(pub, pub_len, msg, msg_len, ossl_raw, 40) : CRYPTO_ERR;
        test("ECDSA openssl sign -> crypto verify", r == CRYPTO_OK);

        sig[0] ^= 0x01;
        r = ecdsa_verify(pub, pub_len, msg, msg_len, sig, sig_len);
        test("ECDSA reject tampered sig", r == CRYPTO_ERR);
    }
    test_done();

    printf("\n===== %d/%d modules passed =====\n", modules_passed, modules_total);
    printf("\n提示：所有密钥key/偏移量IV均/盐值salt为每次启用demo时随机生成\n");
    printf("Random source: %s\n", rand_source());
    return modules_passed == modules_total ? 0 : 1;
}

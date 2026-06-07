#include "crypto.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
extern BOOLEAN WINAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);
#elif defined(__linux__)
#include <unistd.h>
#include <sys/syscall.h>
#elif defined(__APPLE__)
#include <unistd.h>
#include <sys/random.h>
#endif

/* ======== RDRAND (x86-64) ======== */
#if defined(__x86_64__)
#include <immintrin.h>
#include <cpuid.h>

static int rdrand_supported(void)
{
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx))
        return (ecx >> 30) & 1;
    return 0;
}

static int rdrand_fill(uint8_t *buf, size_t len)
{
    static int cached = 0, avail = 0;
    if (!cached) { avail = rdrand_supported(); cached = 1; }
    if (!avail) return CRYPTO_ERR;

    for (size_t i = 0; i < len; i += 8) {
        unsigned long long val;
        int ok = 0;
        for (int j = 0; j < 10; j++) {
            if (_rdrand64_step(&val)) { ok = 1; break; }
        }
        if (!ok) return CRYPTO_ERR;
        size_t n = len - i < 8 ? len - i : 8;
        memcpy(buf + i, &val, n);
    }
    return CRYPTO_OK;
}

#else
static int rdrand_fill(uint8_t *buf, size_t len)
{
    (void)buf; (void)len;
    return CRYPTO_ERR;
}
#endif

/* ======== Platform fillers ======== */
static const char *tier_name = NULL;

#if defined(_WIN32)

static int win_fill(uint8_t *buf, size_t len)
{
    if (BCryptGenRandom(NULL, buf, (ULONG)len,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) {
        if (!tier_name) tier_name = "BCryptGenRandom";
        return CRYPTO_OK;
    }
    if (SystemFunction036(buf, (ULONG)len)) {
        if (!tier_name) tier_name = "RtlGenRandom";
        return CRYPTO_OK;
    }
    return CRYPTO_ERR;
}

#elif defined(__linux__)

static int linux_fill(uint8_t *buf, size_t len)
{
    if (syscall(SYS_getrandom, buf, len, 0) == (long)len) {
        if (!tier_name) tier_name = "getrandom (Linux)";
        return CRYPTO_OK;
    }
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        int ok = (fread(buf, 1, len, f) == len) ? CRYPTO_OK : CRYPTO_ERR;
        fclose(f);
        if (ok == CRYPTO_OK) {
            if (!tier_name) tier_name = "/dev/urandom (Linux)";
            return CRYPTO_OK;
        }
    }
    return CRYPTO_ERR;
}

#elif defined(__APPLE__)

static int macos_fill(uint8_t *buf, size_t len)
{
    arc4random_buf(buf, len);
    if (!tier_name) tier_name = "arc4random_buf (macOS)";
    return CRYPTO_OK;
}

#else

static int unix_fill(uint8_t *buf, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        int ok = (fread(buf, 1, len, f) == len) ? CRYPTO_OK : CRYPTO_ERR;
        fclose(f);
        if (ok == CRYPTO_OK) {
            if (!tier_name) tier_name = "/dev/urandom (Unix)";
            return CRYPTO_OK;
        }
    }
    return CRYPTO_ERR;
}

#endif

/* ======== rand_bytes / rand_source ======== */

int rand_bytes(uint8_t *buf, size_t len)
{
#if defined(_WIN32)
    if (win_fill(buf, len) == CRYPTO_OK) return CRYPTO_OK;
#elif defined(__linux__)
    if (linux_fill(buf, len) == CRYPTO_OK) return CRYPTO_OK;
#elif defined(__APPLE__)
    if (macos_fill(buf, len) == CRYPTO_OK) return CRYPTO_OK;
#else
    if (unix_fill(buf, len) == CRYPTO_OK) return CRYPTO_OK;
#endif

    if (rdrand_fill(buf, len) == CRYPTO_OK) {
        if (!tier_name) tier_name = "RDRAND";
        return CRYPTO_OK;
    }

    if (!tier_name)
        tier_name = "\033[31mWARNING: rand fallback\033[0m";
    fprintf(stderr,
        "WARNING: No hardware/OS random source available, "
        "using deterministic fallback (rand).\n");
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL) ^
              (unsigned int)(uintptr_t)buf ^
              (unsigned int)clock());
        seeded = 1;
    }
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(rand() & 0xFF);
    return CRYPTO_OK;
}

const char *rand_source(void)
{
    if (!tier_name) {
        uint8_t tmp;
        rand_bytes(&tmp, 1);
    }
    return tier_name;
}

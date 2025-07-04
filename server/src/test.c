#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/curve448.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/ed448.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/hqc.h>
#include <wolfssl/wolfcrypt/otmlkem.h>
#include <wolfssl/wolfcrypt/pqclean_mlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sphincs.h>

#define SIG_MSG_SIZE 48
#define WARMUP_ROUNDS 1
#define BENCH_ROUNDS 5

#define BENCH_X25519
#define BENCH_X25519_KEYGEN
#define BENCH_X25519_AGREE

#define BENCH_X448
#define BENCH_X448_KEYGEN
#define BENCH_X448_AGREE

#define BENCH_ECDHE
#define BENCH_ECDHE_KEYGEN
#define BENCH_ECDHE_AGREE

/* I am lazy, so ML-KEM will bench iff OT-ML-KEM bench */
#define BENCH_MLKEM
#define BENCH_MLKEM_KEYGEN
#define BENCH_MLKEM_ENCAP
#define BENCH_MLKEM_DECAP

#define BENCH_HQC
#define BENCH_HQC_KEYGEN
#define BENCH_HQC_ENCAP
#define BENCH_HQC_DECAP

#define BENCH_RSA2048
#define BENCH_RSA2048_KEYGEN
#define BENCH_RSA2048_SIGN
#define BENCH_RSA2048_VERIFY

#define BENCH_ECDSA
#define BENCH_ECDSA_KEYGEN
#define BENCH_ECDSA_SIGN
#define BENCH_ECDSA_VERIFY

#define BENCH_ED25519
#define BENCH_ED25519_KEYGEN
#define BENCH_ED25519_SIGN
#define BENCH_ED25519_VERIFY

#define BENCH_ED448
#define BENCH_ED448_KEYGEN
#define BENCH_ED448_SIGN
#define BENCH_ED448_VERIFY

#define BENCH_DILITHIUM
#define BENCH_DILITHIUM_KEYGEN
#define BENCH_DILITHIUM_SIGN
#define BENCH_DILITHIUM_VERIFY

#define BENCH_FALCON
#define BENCH_FALCON_KEYGEN
#define BENCH_FALCON_SIGN
#define BENCH_FALCON_VERIFY

#define BENCH_SPHINCS
#define BENCH_SPHINCS_KEYGEN
#define BENCH_SPHINCS_SIGN
#define BENCH_SPHINCS_VERIFY

#include <stdint.h>

#ifndef __APPLE__
#ifdef USE_RDPMC  /* Needs echo 2 > /sys/devices/cpu/rdpmc */

static inline uint64_t read_cyccnt(void) {
  const uint32_t ecx = (1U << 30) + 1;
  uint64_t result;

  __asm__ volatile ("rdpmc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : "c" (ecx) : "rdx");

  return result;
}

#else

static inline uint64_t read_cyccnt(void) {
  uint64_t result;

  __asm__ volatile ("rdtsc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : : "%rdx");

  return result;
}

#endif
#else
#include <mach/mach_time.h>
static inline uint64_t read_cyccnt(void) {
    return mach_absolute_time();
}
#endif  /* !__APPLE__ */

/* Benchmark a black box by running it many times. The CPU cycles counts are
 * written to the input timestamp arrays.
 *
 */
void bench_black_box(void (*blackbox)(void *), void *blackbox_args,
                     uint32_t *timestamps, uint32_t rounds) {
    /* warm-up */
    for (uint32_t i = 0; i < WARMUP_ROUNDS; i++) {
        blackbox(blackbox_args);
    }

    uint64_t cyc_start, cyc_stop = 0;
    for (uint64_t i = 0; i < rounds; i++) {
        cyc_start = read_cyccnt();
        blackbox(blackbox_args);
        cyc_stop = read_cyccnt();
        timestamps[i] = cyc_stop - cyc_start;
    }
}

static int cmp_uint32(const void *a, const void *b) {
    uint32_t va = *(const uint32_t *)a;
    uint32_t vb = *(const uint32_t *)b;
    return (va > vb) - (va < vb); // returns 1, 0, or -1
}

uint32_t percentile(uint32_t *sorted, size_t len, double percent) {
    if (len == 0)
        return 0;
    size_t idx = (size_t)((percent / 100.0) * len);
    if (idx >= len)
        idx = len - 1;
    return sorted[idx];
}

void print_results(uint32_t *durs, size_t len, const char *prefix) {
    if (len == 0 || !durs || !prefix)
        return;

    // Sort a copy to avoid modifying original array
    uint32_t *copy = malloc(len * sizeof(uint32_t));
    if (!copy)
        return;
    for (size_t i = 0; i < len; i++) {
        copy[i] = durs[i];
    }
    qsort(copy, len, sizeof(uint32_t), cmp_uint32);

    // Median
    uint32_t median = (len % 2 == 0) ? (copy[len / 2 - 1] + copy[len / 2]) / 2
                                     : copy[len / 2];

    // Percentiles
    uint32_t p90 = percentile(copy, len, 90.0);
    uint32_t p99 = percentile(copy, len, 99.0);

    // Print CSV line
    printf("%s,%u,%u,%u\n", prefix, median, p90, p99);

    free(copy);
}

#ifdef BENCH_X25519
struct x25519_args {
    curve25519_key alice;
    curve25519_key bob;
};

static void x25519_setup(struct x25519_args *args, WC_RNG *rng) {
    int ret;
    wc_curve25519_init(&args->alice);
    wc_curve25519_init(&args->bob);
    ret = wc_curve25519_make_key(rng, 32, &args->alice);
    if (ret < 0) {
        printf("wc_curve25519_make_key returned %d\n", ret);
        exit(-1);
    }
    ret = wc_curve25519_make_key(rng, 32, &args->bob);
    if (ret < 0) {
        printf("wc_curve25519_make_key returned %d\n", ret);
        exit(-1);
    }
    printf("x25519 setup complete\n");
}

#ifdef BENCH_X25519_KEYGEN
static void x25519_keygen(void *args) {
    curve25519_key key;
    WC_RNG *rng = (WC_RNG *)args;
    int ret;
    wc_curve25519_init(&key);
    ret = wc_curve25519_make_key(rng, 32, &key);
    if (ret < 0) {
        printf("wc_curve25519_make_key returned %d\n", ret);
        exit(-1);
    }
}
#endif /* BENCH_X25519_KEYGEN */

#ifdef BENCH_X25519_AGREE
static void x25519_agree(void *args) {
    byte out[32];
    word32 outlen = 32;
    struct x25519_args *keypair = (struct x25519_args *)args;
    int ret = wc_curve25519_shared_secret(&keypair->alice, &keypair->bob, out,
                                          &outlen);
    if (ret < 0) {
        printf("wc_curve25519_shared_secret returned %d\n", ret);
        exit(-1);
    }
}
#endif
#endif /* BENCH_X25519 */

#ifdef BENCH_X448
struct x448_args {
    curve448_key alice;
    curve448_key bob;
};

#ifdef BENCH_X448_KEYGEN
static void x448_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    curve448_key key;
    wc_curve448_init(&key);
    wc_curve448_make_key(rng, 56, &key);
}
#endif

static void x448_setup(struct x448_args *args, WC_RNG *rng) {
    int ret;
    wc_curve448_init(&args->alice);
    wc_curve448_init(&args->bob);
    ret = wc_curve448_make_key(rng, 56, &args->alice);
    if (ret < 0) {
        printf("wc_curve448_make_key returned %d\n", ret);
        exit(-1);
    }
    ret = wc_curve448_make_key(rng, 56, &args->bob);
    if (ret < 0) {
        printf("wc_curve448_make_key returned %d\n", ret);
        exit(-1);
    }
    printf("x448 setup complete\n");
}

#ifdef BENCH_X448_AGREE
static void x448_agree(void *args) {
    byte out[56];
    word32 outlen = 56;
    struct x448_args *keypair = (struct x448_args *)args;
    int ret =
        wc_curve448_shared_secret(&keypair->alice, &keypair->bob, out, &outlen);
    if (ret < 0) {
        printf("wc_curve448_shared_secret returned %d\n", ret);
        exit(-1);
    }
}
#endif
#endif /* BENCH_X448 */

#ifdef BENCH_ECDHE
struct ecdhe_args {
    ecc_key alice;
    ecc_key bob;
};

#ifdef BENCH_ECDHE_KEYGEN
static void ecdhe256_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    ecc_key key;
    int keysize = wc_ecc_get_curve_size_from_id(ECC_SECP256R1);
    wc_ecc_init(&key);
    int ret = wc_ecc_make_key(rng, keysize, &key);
    if (ret < 0) {
        printf("wc_ecc_make_key returned %d\n", ret);
        exit(-1);
    }
}

static void ecdhe384_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    ecc_key key;
    int keysize = wc_ecc_get_curve_size_from_id(ECC_SECP384R1);
    wc_ecc_init(&key);
    int ret = wc_ecc_make_key(rng, keysize, &key);
    if (ret < 0) {
        printf("wc_ecc_make_key returned %d\n", ret);
        exit(-1);
    }
}

static void ecdhe521_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    ecc_key key;
    int keysize = wc_ecc_get_curve_size_from_id(ECC_SECP521R1);
    wc_ecc_init(&key);
    int ret = wc_ecc_make_key(rng, keysize, &key);
    if (ret < 0) {
        printf("wc_ecc_make_key returned %d\n", ret);
        exit(-1);
    }
}
#endif /* BENCH_ECDHE_KEYGEN */

static void ecdhe_setup(struct ecdhe_args *args, WC_RNG *rng, int curve_id) {
    int ret;
    wc_ecc_init(&args->alice);
    wc_ecc_init(&args->bob);
    ret = wc_ecc_make_key(rng, wc_ecc_get_curve_size_from_id(curve_id),
                          &args->alice);
    if (ret < 0) {
        printf("returned %d\n", ret);
        exit(-1);
    }
    ret = wc_ecc_make_key(rng, wc_ecc_get_curve_size_from_id(curve_id),
                          &args->bob);
    if (ret < 0) {
        printf("returned %d\n", ret);
        exit(-1);
    }
    args->alice.rng = rng;
    args->bob.rng = rng;
    printf("ecdhe (%s) setup complete\n", wc_ecc_get_name(curve_id));
}

#ifdef BENCH_ECDHE_AGREE
static void ecdhe_agree(void *args) {
    struct ecdhe_args *keypair = (struct ecdhe_args *)args;
    byte out[80];
    word32 outlen = 80;
    int ret =
        wc_ecc_shared_secret(&keypair->alice, &keypair->bob, out, &outlen);
    if (ret < 0) {
        printf("wc_ecc_shared_secret returned %d\n", ret);
        exit(-1);
    }
}
#endif
#endif /* BENCH_ECDHE */

#ifdef BENCH_MLKEM
struct mlkem_args {
    WC_RNG *rng;
    PQCleanMlKemKey key;
    byte ct[PQCLEAN_MLKEM_MAX_CIPHERTEXT_SIZE];
    byte ss[PQCLEAN_MLKEM_SS_SIZE];
};

#ifdef BENCH_MLKEM_KEYGEN
static void mlkem512_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    PQCleanMlKemKey key;
    wc_PQCleanMlKemKey_Init(&key);
    wc_PQCleanMlKemKey_SetLevel(&key, 1);
    int ret = wc_PQCleanMlKemKey_MakeKey(&key, rng);
    if (ret < 0) {
        printf("wc_PQCleanMlKemKey_MakeKey returned %d\n", ret);
        exit(-1);
    }
}

static void mlkem768_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    PQCleanMlKemKey key;
    wc_PQCleanMlKemKey_Init(&key);
    wc_PQCleanMlKemKey_SetLevel(&key, 3);
    int ret = wc_PQCleanMlKemKey_MakeKey(&key, rng);
    if (ret < 0) {
        printf("wc_PQCleanMlKemKey_MakeKey returned %d\n", ret);
        exit(-1);
    }
}

static void mlkem1024_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    PQCleanMlKemKey key;
    wc_PQCleanMlKemKey_Init(&key);
    wc_PQCleanMlKemKey_SetLevel(&key, 5);
    int ret = wc_PQCleanMlKemKey_MakeKey(&key, rng);
    if (ret < 0) {
        printf("wc_PQCleanMlKemKey_MakeKey returned %d\n", ret);
        exit(-1);
    }
}
#endif /* BENCH_MLKEM_KEYGEN */

static void mlkem_setup(struct mlkem_args *args, int level, WC_RNG *rng) {
    int ret;
    ret = wc_PQCleanMlKemKey_Init(&args->key);
    if (ret < 0) {
        printf("wc_PQCleanMlKemKey_Init returned %d\n", ret);
        exit(-1);
    }
    ret = wc_PQCleanMlKemKey_SetLevel(&args->key, level);
    if (ret < 0) {
        printf("wc_PQCleanMlKemKey_SetLevel returned %d\n", ret);
        exit(-1);
    }
    ret = wc_PQCleanMlKemKey_MakeKey(&args->key, rng);
    if (ret < 0) {
        printf("wc_PQCleanMlKemKey_MakeKey returned %d\n", ret);
        exit(-1);
    }
    ret = wc_PQCleanMlKemKey_Encapsulate(&args->key, args->ct, args->ss, rng);
    if (ret < 0) {
        printf("wc_PQCleanMlKemKey_Encapsulate returned %d\n", ret);
        exit(-1);
    }
    args->rng = rng;
    printf("mlkem (level=%d) setup complete\n", level);
}

#ifdef BENCH_MLKEM_ENCAP
static void mlkem_encap(void *_args) {
    struct mlkem_args *args = (struct mlkem_args *)_args;
    int ret;
    byte ct[PQCLEAN_MLKEM_MAX_CIPHERTEXT_SIZE];
    byte ss[PQCLEAN_MLKEM_SS_SIZE];
    ret = wc_PQCleanMlKemKey_Encapsulate(&args->key, ct, ss, args->rng);
    if (ret < 0) {
        printf("wc_PQCleanMlKemKey_Encapsulate returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_MLKEM_DECAP
static void mlkem_decap(void *_args) {
    struct mlkem_args *args = (struct mlkem_args *)_args;
    int ret;
    byte ss_cmp[PQCLEAN_MLKEM_SS_SIZE];
    word32 ctLen;
    ret = wc_PQCleanMlKemKey_CipherTextSize(&args->key, &ctLen);
    if (ret < 0) {
        printf("wc_PQCleanMlKemKey_CipherTextSize returned %d\n", ret);
        exit(-1);
    }
    ret = wc_PQCleanMlKemKey_Decapsulate(&args->key, ss_cmp, args->ct, ctLen);
    if (ret < 0) {
        printf("wc_PQCleanMlKemKey_Decapsulate returned %d\n", ret);
        exit(-1);
    }
    if (memcmp(args->ss, ss_cmp, sizeof(ss_cmp)) != 0) {
        printf("ML-KEM decap incorrect\n");
        exit(-1);
    }
}
#endif
#endif /* BENCH_MLKEM */

#ifdef BENCH_HQC
struct hqc_args {
    WC_RNG *rng;
    HqcKey key;
    byte ct[PQCLEAN_HQC_MAX_CIPHERTEXT_SIZE];
    byte ss[PQCLEAN_HQC_MAX_SHAREDSECRET_SIZE];
};

#ifdef BENCH_HQC_KEYGEN
static void hqc128_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    HqcKey key;
    wc_HqcKey_Init(&key);
    wc_HqcKey_SetLevel(&key, 1);
    int ret = wc_HqcKey_MakeKey(&key, rng);
    if (ret < 0) {
        printf("wc_HqcKey_MakeKey returned %d\n", ret);
        exit(-1);
    }
}

static void hqc192_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    HqcKey key;
    wc_HqcKey_Init(&key);
    wc_HqcKey_SetLevel(&key, 3);
    int ret = wc_HqcKey_MakeKey(&key, rng);
    if (ret < 0) {
        printf("wc_HqcKey_MakeKey returned %d\n", ret);
        exit(-1);
    }
}

static void hqc256_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    HqcKey key;
    wc_HqcKey_Init(&key);
    wc_HqcKey_SetLevel(&key, 5);
    int ret = wc_HqcKey_MakeKey(&key, rng);
    if (ret < 0) {
        printf("wc_HqcKey_MakeKey returned %d\n", ret);
        exit(-1);
    }
}
#endif /* BENCH_HQC_KEYGEN */

static void hqc_setup(struct hqc_args *args, int level, WC_RNG *rng) {
    int ret;
    ret = wc_HqcKey_Init(&args->key);
    if (ret < 0) {
        printf("wc_HqcKey_Init returned %d\n", ret);
        exit(-1);
    }
    ret = wc_HqcKey_SetLevel(&args->key, level);
    if (ret < 0) {
        printf("wc_HqcKey_SetLevel returned %d\n", ret);
        exit(-1);
    }
    ret = wc_HqcKey_MakeKey(&args->key, rng);
    if (ret < 0) {
        printf("wc_HqcKey_MakeKey returned %d\n", ret);
        exit(-1);
    }
    ret = wc_HqcKey_Encapsulate(&args->key, args->ct, args->ss, rng);
    if (ret < 0) {
        printf("wc_HqcKey_Encapsulate returned %d\n", ret);
        exit(-1);
    }
    args->rng = rng;
    printf("hqc (level=%d) setup complete\n", level);
}

#ifdef BENCH_HQC_ENCAP
static void hqc_encap(void *_args) {
    struct hqc_args *args = (struct hqc_args *)_args;
    int ret;
    byte ct[PQCLEAN_HQC_MAX_CIPHERTEXT_SIZE];
    byte ss[PQCLEAN_HQC_MAX_SHAREDSECRET_SIZE];
    ret = wc_HqcKey_Encapsulate(&args->key, ct, ss, args->rng);
    if (ret < 0) {
        printf("wc_HqcKey_Encapsulate returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_HQC_DECAP
static void hqc_decap(void *_args) {
    struct hqc_args *args = (struct hqc_args *)_args;
    int ret;
    byte ss_cmp[PQCLEAN_HQC_MAX_SHAREDSECRET_SIZE];
    word32 ctLen;
    ret = wc_HqcKey_CipherTextSize(&args->key, &ctLen);
    if (ret < 0) {
        printf("wc_HqcKey_CipherTextSize returned %d\n", ret);
        exit(-1);
    }
    ret = wc_HqcKey_Decapsulate(&args->key, ss_cmp, args->ct, ctLen);
    if (ret < 0) {
        printf("wc_HqcKey_Decapsulate returned %d\n", ret);
        exit(-1);
    }
    if (memcmp(args->ss, ss_cmp, sizeof(ss_cmp)) != 0) {
        printf("ML-KEM decap incorrect\n");
        exit(-1);
    }
}
#endif
#endif /* BENCH_HQC */

#ifdef BENCH_MLKEM
struct otmlkem_args {
    WC_RNG *rng;
    OtMlKemKey key;
    byte ct[PQCLEAN_OTMLKEM_MAX_CIPHERTEXT_SIZE];
    byte ss[PQCLEAN_OTMLKEM_MAX_SHAREDSECRET_SIZE];
};

#ifdef BENCH_MLKEM_KEYGEN
static void otmlkem512_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    OtMlKemKey key;
    wc_OtMlKemKey_Init(&key);
    wc_OtMlKemKey_SetLevel(&key, 1);
    int ret = wc_OtMlKemKey_MakeKey(&key, rng);
    if (ret < 0) {
        printf("wc_OtMlKemKey_MakeKey returned %d\n", ret);
        exit(-1);
    }
}

static void otmlkem768_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    OtMlKemKey key;
    wc_OtMlKemKey_Init(&key);
    wc_OtMlKemKey_SetLevel(&key, 3);
    int ret = wc_OtMlKemKey_MakeKey(&key, rng);
    if (ret < 0) {
        printf("wc_OtMlKemKey_MakeKey returned %d\n", ret);
        exit(-1);
    }
}

static void otmlkem1024_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    OtMlKemKey key;
    wc_OtMlKemKey_Init(&key);
    wc_OtMlKemKey_SetLevel(&key, 5);
    int ret = wc_OtMlKemKey_MakeKey(&key, rng);
    if (ret < 0) {
        printf("wc_OtMlKemKey_MakeKey returned %d\n", ret);
        exit(-1);
    }
}
#endif /* BENCH_MLKEM_KEYGEN */

static void otmlkem_setup(struct otmlkem_args *args, int level, WC_RNG *rng) {
    int ret;
    ret = wc_OtMlKemKey_Init(&args->key);
    if (ret < 0) {
        printf("wc_OtMlKemKey_Init returned %d\n", ret);
        exit(-1);
    }
    ret = wc_OtMlKemKey_SetLevel(&args->key, level);
    if (ret < 0) {
        printf("wc_OtMlKemKey_SetLevel returned %d\n", ret);
        exit(-1);
    }
    ret = wc_OtMlKemKey_MakeKey(&args->key, rng);
    if (ret < 0) {
        printf("wc_OtMlKemKey_MakeKey returned %d\n", ret);
        exit(-1);
    }
    ret = wc_OtMlKemKey_Encapsulate(&args->key, args->ct, args->ss, rng);
    if (ret < 0) {
        printf("wc_OtMlKemKey_Encapsulate returned %d\n", ret);
        exit(-1);
    }
    args->rng = rng;
    printf("otmlkem (level=%d) setup complete\n", level);
}

#ifdef BENCH_MLKEM_ENCAP
static void otmlkem_encap(void *_args) {
    struct otmlkem_args *args = (struct otmlkem_args *)_args;
    int ret;
    byte ct[PQCLEAN_OTMLKEM_MAX_CIPHERTEXT_SIZE];
    byte ss[PQCLEAN_OTMLKEM_MAX_SHAREDSECRET_SIZE];
    ret = wc_OtMlKemKey_Encapsulate(&args->key, ct, ss, args->rng);
    if (ret < 0) {
        printf("wc_OtMlKemKey_Encapsulate returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_MLKEM_DECAP
static void otmlkem_decap(void *_args) {
    struct otmlkem_args *args = (struct otmlkem_args *)_args;
    int ret;
    byte ss_cmp[PQCLEAN_OTMLKEM_MAX_SHAREDSECRET_SIZE];
    word32 ctLen;
    ret = wc_OtMlKemKey_CipherTextSize(&args->key, &ctLen);
    if (ret < 0) {
        printf("wc_OtMlKemKey_CipherTextSize returned %d\n", ret);
        exit(-1);
    }
    ret = wc_OtMlKemKey_Decapsulate(&args->key, ss_cmp, args->ct, ctLen);
    if (ret < 0) {
        printf("wc_OtMlKemKey_Decapsulate returned %d\n", ret);
        exit(-1);
    }
    if (memcmp(args->ss, ss_cmp, sizeof(ss_cmp)) != 0) {
        printf("ML-KEM decap incorrect\n");
        exit(-1);
    }
}
#endif
#endif /* BENCH_MLKEM */

/* Benchmarking digital signatures
 *
 * For each digital signature schemes we will bench three operations: keygen,
 * sign, verify Keygen can be benched with only the RNG. Benching sign requires
 * a ready-made key, and benching verify requires ready-made key, message, and
 * signature.
 *
 * For benching sign/verify, the message size will be 48 bytes. This is because
 * the highest level TLS 1.3 cipher suite uses SHA384.
 */
#define MSG_SIZE 48

#ifdef BENCH_RSA2048
#ifdef BENCH_RSA2048_KEYGEN
static void rsa2048_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    RsaKey key;
    int ret;

    ret = wc_InitRsaKey(&key, NULL);
    if (ret < 0) {
        printf("wc_InitRsaKey returned %d\n", ret);
        exit(-1);
    }
    ret = wc_MakeRsaKey(&key, RSA_MIN_SIZE, WC_RSA_EXPONENT, rng);
    if (ret < 0) {
        printf("wc_MakeRsaKey returned %d\n", ret);
    }
}
#endif

struct rsa_args {
    WC_RNG *rng;
    RsaKey key;
    byte msg[MSG_SIZE];
    byte sig[RSA_MAX_SIZE / 8];
};

/* Generate keypair, sign a random message */
static void rsa2048_setup(struct rsa_args *args, WC_RNG *rng) {
    int ret;

    if ((ret = wc_InitRsaKey(&args->key, NULL)) < 0) {
        printf("wc_InitRsaKey returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_MakeRsaKey(&args->key, RSA_MIN_SIZE, WC_RSA_EXPONENT, rng)) <
        0) {
        printf("wc_MakeRsaKey returned %d\n", ret);
        exit(-1);
    }

    /* to sign with RsaPSS we first need to hash the message */
    byte digest[32];
    byte pss[RSA_MAX_SIZE / 8];
    if ((ret = wc_RNG_GenerateBlock(rng, args->msg, sizeof(args->msg))) < 0) {
        printf("wc_RNG_GenerateBlock returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_Sha256Hash(args->msg, sizeof(args->msg), digest)) < 0) {
        printf("wc_Sha256Hash returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_RsaPSS_Sign(digest, sizeof(digest), args->sig,
                              sizeof(args->sig), WC_HASH_TYPE_SHA256,
                              WC_MGF1SHA256, &args->key, rng)) < 0) {
        printf("RsaPSS_Sign returned %d\n", ret);
        exit(-1);
    }
    printf("RsaPSS size %d\n", ret);

    if ((ret = wc_RsaPSS_VerifyCheck(args->sig, sizeof(args->sig), pss,
                                     sizeof(pss), digest, sizeof(digest),
                                     WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                                     &args->key)) < 0) {
        printf("RsaPSS_Verify returned %d\n", ret);
        exit(-1);
    }

    args->rng = rng;
    printf("RSA2048 setup complete\n");
}

#ifdef BENCH_RSA2048_SIGN
static void rsa2048_sign(void *_args) {
    struct rsa_args *args = (struct rsa_args *)_args;
    int ret;
    byte digest[32];
    if ((ret = wc_Sha256Hash(args->msg, sizeof(args->msg), digest)) < 0) {
        printf("wc_Sha256Hash returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_RsaPSS_Sign(digest, sizeof(digest), args->sig,
                              sizeof(args->sig), WC_HASH_TYPE_SHA256,
                              WC_MGF1SHA256, &args->key, args->rng)) < 0) {
        printf("RsaPSS_Sign returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_RSA2048_VERIFY
static void rsa2048_verify(void *_args) {
    struct rsa_args *args = (struct rsa_args *)_args;
    int ret;
    byte digest[32], pss[RSA_MAX_SIZE / 8];
    if ((ret = wc_Sha256Hash(args->msg, sizeof(args->msg), digest)) < 0) {
        printf("wc_Sha256Hash returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_RsaPSS_VerifyCheck(args->sig, sizeof(args->sig), pss,
                                     sizeof(pss), digest, sizeof(digest),
                                     WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                                     &args->key)) < 0) {
        printf("RsaPSS_Verify returned %d\n", ret);
        exit(-1);
    }
}
#endif
#endif /* BENCH_RSA2048 */

#ifdef BENCH_ECDSA
/* ECDSA benchmarks */
struct ecdsa_args {
    ecc_key key;
    WC_RNG *rng;
    byte msg[MSG_SIZE];
    byte sig[160];
    word32 siglen;
};

static void ecdsa_setup(struct ecdsa_args *args, WC_RNG *rng, int curve_id) {
    int ret;
    args->siglen = sizeof(args->sig);
    if ((ret = wc_ecc_init(&args->key)) < 0) {
        printf("wc_ecc_init returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_ecc_make_key(rng, wc_ecc_get_curve_size_from_id(curve_id),
                               &args->key)) < 0) {
        printf("wc_ecc_make_key returned %d\n", ret);
        exit(-1);
    }
    wc_RNG_GenerateBlock(rng, args->msg, sizeof(args->msg));

    byte digest[64];
    word32 digestlen = 64;
    switch (curve_id) {
    case ECC_SECP256R1:
        digestlen = 32;
        ret = wc_Sha256Hash(args->msg, sizeof(args->msg), digest);
        break;
    case ECC_SECP384R1:
        digestlen = 48;
        ret = wc_Sha384Hash(args->msg, sizeof(args->msg), digest);
        break;
    case ECC_SECP521R1:
        digestlen = 64;
        ret = wc_Sha512Hash(args->msg, sizeof(args->msg), digest);
        break;
    }
    if (ret < 0) {
        printf("ShaXXXHash returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_ecc_sign_hash(digest, digestlen, args->sig, &args->siglen,
                                rng, &args->key)) < 0) {
        printf("wc_ecc_sign_hash returned %d\n", ret);
        exit(-1);
    }
    printf("ecc siglen=%d\n", args->siglen);

    int verified;
    if ((ret = wc_ecc_verify_hash(args->sig, args->siglen, digest, digestlen,
                                  &verified, &args->key)) < 0) {
        printf("wc_ecc_verify_hash returned %d\n", ret);
        exit(-1);
    }
    if (!verified) {
        printf("invalid ecc sig\n");
        exit(-1);
    }

    args->rng = rng;
    printf("ECDSA (%s) setup complete\n", wc_ecc_get_name(curve_id));
}

#ifdef BENCH_ECDSA_KEYGEN
/* does not mutate the args, only read the curve_id and use the RNG */
static void ecdsa_keygen(void *_args) {
    struct ecdsa_args *args = (struct ecdsa_args *)_args;
    ecc_key key;
    int ret;
    int curve_id = args->key.dp->id;

    if ((ret = wc_ecc_init(&key)) < 0) {
        printf("wc_ecc_init returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_ecc_make_key(
             args->rng, wc_ecc_get_curve_size_from_id(curve_id), &key)) < 0) {
        printf("wc_ecc_make_key returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_ECDSA_SIGN
static void ecdsa_sign(void *_args) {
    struct ecdsa_args *args = (struct ecdsa_args *)_args;
    int ret;
    byte digest[64], sig[160];
    word32 digestlen = 64;
    word32 siglen = 160;

    switch (args->key.dp->id) {
    case ECC_SECP256R1:
        digestlen = 32;
        ret = wc_Sha256Hash(args->msg, sizeof(args->msg), digest);
        break;
    case ECC_SECP384R1:
        digestlen = 48;
        ret = wc_Sha384Hash(args->msg, sizeof(args->msg), digest);
        break;
    case ECC_SECP521R1:
        digestlen = 64;
        ret = wc_Sha512Hash(args->msg, sizeof(args->msg), digest);
        break;
    }
    if (ret < 0) {
        printf("ShaXXXHash returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_ecc_sign_hash(digest, digestlen, sig, &siglen, args->rng,
                                &args->key)) < 0) {
        printf("wc_ecc_sign_hash returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_ECDSA_VERIFY
static void ecdsa_verify(void *_args) {
    struct ecdsa_args *args = (struct ecdsa_args *)_args;
    int ret, verified;
    byte digest[64];
    word32 digestlen;

    switch (args->key.dp->id) {
    case ECC_SECP256R1:
        digestlen = 32;
        ret = wc_Sha256Hash(args->msg, sizeof(args->msg), digest);
        break;
    case ECC_SECP384R1:
        digestlen = 48;
        ret = wc_Sha384Hash(args->msg, sizeof(args->msg), digest);
        break;
    case ECC_SECP521R1:
        digestlen = 64;
        ret = wc_Sha512Hash(args->msg, sizeof(args->msg), digest);
        break;
    }
    if ((ret = wc_ecc_verify_hash(args->sig, args->siglen, digest, digestlen,
                                  &verified, &args->key)) < 0) {
        printf("wc_ecc_verify_hash returned %d\n", ret);
        exit(-1);
    }
    if (!verified) {
        printf("invalid ecc sig\n");
        exit(-1);
    }
}
#endif
#endif /* BENCH_ECDSA */

#ifdef BENCH_ED25519
/* benchmarking Ed25519 */
typedef struct ed25519_args {
    ed25519_key key;
    WC_RNG *rng;
    byte msg[MSG_SIZE];
    byte sig[ED25519_SIG_SIZE];
    word32 siglen;
} ed25519_args_t;

static void ed25519_setup(struct ed25519_args *args, WC_RNG *rng) {
    int ret, verified;
    args->siglen = ED25519_SIG_SIZE;

    if ((ret = wc_ed25519_init(&args->key)) < 0) {
        printf("wc_ed25519_init returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &args->key)) < 0) {
        printf("wc_ed25519_make_key returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_RNG_GenerateBlock(rng, args->msg, sizeof(args->msg))) < 0) {
        printf("Failed to sample random message\n");
        exit(-1);
    }

    if ((ret = wc_ed25519_sign_msg(args->msg, sizeof(args->msg), args->sig,
                                   &args->siglen, &args->key)) < 0) {
        printf("wc_ed25519_sign_msg returned %d\n", ret);
        exit(-1);
    }

    if ((ret = wc_ed25519_verify_msg(args->sig, args->siglen, args->msg,
                                     sizeof(args->msg), &verified,
                                     &args->key)) < 0) {
        printf("wc_ed25519_verify_msg returned %d\n", ret);
        exit(-1);
    }
    if (!verified) {
        printf("ed25519 signature invalid\n");
        exit(-1);
    }

    args->rng = rng;
    printf("ed25519 setup complete\n");
}

#ifdef BENCH_ED25519_KEYGEN
static void ed25519_keygen(void *_args) {
    struct ed25519_args *args = (struct ed25519_args *)_args;
    int ret;

    ed25519_key key;
    if ((ret = wc_ed25519_init(&key)) < 0) {
        printf("wc_ed25519_init returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_ed25519_make_key(args->rng, ED25519_KEY_SIZE, &key)) < 0) {
        printf("wc_ed25519_make_key returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_ED25519_SIGN
static void ed25519_sign(void *_args) {
    struct ed25519_args *args = (struct ed25519_args *)_args;
    int ret;
    byte sig[ED25519_SIG_SIZE];
    word32 siglen = sizeof(sig);

    if ((ret = wc_ed25519_sign_msg(args->msg, sizeof(args->msg), sig, &siglen,
                                   &args->key)) < 0) {
        printf("wc_ed25519_sign_msg returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_ED25519_VERIFY
static void ed25519_verify(void *_args) {
    struct ed25519_args *args = (struct ed25519_args *)_args;
    int ret, verified;

    if ((ret = wc_ed25519_verify_msg(args->sig, args->siglen, args->msg,
                                     sizeof(args->msg), &verified,
                                     &args->key)) < 0) {
        printf("wc_ed25519_verify_msg returned %d\n", ret);
        exit(-1);
    }
    if (!verified) {
        printf("ed25519 signature invalid\n");
        exit(-1);
    }
}
#endif
#endif /* BENCH_ED25519 */

#ifdef BENCH_ED448
/* benchmarking Ed448 */
typedef struct ed448_args {
    ed448_key key;
    WC_RNG *rng;
    byte msg[MSG_SIZE];
    byte sig[ED448_SIG_SIZE];
    word32 siglen;
} ed448_args_t;

static void ed448_setup(struct ed448_args *args, WC_RNG *rng) {
    int ret, verified;
    args->siglen = ED448_SIG_SIZE;

    if ((ret = wc_ed448_init(&args->key)) < 0) {
        printf("wc_ed448_init returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_ed448_make_key(rng, ED448_KEY_SIZE, &args->key)) < 0) {
        printf("wc_ed448_make_key returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_RNG_GenerateBlock(rng, args->msg, sizeof(args->msg))) < 0) {
        printf("Failed to sample random message\n");
        exit(-1);
    }

    if ((ret = wc_ed448_sign_msg(args->msg, sizeof(args->msg), args->sig,
                                 &args->siglen, &args->key, NULL, 0)) < 0) {
        printf("wc_ed448_sign_msg returned %d\n", ret);
        exit(-1);
    }

    if ((ret = wc_ed448_verify_msg(args->sig, args->siglen, args->msg,
                                   sizeof(args->msg), &verified, &args->key,
                                   NULL, 0)) < 0) {
        printf("wc_ed448_verify_msg returned %d\n", ret);
        exit(-1);
    }
    if (!verified) {
        printf("ed448 signature invalid\n");
        exit(-1);
    }

    args->rng = rng;
    printf("ed448 setup complete\n");
}

#ifdef BENCH_ED448_KEYGEN
static void ed448_keygen(void *_args) {
    struct ed448_args *args = (struct ed448_args *)_args;
    int ret;

    ed448_key key;
    if ((ret = wc_ed448_init(&key)) < 0) {
        printf("wc_ed448_init returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_ed448_make_key(args->rng, ED448_KEY_SIZE, &key)) < 0) {
        printf("wc_ed448_make_key returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_ED448_SIGN
static void ed448_sign(void *_args) {
    struct ed448_args *args = (struct ed448_args *)_args;
    int ret;
    byte sig[ED448_SIG_SIZE];
    word32 siglen = sizeof(sig);

    if ((ret = wc_ed448_sign_msg(args->msg, sizeof(args->msg), sig, &siglen,
                                 &args->key, NULL, 0)) < 0) {
        printf("wc_ed448_sign_msg returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_ED448_VERIFY
static void ed448_verify(void *_args) {
    struct ed448_args *args = (struct ed448_args *)_args;
    int ret, verified;

    if ((ret = wc_ed448_verify_msg(args->sig, args->siglen, args->msg,
                                   sizeof(args->msg), &verified, &args->key,
                                   NULL, 0)) < 0) {
        printf("wc_ed448_verify_msg returned %d\n", ret);
        exit(-1);
    }
    if (!verified) {
        printf("ed448 signature invalid\n");
        exit(-1);
    }
}
#endif
#endif /* BENCH_ED448 */

#ifdef BENCH_DILITHIUM
/* benchmarking dilithium */
typedef struct dilithium_args {
    dilithium_key key;
    WC_RNG *rng;
    byte msg[MSG_SIZE];
    byte sig[DILITHIUM_MAX_SIG_SIZE];
    word32 siglen;
} dilithium_args_t;

static void dilithium_setup(struct dilithium_args *args, WC_RNG *rng,
                            int level) {
    int ret, verified;
    args->siglen = sizeof(args->sig);

    if ((ret = wc_dilithium_init(&args->key)) < 0) {
        printf("wc_dilithium_init returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_dilithium_set_level(&args->key, level)) < 0) {
        printf("wc_dilithium_set_level returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_dilithium_make_key(&args->key, rng)) < 0) {
        printf("wc_dilithium_make_key returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_RNG_GenerateBlock(rng, args->msg, sizeof(args->msg))) < 0) {
        printf("Failed to sample random message\n");
        exit(-1);
    }

    if ((ret = wc_dilithium_sign_msg(args->msg, sizeof(args->msg), args->sig,
                                     &args->siglen, &args->key, rng)) < 0) {
        printf("wc_dilithium_sign_msg returned %d\n", ret);
        exit(-1);
    }

    if ((ret = wc_dilithium_verify_msg(args->sig, args->siglen, args->msg,
                                       sizeof(args->msg), &verified,
                                       &args->key)) < 0) {
        printf("wc_dilithium_verify_msg returned %d\n", ret);
        exit(-1);
    }
    if (!verified) {
        printf("dilithium signature invalid\n");
        exit(-1);
    }

    args->rng = rng;
    printf("dilithium setup complete\n");
}

#ifdef BENCH_DILITHIUM_KEYGEN
static void dilithium_keygen(void *_args) {
    struct dilithium_args *args = (struct dilithium_args *)_args;
    int ret;

    dilithium_key key;
    if ((ret = wc_dilithium_init(&key)) < 0) {
        printf("wc_dilithium_init returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_dilithium_set_level(&key, args->key.level)) < 0) {
        printf("wc_dilithium_set_level returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_dilithium_make_key(&key, args->rng)) < 0) {
        printf("wc_dilithium_make_key returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_DILITHIUM_SIGN
static void dilithium_sign(void *_args) {
    struct dilithium_args *args = (struct dilithium_args *)_args;
    int ret;
    byte sig[DILITHIUM_MAX_SIG_SIZE];
    word32 siglen = sizeof(sig);

    if ((ret = wc_dilithium_sign_msg(args->msg, sizeof(args->msg), sig, &siglen,
                                     &args->key, args->rng)) < 0) {
        printf("wc_dilithium_sign_msg returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_DILITHIUM_VERIFY
static void dilithium_verify(void *_args) {
    struct dilithium_args *args = (struct dilithium_args *)_args;
    int ret, verified;

    if ((ret = wc_dilithium_verify_msg(args->sig, args->siglen, args->msg,
                                       sizeof(args->msg), &verified,
                                       &args->key)) < 0) {
        printf("wc_dilithium_verify_msg returned %d\n", ret);
        exit(-1);
    }
    if (!verified) {
        printf("dilithium signature invalid\n");
        exit(-1);
    }
}
#endif
#endif /* BENCH_DILITHIUM */

#ifdef BENCH_FALCON
/* benchmarking falcon */
typedef struct falcon_args {
    falcon_key key;
    WC_RNG *rng;
    byte msg[MSG_SIZE];
    byte sig[FALCON_LEVEL5_SIG_SIZE];
    word32 siglen;
} falcon_args_t;

static void falcon_setup(struct falcon_args *args, WC_RNG *rng, int level) {
    int ret, verified;
    args->siglen = sizeof(args->sig);

    if ((ret = wc_falcon_init(&args->key)) < 0) {
        printf("wc_falcon_init returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_falcon_set_level(&args->key, level)) < 0) {
        printf("wc_falcon_set_level returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_falcon_make_key(&args->key, rng)) < 0) {
        printf("wc_falcon_make_key returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_RNG_GenerateBlock(rng, args->msg, sizeof(args->msg))) < 0) {
        printf("Failed to sample random message\n");
        exit(-1);
    }

    if ((ret = wc_falcon_sign_msg(args->msg, sizeof(args->msg), args->sig,
                                  &args->siglen, &args->key, rng)) < 0) {
        printf("wc_falcon_sign_msg returned %d\n", ret);
        exit(-1);
    }

    if ((ret = wc_falcon_verify_msg(args->sig, args->siglen, args->msg,
                                    sizeof(args->msg), &verified, &args->key)) <
        0) {
        printf("wc_falcon_verify_msg returned %d\n", ret);
        exit(-1);
    }
    if (!verified) {
        printf("falcon signature invalid\n");
        exit(-1);
    }

    args->rng = rng;
    printf("falcon setup complete\n");
}

#ifdef BENCH_FALCON_KEYGEN
static void falcon_keygen(void *_args) {
    struct falcon_args *args = (struct falcon_args *)_args;
    int ret;

    falcon_key key;
    if ((ret = wc_falcon_init(&key)) < 0) {
        printf("wc_falcon_init returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_falcon_set_level(&key, args->key.level)) < 0) {
        printf("wc_falcon_set_level returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_falcon_make_key(&key, args->rng)) < 0) {
        printf("wc_falcon_make_key returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_FALCON_SIGN
static void falcon_sign(void *_args) {
    struct falcon_args *args = (struct falcon_args *)_args;
    int ret;
    byte sig[FALCON_LEVEL5_SIG_SIZE];
    word32 siglen = sizeof(sig);

    if ((ret = wc_falcon_sign_msg(args->msg, sizeof(args->msg), sig, &siglen,
                                  &args->key, args->rng)) < 0) {
        printf("wc_falcon_sign_msg returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_FALCON_VERIFY
static void falcon_verify(void *_args) {
    struct falcon_args *args = (struct falcon_args *)_args;
    int ret, verified;

    if ((ret = wc_falcon_verify_msg(args->sig, args->siglen, args->msg,
                                    sizeof(args->msg), &verified, &args->key)) <
        0) {
        printf("wc_falcon_verify_msg returned %d\n", ret);
        exit(-1);
    }
    if (!verified) {
        printf("falcon signature invalid\n");
        exit(-1);
    }
}
#endif
#endif /* BENCH_FALCON */

#ifdef BENCH_SPHINCS
/* benchmarking sphincs */
typedef struct sphincs_args {
    sphincs_key key;
    WC_RNG *rng;
    byte msg[MSG_SIZE];
    byte sig[SPHINCS_MAX_SIG_SIZE];
    word32 siglen;
} sphincs_args_t;

static void sphincs_setup(struct sphincs_args *args, WC_RNG *rng, int level,
                          int optim) {
    int ret, verified;
    args->siglen = sizeof(args->sig);

    if ((ret = wc_sphincs_init(&args->key)) < 0) {
        printf("wc_sphincs_init returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_sphincs_set_level_and_optim(&args->key, level, optim)) < 0) {
        printf("wc_sphincs_set_level returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_sphincs_make_key(&args->key, rng)) < 0) {
        printf("wc_sphincs_make_key returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_RNG_GenerateBlock(rng, args->msg, sizeof(args->msg))) < 0) {
        printf("Failed to sample random message\n");
        exit(-1);
    }

    if ((ret = wc_sphincs_sign_msg(args->msg, sizeof(args->msg), args->sig,
                                   &args->siglen, &args->key, rng)) < 0) {
        printf("wc_sphincs_sign_msg returned %d\n", ret);
        exit(-1);
    }

    if ((ret = wc_sphincs_verify_msg(args->sig, args->siglen, args->msg,
                                     sizeof(args->msg), &verified,
                                     &args->key)) < 0) {
        printf("wc_sphincs_verify_msg returned %d\n", ret);
        exit(-1);
    }
    if (!verified) {
        printf("sphincs signature invalid\n");
        exit(-1);
    }

    args->rng = rng;
    printf("sphincs setup complete\n");
}

#ifdef BENCH_SPHINCS_KEYGEN
static void sphincs_keygen(void *_args) {
    struct sphincs_args *args = (struct sphincs_args *)_args;
    int ret;

    sphincs_key key;
    if ((ret = wc_sphincs_init(&key)) < 0) {
        printf("wc_sphincs_init returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_sphincs_set_level_and_optim(&key, args->key.level,
                                              args->key.optim)) < 0) {
        printf("wc_sphincs_set_level returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_sphincs_make_key(&key, args->rng)) < 0) {
        printf("wc_sphincs_make_key returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_SPHINCS_SIGN
static void sphincs_sign(void *_args) {
    struct sphincs_args *args = (struct sphincs_args *)_args;
    int ret;
    byte sig[SPHINCS_MAX_SIG_SIZE];
    word32 siglen = sizeof(sig);

    if ((ret = wc_sphincs_sign_msg(args->msg, sizeof(args->msg), sig, &siglen,
                                   &args->key, args->rng)) < 0) {
        printf("wc_sphincs_sign_msg returned %d\n", ret);
        exit(-1);
    }
}
#endif

#ifdef BENCH_SPHINCS_VERIFY
static void sphincs_verify(void *_args) {
    struct sphincs_args *args = (struct sphincs_args *)_args;
    int ret, verified;

    if ((ret = wc_sphincs_verify_msg(args->sig, args->siglen, args->msg,
                                     sizeof(args->msg), &verified,
                                     &args->key)) < 0) {
        printf("wc_sphincs_verify_msg returned %d\n", ret);
        exit(-1);
    }
    if (!verified) {
        printf("sphincs signature invalid\n");
        exit(-1);
    }
}
#endif
#endif /* BENCH_SPHINCS */

int main(void) {
    wolfSSL_Init();
    // wolfSSL_Debugging_ON();
    WC_RNG rng;
    wc_InitRng(&rng);
    printf("Initialized RNG\n");

    uint32_t durs[BENCH_ROUNDS];
    size_t len = BENCH_ROUNDS;

    /* setup */
#ifdef BENCH_SPHINCS
    sphincs_args_t sphincs_args;
#endif
#ifdef BENCH_FALCON
    falcon_args_t falcon512_args, falcon1024_args;
    falcon_setup(&falcon512_args, &rng, 1);
    falcon_setup(&falcon1024_args, &rng, 5);
#endif
#ifdef BENCH_DILITHIUM
    dilithium_args_t mldsa44_args, mldsa65_args, mldsa87_args;
    dilithium_setup(&mldsa44_args, &rng, 2);
    dilithium_setup(&mldsa65_args, &rng, 3);
    dilithium_setup(&mldsa87_args, &rng, 5);
#endif
#ifdef BENCH_ED448
    ed448_args_t ed448_args;
    ed448_setup(&ed448_args, &rng);
#endif
#ifdef BENCH_ED25519
    ed25519_args_t ed25519_args;
    ed25519_setup(&ed25519_args, &rng);
#endif
#ifdef BENCH_ECDSA
    struct ecdsa_args ecdsa256_args, ecdsa384_args, ecdsa521_args;
    ecdsa_setup(&ecdsa256_args, &rng, ECC_SECP256R1);
    ecdsa_setup(&ecdsa384_args, &rng, ECC_SECP384R1);
    ecdsa_setup(&ecdsa521_args, &rng, ECC_SECP521R1);
#endif

#ifdef BENCH_X25519
    struct x25519_args x25519_agree_args;
    x25519_setup(&x25519_agree_args, &rng);
#endif

#ifdef BENCH_X448
    struct x448_args x448_agree_args;
    x448_setup(&x448_agree_args, &rng);
#endif

#ifdef BENCH_ECDHE
    struct ecdhe_args ecdhe256_args, ecdhe384_args, ecdhe521_args;
    ecdhe_setup(&ecdhe256_args, &rng, ECC_SECP256R1);
    ecdhe_setup(&ecdhe384_args, &rng, ECC_SECP384R1);
    ecdhe_setup(&ecdhe521_args, &rng, ECC_SECP521R1);
#endif

#ifdef BENCH_MLKEM
    struct mlkem_args mlkem512_args, mlkem768_args, mlkem1024_args;
    mlkem_setup(&mlkem512_args, 1, &rng);
    mlkem_setup(&mlkem768_args, 3, &rng);
    mlkem_setup(&mlkem1024_args, 5, &rng);
#endif

#ifdef BENCH_HQC
    struct hqc_args hqc128_args, hqc192_args, hqc256_args;
    hqc_setup(&hqc128_args, 1, &rng);
    hqc_setup(&hqc192_args, 3, &rng);
    hqc_setup(&hqc256_args, 5, &rng);
#endif

#ifdef BENCH_MLKEM
    struct otmlkem_args otmlkem512_args, otmlkem768_args, otmlkem1024_args;
    otmlkem_setup(&otmlkem512_args, 1, &rng);
    otmlkem_setup(&otmlkem768_args, 3, &rng);
    otmlkem_setup(&otmlkem1024_args, 5, &rng);
#endif

#ifdef BENCH_RSA2048
    struct rsa_args rsa2048_args;
    rsa2048_setup(&rsa2048_args, &rng);
#endif

    printf("name,op,median,p90,p99\n");
    while (1) {
#ifdef BENCH_FALCON
#ifdef BENCH_FALCON_KEYGEN
        bench_black_box(falcon_keygen, &falcon512_args, durs, len);
        print_results(durs, len, "Falcon-512,keygen");
        bench_black_box(falcon_keygen, &falcon1024_args, durs, len);
        print_results(durs, len, "Falcon-1024,keygen");
#endif
#ifdef BENCH_FALCON_SIGN
        bench_black_box(falcon_sign, &falcon512_args, durs, len);
        print_results(durs, len, "Falcon-512,sign");
        bench_black_box(falcon_sign, &falcon1024_args, durs, len);
        print_results(durs, len, "Falcon-1024,sign");
#endif
#ifdef BENCH_FALCON_VERIFY
        bench_black_box(falcon_verify, &falcon512_args, durs, len);
        print_results(durs, len, "Falcon-512,verify");
        bench_black_box(falcon_verify, &falcon1024_args, durs, len);
        print_results(durs, len, "Falcon-1024,verify");
#endif
#endif

#ifdef BENCH_DILITHIUM
#ifdef BENCH_DILITHIUM_KEYGEN
        bench_black_box(dilithium_keygen, &mldsa44_args, durs, len);
        print_results(durs, len, "ML-DSA-44,keygen");
        bench_black_box(dilithium_keygen, &mldsa65_args, durs, len);
        print_results(durs, len, "ML-DSA-65,keygen");
        bench_black_box(dilithium_keygen, &mldsa87_args, durs, len);
        print_results(durs, len, "ML-DSA-87,keygen");
#endif
#ifdef BENCH_DILITHIUM_SIGN
        bench_black_box(dilithium_sign, &mldsa44_args, durs, len);
        print_results(durs, len, "ML-DSA-44,sign");
        bench_black_box(dilithium_sign, &mldsa65_args, durs, len);
        print_results(durs, len, "ML-DSA-65,sign");
        bench_black_box(dilithium_sign, &mldsa87_args, durs, len);
        print_results(durs, len, "ML-DSA-87,sign");
#endif
#ifdef BENCH_DILITHIUM_VERIFY
        bench_black_box(dilithium_verify, &mldsa44_args, durs, len);
        print_results(durs, len, "ML-DSA-44,verify");
        bench_black_box(dilithium_verify, &mldsa65_args, durs, len);
        print_results(durs, len, "ML-DSA-65,verify");
        bench_black_box(dilithium_verify, &mldsa87_args, durs, len);
        print_results(durs, len, "ML-DSA-87,verify");
#endif
#endif

#ifdef BENCH_ED448
#ifdef BENCH_ED448_KEYGEN
        bench_black_box(ed448_keygen, &ed448_args, durs, len);
        print_results(durs, len, "ed448,keygen");
#endif
#ifdef BENCH_ED448_SIGN
        bench_black_box(ed448_sign, &ed448_args, durs, len);
        print_results(durs, len, "ed448,sign");
#endif
#ifdef BENCH_ED448_VERIFY
        bench_black_box(ed448_verify, &ed448_args, durs, len);
        print_results(durs, len, "ed448,verify");
#endif
#endif

#ifdef BENCH_ED25519
#ifdef BENCH_ED25519_KEYGEN
        bench_black_box(ed25519_keygen, &ed25519_args, durs, len);
        print_results(durs, len, "ed25519,keygen");
#endif
#ifdef BENCH_ED25519_SIGN
        bench_black_box(ed25519_sign, &ed25519_args, durs, len);
        print_results(durs, len, "ed25519,sign");
#endif
#ifdef BENCH_ED25519_VERIFY
        bench_black_box(ed25519_verify, &ed25519_args, durs, len);
        print_results(durs, len, "ed25519,verify");
#endif
#endif

#ifdef BENCH_ECDSA
#ifdef BENCH_ECDSA_KEYGEN
        bench_black_box(ecdsa_keygen, &ecdsa256_args, durs, len);
        print_results(durs, len, "sha256ecdsa,keygen");
        bench_black_box(ecdsa_keygen, &ecdsa384_args, durs, len);
        print_results(durs, len, "sha384ecdsa,keygen");
        bench_black_box(ecdsa_keygen, &ecdsa521_args, durs, len);
        print_results(durs, len, "sha521ecdsa,keygen");
#endif
#ifdef BENCH_ECDSA_SIGN
        bench_black_box(ecdsa_sign, &ecdsa256_args, durs, len);
        print_results(durs, len, "sha256ecdsa,sign");
        bench_black_box(ecdsa_sign, &ecdsa384_args, durs, len);
        print_results(durs, len, "sha384ecdsa,sign");
        bench_black_box(ecdsa_sign, &ecdsa521_args, durs, len);
        print_results(durs, len, "sha521ecdsa,sign");
#endif
#ifdef BENCH_ECDSA_VERIFY
        bench_black_box(ecdsa_verify, &ecdsa256_args, durs, len);
        print_results(durs, len, "sha256ecdsa,verify");
        bench_black_box(ecdsa_verify, &ecdsa384_args, durs, len);
        print_results(durs, len, "sha384ecdsa,verify");
        bench_black_box(ecdsa_verify, &ecdsa521_args, durs, len);
        print_results(durs, len, "sha521ecdsa,verify");
#endif
#endif

#ifdef BENCH_RSA2048
#ifdef BENCH_RSA2048_KEYGEN
        bench_black_box(rsa2048_keygen, &rng, durs, len);
        print_results(durs, len, "RSA-2048,keygen");
#endif
#ifdef BENCH_RSA2048_SIGN
        bench_black_box(rsa2048_sign, &rsa2048_args, durs, len);
        print_results(durs, len, "RSA-2048,sign");
#endif
#ifdef BENCH_RSA2048_VERIFY
        bench_black_box(rsa2048_verify, &rsa2048_args, durs, len);
        print_results(durs, len, "RSA-2048,verify");
#endif
#endif

#ifdef BENCH_X25519
#ifdef BENCH_X25519_KEYGEN
        bench_black_box(x25519_keygen, &rng, durs, len);
        print_results(durs, len, "x25519,keygen");
#endif
#ifdef BENCH_X25519_AGREE
        bench_black_box(x25519_agree, &x25519_agree_args, durs, len);
        print_results(durs, len, "x25519,agree");
#endif
#endif

#ifdef BENCH_X448
#ifdef BENCH_X448_KEYGEN
        bench_black_box(x448_keygen, &rng, durs, len);
        print_results(durs, len, "x448,keygen");
#endif
#ifdef BENCH_X448_AGREE
        bench_black_box(x448_agree, &x448_agree_args, durs, len);
        print_results(durs, len, "x448,agree");
#endif
#endif

#ifdef BENCH_ECDHE
#ifdef BENCH_ECDHE_KEYGEN
        bench_black_box(ecdhe256_keygen, &rng, durs, len);
        print_results(durs, len, "ECDHE (P-256),keygen");
        bench_black_box(ecdhe384_keygen, &rng, durs, len);
        print_results(durs, len, "ECDHE (P-384),keygen");
        bench_black_box(ecdhe521_keygen, &rng, durs, len);
        print_results(durs, len, "ECDHE (P-521),keygen");
#endif
#ifdef BENCH_ECDHE_AGREE
        bench_black_box(ecdhe_agree, &ecdhe256_args, durs, len);
        print_results(durs, len, "ECDHE (P-256),agree");
        bench_black_box(ecdhe_agree, &ecdhe384_args, durs, len);
        print_results(durs, len, "ECDHE (P-384),agree");
        bench_black_box(ecdhe_agree, &ecdhe521_args, durs, len);
        print_results(durs, len, "ECDHE (P-521),agree");
#endif
#endif /* BENCH_ECDHE */

#ifdef BENCH_MLKEM
#ifdef BENCH_MLKEM_KEYGEN
        bench_black_box(mlkem512_keygen, &rng, durs, len);
        print_results(durs, len, "ML-KEM-512,keygen");
        bench_black_box(mlkem768_keygen, &rng, durs, len);
        print_results(durs, len, "ML-KEM-768,keygen");
        bench_black_box(mlkem1024_keygen, &rng, durs, len);
        print_results(durs, len, "ML-KEM-1024,keygen");
#endif
#ifdef BENCH_MLKEM_ENCAP
        bench_black_box(mlkem_encap, &mlkem512_args, durs, len);
        print_results(durs, len, "ML-KEM-512,encap");
        bench_black_box(mlkem_encap, &mlkem768_args, durs, len);
        print_results(durs, len, "ML-KEM-768,encap");
        bench_black_box(mlkem_encap, &mlkem1024_args, durs, len);
        print_results(durs, len, "ML-KEM-1024,encap");
#endif
#ifdef BENCH_MLKEM_DECAP
        bench_black_box(mlkem_decap, &mlkem512_args, durs, len);
        print_results(durs, len, "ML-KEM-512,decap");
        bench_black_box(mlkem_decap, &mlkem768_args, durs, len);
        print_results(durs, len, "ML-KEM-768,decap");
        bench_black_box(mlkem_decap, &mlkem1024_args, durs, len);
        print_results(durs, len, "ML-KEM-1024,decap");
#endif
#endif /* BENCH_MLKEM */

#ifdef BENCH_HQC
#ifdef BENCH_HQC_KEYGEN
        bench_black_box(hqc128_keygen, &rng, durs, len);
        print_results(durs, len, "HQC-128,keygen");
        bench_black_box(hqc192_keygen, &rng, durs, len);
        print_results(durs, len, "HQC-192,keygen");
        bench_black_box(hqc256_keygen, &rng, durs, len);
        print_results(durs, len, "HQC-256,keygen");
#endif
#ifdef BENCH_HQC_ENCAP
        bench_black_box(hqc_encap, &hqc128_args, durs, len);
        print_results(durs, len, "HQC-128,encap");
        bench_black_box(hqc_encap, &hqc192_args, durs, len);
        print_results(durs, len, "HQC-192,encap");
        bench_black_box(hqc_encap, &hqc256_args, durs, len);
        print_results(durs, len, "HQC-256,encap");
#endif
#ifdef BENCH_HQC_DECAP
        bench_black_box(hqc_decap, &hqc128_args, durs, len);
        print_results(durs, len, "HQC-128,decap");
        bench_black_box(hqc_decap, &hqc192_args, durs, len);
        print_results(durs, len, "HQC-192,decap");
        bench_black_box(hqc_decap, &hqc256_args, durs, len);
        print_results(durs, len, "HQC-256,decap");
#endif
#endif /* BENCH_HQC */

#ifdef BENCH_MLKEM
#ifdef BENCH_MLKEM_KEYGEN
        bench_black_box(otmlkem512_keygen, &rng, durs, len);
        print_results(durs, len, "OT-ML-KEM-512,keygen");
        bench_black_box(otmlkem768_keygen, &rng, durs, len);
        print_results(durs, len, "OT-ML-KEM-768,keygen");
        bench_black_box(otmlkem1024_keygen, &rng, durs, len);
        print_results(durs, len, "OT-ML-KEM-1024,keygen");
#endif
#ifdef BENCH_MLKEM_ENCAP
        bench_black_box(otmlkem_encap, &otmlkem512_args, durs, len);
        print_results(durs, len, "OT-ML-KEM-512,encap");
        bench_black_box(otmlkem_encap, &otmlkem768_args, durs, len);
        print_results(durs, len, "OT-ML-KEM-768,encap");
        bench_black_box(otmlkem_encap, &otmlkem1024_args, durs, len);
        print_results(durs, len, "OT-ML-KEM-1024,encap");
#endif
#ifdef BENCH_MLKEM_DECAP
        bench_black_box(otmlkem_decap, &otmlkem512_args, durs, len);
        print_results(durs, len, "OT-ML-KEM-512,decap");
        bench_black_box(otmlkem_decap, &otmlkem768_args, durs, len);
        print_results(durs, len, "OT-ML-KEM-768,decap");
        bench_black_box(otmlkem_decap, &otmlkem1024_args, durs, len);
        print_results(durs, len, "OT-ML-KEM-1024,decap");
#endif
#endif /* BENCH_MLKEM */

#ifdef BENCH_SPHINCS
        sphincs_setup(&sphincs_args, &rng, 1, FAST_VARIANT);
#ifdef BENCH_SPHINCS_KEYGEN
        bench_black_box(sphincs_keygen, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-128-FAST,keygen");
#endif
#ifdef BENCH_SPHINCS_SIGN
        bench_black_box(sphincs_sign, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-128-FAST,sign");
#endif
#ifdef BENCH_SPHINCS_VERIFY
        bench_black_box(sphincs_verify, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-128-FAST,verify");
#endif

        sphincs_setup(&sphincs_args, &rng, 3, FAST_VARIANT);
#ifdef BENCH_SPHINCS_KEYGEN
        bench_black_box(sphincs_keygen, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-192-FAST,keygen");
#endif
#ifdef BENCH_SPHINCS_SIGN
        bench_black_box(sphincs_sign, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-192-FAST,sign");
#endif
#ifdef BENCH_SPHINCS_VERIFY
        bench_black_box(sphincs_verify, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-192-FAST,verify");
#endif

        sphincs_setup(&sphincs_args, &rng, 5, FAST_VARIANT);
#ifdef BENCH_SPHINCS_KEYGEN
        bench_black_box(sphincs_keygen, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-256-FAST,keygen");
#endif
#ifdef BENCH_SPHINCS_SIGN
        bench_black_box(sphincs_sign, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-256-FAST,sign");
#endif
#ifdef BENCH_SPHINCS_VERIFY
        bench_black_box(sphincs_verify, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-256-FAST,verify");
#endif

        sphincs_setup(&sphincs_args, &rng, 1, SMALL_VARIANT);
#ifdef BENCH_SPHINCS_KEYGEN
        bench_black_box(sphincs_keygen, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-128-SMALL,keygen");
#endif
#ifdef BENCH_SPHINCS_SIGN
        bench_black_box(sphincs_sign, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-128-SMALL,sign");
#endif
#ifdef BENCH_SPHINCS_VERIFY
        bench_black_box(sphincs_verify, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-128-SMALL,verify");
#endif

        sphincs_setup(&sphincs_args, &rng, 3, SMALL_VARIANT);
#ifdef BENCH_SPHINCS_KEYGEN
        bench_black_box(sphincs_keygen, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-192-SMALL,keygen");
#endif
#ifdef BENCH_SPHINCS_SIGN
        bench_black_box(sphincs_sign, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-192-SMALL,sign");
#endif
#ifdef BENCH_SPHINCS_VERIFY
        bench_black_box(sphincs_verify, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-192-SMALL,verify");
#endif

        sphincs_setup(&sphincs_args, &rng, 5, SMALL_VARIANT);
#ifdef BENCH_SPHINCS_KEYGEN
        bench_black_box(sphincs_keygen, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-256-SMALL,keygen");
#endif
#ifdef BENCH_SPHINCS_SIGN
        bench_black_box(sphincs_sign, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-256-SMALL,sign");
#endif
#ifdef BENCH_SPHINCS_VERIFY
        bench_black_box(sphincs_verify, &sphincs_args, durs, len);
        print_results(durs, len, "SPHINCS-256-SMALL,verify");
#endif
#endif /* BENCH_SPHINCS */
    }
}

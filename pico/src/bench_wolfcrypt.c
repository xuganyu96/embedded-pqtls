/* bench_main.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <hardware/clocks.h>
#include <pico/stdlib.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/curve448.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hqc.h>
#include <wolfssl/wolfcrypt/otmlkem.h>
#include <wolfssl/wolfcrypt/pqclean_mlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>

#include "pico-pqtls/utils.h"

#define SIG_MSG_SIZE 48
#define WARMUP_ROUNDS 10
#define BENCH_ROUNDS 10

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

    reset_cyccnt();
    uint32_t cyc_start, cyc_stop = 0;
    for (uint32_t i = 0; i < rounds; i++) {
        cyc_start = read_cyccnt();
        blackbox(blackbox_args);
        cyc_stop = read_cyccnt();
        timestamps[i] = cyc_stop - cyc_start;
        reset_cyccnt();
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

/* The Cortex-M33 core runs at 150MHz, so sleeping for 1ms should take 150
 * kilocycles
 */
static void bench_sleep(void *args) {
    (void)args;
    sleep_ms(1);
}

struct x25519_args {
    curve25519_key alice;
    curve25519_key bob;
};

/* args must be a pointer to WC_RNG
 */
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
}

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

struct x448_args {
    curve448_key alice;
    curve448_key bob;
};

static void x448_keygen(void *args) {
    WC_RNG *rng = (WC_RNG *)args;
    curve448_key key;
    wc_curve448_init(&key);
    wc_curve448_make_key(rng, 56, &key);
}

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
}

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

struct ecdhe_args {
    ecc_key alice;
    ecc_key bob;
};

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
}

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

struct mlkem_args {
    WC_RNG *rng;
    PQCleanMlKemKey key;
    byte ct[PQCLEAN_MLKEM_MAX_CIPHERTEXT_SIZE];
    byte ss[PQCLEAN_MLKEM_SS_SIZE];
};

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
}

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

struct hqc_args {
    WC_RNG *rng;
    HqcKey key;
    byte ct[PQCLEAN_HQC_MAX_CIPHERTEXT_SIZE];
    byte ss[PQCLEAN_HQC_MAX_SHAREDSECRET_SIZE];
};

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
}

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

struct otmlkem_args {
    WC_RNG *rng;
    OtMlKemKey key;
    byte ct[PQCLEAN_OTMLKEM_MAX_CIPHERTEXT_SIZE];
    byte ss[PQCLEAN_OTMLKEM_MAX_SHAREDSECRET_SIZE];
};

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
}

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

/* Benchmarking digital signatures
 *
 * For each digital signature schemes we will bench three operations: keygen, sign, verify
 * Keygen can be benched with only the RNG. Benching sign requires a ready-made key, and
 * benching verify requires ready-made key, message, and signature.
 *
 * For benching sign/verify, the message size will be 48 bytes. This is because the highest
 * level TLS 1.3 cipher suite uses SHA384.
 */

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

struct rsa_args {
    WC_RNG *rng;
    RsaKey key;
    byte msg[SIG_MSG_SIZE];
    byte sig[RSA_MAX_SIZE / 8];
};

static void rsa2048_setup(struct rsa_args *args, WC_RNG *rng) {
    int ret;
    if ((ret = wc_InitRsaKey(&args->key, NULL)) < 0) {
        printf("wc_InitRsaKey returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_MakeRsaKey(&args->key, RSA_MIN_SIZE, WC_RSA_EXPONENT, rng)) < 0) {
        printf("wc_MakeRsaKey returned %d\n", ret);
        exit(-1);
    }
    if ((ret = wc_RNG_GenerateBlock(rng, args->msg, sizeof(args->msg))) < 0) {
        printf("wc_RNG_GenerateBlock returned %d\n", ret);
        exit(-1);
    }
    // TODO: finish this
}

int main(void) {
    stdio_init_all();
    countdown_s(5);
    wolfSSL_Init();
    wolfSSL_Debugging_ON();
    printf("System clock = %dMHz\n\n", clock_get_hz(clk_sys) / 1000000);
    enable_dwt();
    WC_RNG rng;
    wc_InitRng(&rng);
    printf("Initialized RNG\n");

    uint32_t durs[BENCH_ROUNDS];
    size_t len = BENCH_ROUNDS;

    /* setup */
    struct x25519_args x25519_agree_args;
    x25519_setup(&x25519_agree_args, &rng);
    struct x448_args x448_agree_args;
    x448_setup(&x448_agree_args, &rng);
    struct ecdhe_args ecdhe256_args, ecdhe384_args, ecdhe521_args;
    ecdhe_setup(&ecdhe256_args, &rng, ECC_SECP256R1);
    ecdhe_setup(&ecdhe384_args, &rng, ECC_SECP384R1);
    ecdhe_setup(&ecdhe521_args, &rng, ECC_SECP521R1);
    struct mlkem_args mlkem512_args, mlkem768_args, mlkem1024_args;
    mlkem_setup(&mlkem512_args, 1, &rng);
    mlkem_setup(&mlkem768_args, 3, &rng);
    mlkem_setup(&mlkem1024_args, 5, &rng);
    struct hqc_args hqc128_args, hqc192_args, hqc256_args;
    hqc_setup(&hqc128_args, 1, &rng);
    hqc_setup(&hqc192_args, 3, &rng);
    hqc_setup(&hqc256_args, 5, &rng);
    struct otmlkem_args otmlkem512_args, otmlkem768_args, otmlkem1024_args;
    otmlkem_setup(&otmlkem512_args, 1, &rng);
    otmlkem_setup(&otmlkem768_args, 3, &rng);
    otmlkem_setup(&otmlkem1024_args, 5, &rng);

    /* bench */
    printf("name,op,median,p90,p99\n");
    while (1) {
        bench_black_box(bench_sleep, NULL, durs, len);
        print_results(durs, len, "sleep,sleep");

        bench_black_box(x25519_keygen, &rng, durs, len);
        print_results(durs, len, "x25519,keygen");
        bench_black_box(x25519_agree, &x25519_agree_args, durs, len);
        print_results(durs, len, "x25519,agree");

        bench_black_box(x448_keygen, &rng, durs, len);
        print_results(durs, len, "x448,keygen");
        bench_black_box(x448_agree, &x448_agree_args, durs, len);
        print_results(durs, len, "x448,agree");

        bench_black_box(ecdhe256_keygen, &rng, durs, len);
        print_results(durs, len, "ECDHE (P-256),keygen");
        bench_black_box(ecdhe_agree, &ecdhe256_args, durs, len);
        print_results(durs, len, "ECDHE (P-256),agree");

        bench_black_box(ecdhe384_keygen, &rng, durs, len);
        print_results(durs, len, "ECDHE (P-384),keygen");
        bench_black_box(ecdhe_agree, &ecdhe384_args, durs, len);
        print_results(durs, len, "ECDHE (P-384),agree");

        bench_black_box(ecdhe521_keygen, &rng, durs, len);
        print_results(durs, len, "ECDHE (P-521),keygen");
        bench_black_box(ecdhe_agree, &ecdhe521_args, durs, len);
        print_results(durs, len, "ECDHE (P-521),agree");

        bench_black_box(mlkem512_keygen, &rng, durs, len);
        print_results(durs, len, "ML-KEM-512,keygen");
        bench_black_box(mlkem_encap, &mlkem512_args, durs, len);
        print_results(durs, len, "ML-KEM-512,encap");
        bench_black_box(mlkem_decap, &mlkem512_args, durs, len);
        print_results(durs, len, "ML-KEM-512,decap");

        bench_black_box(mlkem768_keygen, &rng, durs, len);
        print_results(durs, len, "ML-KEM-768,keygen");
        bench_black_box(mlkem_encap, &mlkem768_args, durs, len);
        print_results(durs, len, "ML-KEM-768,encap");
        bench_black_box(mlkem_decap, &mlkem768_args, durs, len);
        print_results(durs, len, "ML-KEM-768,decap");

        bench_black_box(mlkem1024_keygen, &rng, durs, len);
        print_results(durs, len, "ML-KEM-1024,keygen");
        bench_black_box(mlkem_encap, &mlkem1024_args, durs, len);
        print_results(durs, len, "ML-KEM-1024,encap");
        bench_black_box(mlkem_decap, &mlkem1024_args, durs, len);
        print_results(durs, len, "ML-KEM-1024,decap");

        bench_black_box(hqc128_keygen, &rng, durs, len);
        print_results(durs, len, "HQC-128,keygen");
        bench_black_box(hqc_encap, &hqc128_args, durs, len);
        print_results(durs, len, "HQC-128,encap");
        bench_black_box(hqc_decap, &hqc128_args, durs, len);
        print_results(durs, len, "HQC-128,decap");

        bench_black_box(hqc192_keygen, &rng, durs, len);
        print_results(durs, len, "HQC-192,keygen");
        bench_black_box(hqc_encap, &hqc192_args, durs, len);
        print_results(durs, len, "HQC-192,encap");
        bench_black_box(hqc_decap, &hqc192_args, durs, len);
        print_results(durs, len, "HQC-192,decap");

        bench_black_box(hqc256_keygen, &rng, durs, len);
        print_results(durs, len, "HQC-256,keygen");
        bench_black_box(hqc_encap, &hqc256_args, durs, len);
        print_results(durs, len, "HQC-256,encap");
        bench_black_box(hqc_decap, &hqc256_args, durs, len);
        print_results(durs, len, "HQC-256,decap");

        bench_black_box(otmlkem512_keygen, &rng, durs, len);
        print_results(durs, len, "OT-ML-KEM-512,keygen");
        bench_black_box(otmlkem_encap, &otmlkem512_args, durs, len);
        print_results(durs, len, "OT-ML-KEM-512,encap");
        bench_black_box(otmlkem_decap, &otmlkem512_args, durs, len);
        print_results(durs, len, "OT-ML-KEM-512,decap");

        bench_black_box(otmlkem768_keygen, &rng, durs, len);
        print_results(durs, len, "OT-ML-KEM-768,keygen");
        bench_black_box(otmlkem_encap, &otmlkem768_args, durs, len);
        print_results(durs, len, "OT-ML-KEM-768,encap");
        bench_black_box(otmlkem_decap, &otmlkem768_args, durs, len);
        print_results(durs, len, "OT-ML-KEM-768,decap");

        bench_black_box(otmlkem1024_keygen, &rng, durs, len);
        print_results(durs, len, "OT-ML-KEM-1024,keygen");
        bench_black_box(otmlkem_encap, &otmlkem1024_args, durs, len);
        print_results(durs, len, "OT-ML-KEM-1024,encap");
        bench_black_box(otmlkem_decap, &otmlkem1024_args, durs, len);
        print_results(durs, len, "OT-ML-KEM-1024,decap");
    }
}

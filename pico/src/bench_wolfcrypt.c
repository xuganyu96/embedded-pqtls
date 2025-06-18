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
#include <wolfssl/wolfcrypt/random.h>

#include "pico-pqtls/utils.h"

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

static void ecdhe256_setup(struct ecdhe_args *args, WC_RNG *rng) {
    int ret;
    wc_ecc_init(&args->alice);
    wc_ecc_init(&args->bob);
    ret = wc_ecc_make_key(rng, wc_ecc_get_curve_size_from_id(ECC_SECP256R1),
                          &args->alice);
    if (ret < 0) {
        printf("returned %d\n", ret);
        exit(-1);
    }
    ret = wc_ecc_make_key(rng, wc_ecc_get_curve_size_from_id(ECC_SECP256R1),
                          &args->bob);
    if (ret < 0) {
        printf("returned %d\n", ret);
        exit(-1);
    }
    args->alice.rng = rng;
    args->bob.rng = rng;
}

static void ecdhe384_setup(struct ecdhe_args *args, WC_RNG *rng) {
    int ret;
    wc_ecc_init(&args->alice);
    wc_ecc_init(&args->bob);
    ret = wc_ecc_make_key(rng, wc_ecc_get_curve_size_from_id(ECC_SECP384R1),
                          &args->alice);
    if (ret < 0) {
        printf("returned %d\n", ret);
        exit(-1);
    }
    ret = wc_ecc_make_key(rng, wc_ecc_get_curve_size_from_id(ECC_SECP384R1),
                          &args->bob);
    if (ret < 0) {
        printf("returned %d\n", ret);
        exit(-1);
    }
    args->alice.rng = rng;
    args->bob.rng = rng;
}

static void ecdhe521_setup(struct ecdhe_args *args, WC_RNG *rng) {
    int ret;
    wc_ecc_init(&args->alice);
    wc_ecc_init(&args->bob);
    ret = wc_ecc_make_key(rng, wc_ecc_get_curve_size_from_id(ECC_SECP521R1),
                          &args->alice);
    if (ret < 0) {
        printf("wc_ecc_make_key returned %d\n", ret);
        exit(-1);
    }
    ret = wc_ecc_make_key(rng, wc_ecc_get_curve_size_from_id(ECC_SECP521R1),
                          &args->bob);
    if (ret < 0) {
        printf("wc_ecc_make_key returned %d\n", ret);
        exit(-1);
    }
    args->alice.rng = rng;
    args->bob.rng = rng;
}

static void ecdhe256_agree(void *args) {
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

static void ecdhe384_agree(void *args) {
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

static void ecdhe521_agree(void *args) {
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
    ecdhe256_setup(&ecdhe256_args, &rng);
    ecdhe384_setup(&ecdhe384_args, &rng);
    ecdhe521_setup(&ecdhe521_args, &rng);

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

        bench_black_box(ecdhe256_agree, &ecdhe256_args, durs, len);
        print_results(durs, len, "ECDHE (P-256),agree");

        bench_black_box(ecdhe384_keygen, &rng, durs, len);
        print_results(durs, len, "ECDHE (P-384),keygen");

        bench_black_box(ecdhe384_agree, &ecdhe384_args, durs, len);
        print_results(durs, len, "ECDHE (P-384),agree");

        bench_black_box(ecdhe521_keygen, &rng, durs, len);
        print_results(durs, len, "ECDHE (P-521),keygen");

        bench_black_box(ecdhe521_agree, &ecdhe521_args, durs, len);
        print_results(durs, len, "ECDHE (P-521),agree");
    }
}

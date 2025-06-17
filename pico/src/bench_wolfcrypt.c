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
#include <wolfssl/wolfcrypt/random.h>

#include "pico-pqtls/utils.h"

#define WARMUP_ROUNDS 1000

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
    return (va > vb) - (va < vb);  // returns 1, 0, or -1
}

uint32_t percentile(uint32_t *sorted, size_t len, double percent) {
    if (len == 0) return 0;
    size_t idx = (size_t)((percent / 100.0) * len);
    if (idx >= len) idx = len - 1;
    return sorted[idx];
}

void print_results(uint32_t *durs, size_t len, const char *prefix) {
    if (len == 0 || !durs || !prefix) return;

    // Sort a copy to avoid modifying original array
    uint32_t *copy = malloc(len * sizeof(uint32_t));
    if (!copy) return;
    for (size_t i = 0; i < len; i++) {
        copy[i] = durs[i];
    }
    qsort(copy, len, sizeof(uint32_t), cmp_uint32);

    // Median
    uint32_t median = (len % 2 == 0)
        ? (copy[len / 2 - 1] + copy[len / 2]) / 2
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

/* args must be a pointer to WC_RNG
 */
static void bench_x25519keygen(void *args) {
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

struct bench_x25519_agree_args {
    curve25519_key alice;
    curve25519_key bob;
};

static void bench_x25519agree_setup(struct bench_x25519_agree_args *args, WC_RNG *rng) {
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

static void bench_x25519agree(void *args) {
    byte out[32];
    word32 outlen = 32;
    struct bench_x25519_agree_args *keypair = (struct bench_x25519_agree_args *)args;
    int ret = wc_curve25519_shared_secret(&keypair->alice, &keypair->bob, out, &outlen);
    if (ret < 0) {
        printf("wc_curve25519_shared_secret returned %d\n", ret);
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

    uint32_t durs[1000];
    size_t len = 1000;

    /* setup */
    struct bench_x25519_agree_args x25519_agree_args;
    bench_x25519agree_setup(&x25519_agree_args, &rng);

    /* bench */
    printf("name,op,median,p90,p99\n");
    while (1) {
        bench_black_box(bench_sleep, NULL, durs, len);
        print_results(durs, len, "sleep,sleep");

        bench_black_box(bench_x25519keygen, &rng, durs, len);
        print_results(durs, len, "x25519,keygen");

        bench_black_box(bench_x25519agree, &x25519_agree_args, durs, len);
        print_results(durs, len, "x25519,agree");
    }
}

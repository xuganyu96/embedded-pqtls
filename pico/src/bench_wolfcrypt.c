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

#include "wolfcrypt/benchmark/benchmark.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/random.h"

#include "pico-pqtls/utils.h"

int main(void) {
  stdio_init_all();
  countdown_s(5);
  wolfSSL_Init();
  wolfSSL_Debugging_ON();
  DEBUG_printf("System clock = %dMHz\n\n", clock_get_hz(clk_sys) / 1000000);
  WC_RNG rng;
  wc_InitRng(&rng);
  INFO_printf("Initialized RNG\n");

  int ret;
  while (1) {
    ret = benchmark_test(NULL);
    DEBUG_printf("Bench finished: %d\n", ret);
    sleep_ms(1000);
  }
}

#include <time.h>
time_t myTime(time_t *t) {
  *t = (((2023 - 1970) * 12 + 8) * 30 * 24 * 60 * 60);
  return *t;
}

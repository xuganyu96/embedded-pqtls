#include <inttypes.h>
#include <string.h>
#include <wolfcrypt/benchmark/benchmark.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/pqclean_mlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sphincs.h>

/* SHA3 impl's */
#include <wolfssl/wolfcrypt/pqclean/common/fips202.h>
#include <wolfssl/wolfcrypt/sha3.h>

#define ROUNDS 3

static int test_wc_falcon_correctness(int level, int rounds, WC_RNG *rng) {
  int test_err = 0;

  falcon_key key;
  uint8_t msg[512];
  uint8_t sig[FALCON_MAX_SIG_SIZE];
  uint32_t siglen = sizeof(sig);
  int verified;

  for (int round = 0; round < rounds; round++) {
    verified = 0;
    siglen = sizeof(sig);

    wc_RNG_GenerateBlock(rng, msg, sizeof(msg));

    if ((test_err = wc_falcon_init(&key)) != 0) {
      fprintf(stderr, "Failed to init <Falcon lvl=%d> key (err %d)\n", level,
              test_err);
      return test_err;
    }
    if ((test_err = wc_falcon_set_level(&key, level)) != 0) {
      fprintf(stderr, "Failed to set <Falcon lvl=%d> params (err %d)\n", level,
              test_err);
      return test_err;
    }
    if ((test_err = wc_falcon_make_key(&key, rng)) != 0) {
      fprintf(stderr, "Failed to generate <Falcon lvl=%d> keypair (err %d)\n",
              level, test_err);
      return test_err;
    }
    if ((test_err = wc_falcon_sign_msg(msg, sizeof(msg), sig, &siglen, &key,
                                       rng)) != 0) {
      fprintf(stderr, "Failed to sign (err %d)\n", test_err);
      return test_err;
    }
    if ((test_err = wc_falcon_verify_msg(sig, siglen, msg, sizeof(msg),
                                         &verified, &key)) != 0) {
      fprintf(stderr, "verification returned error (err %d)\n", test_err);
      return test_err;
    }
    if (!verified) {
      fprintf(stderr, "bad signature");
      return test_err;
    }
  }

  return 0;
}

static int test_wc_sphincs_correctness(int level, int optim, int rounds,
                                       WC_RNG *rng) {
  int test_err = 0;

  sphincs_key key;
  uint8_t msg[512];
  uint8_t sig[SPHINCS_MAX_SIG_SIZE];
  uint32_t siglen = sizeof(sig);
  int verified;

  for (int round = 0; round < rounds; round++) {
    verified = 0;
    siglen = sizeof(sig);

    wc_RNG_GenerateBlock(rng, msg, sizeof(msg));

    if ((test_err = wc_sphincs_init(&key)) != 0) {
      fprintf(stderr, "Failed to init <sphincs lvl=%d> key (err %d)\n", level,
              test_err);
      return test_err;
    }
    if ((test_err = wc_sphincs_set_level_and_optim(&key, level, optim)) != 0) {
      fprintf(stderr, "Failed to set <sphincs lvl=%d> params (err %d)\n", level,
              test_err);
      return test_err;
    }
    if ((test_err = wc_sphincs_make_key(&key, rng)) != 0) {
      fprintf(stderr, "Failed to generate <sphincs lvl=%d> keypair (err %d)\n",
              level, test_err);
      return test_err;
    }
    if ((test_err = wc_sphincs_sign_msg(msg, sizeof(msg), sig, &siglen, &key,
                                        rng)) != 0) {
      fprintf(stderr, "Failed to sign (err %d)\n", test_err);
      return test_err;
    }
    if ((test_err = wc_sphincs_verify_msg(sig, siglen, msg, sizeof(msg),
                                          &verified, &key)) != 0) {
      fprintf(stderr, "verification returned error (err %d)\n", test_err);
      return test_err;
    }
    if (!verified) {
      fprintf(stderr, "bad signature");
      return test_err;
    }
  }

  return 0;
}

static int test_wc_pqcleanmlkem_correctness(int level, int rounds,
                                            WC_RNG *rng) {
  PQCleanMlKemKey key;
  int wc_err;
  word32 ctlen;
  byte ct[PQCLEAN_MLKEM_MAX_CIPHERTEXT_SIZE], ss[PQCLEAN_MLKEM_SS_SIZE],
      ss_cmp[PQCLEAN_MLKEM_SS_SIZE];
  for (int round = 0; round < rounds; round++) {
    memset(ct, 0, sizeof(ct));
    memset(ss, 0, sizeof(ss));
    memset(ss_cmp, 0, sizeof(ss_cmp));

    wc_PQCleanMlKemKey_Init(&key);
    wc_PQCleanMlKemKey_SetLevel(&key, level);
    wc_PQCleanMlKemKey_CipherTextSize(&key, &ctlen);

    if ((wc_err = wc_PQCleanMlKemKey_MakeKey(&key, rng)) != 0) {
      fprintf(stderr, "Failed to generate <PQCleanMlKemKey lvl=%d>\n", level);
      return wc_err;
    }
    if ((wc_err = wc_PQCleanMlKemKey_Encapsulate(&key, ct, ss, rng)) != 0) {
      fprintf(stderr, "Failed to encapsulate <PQCleanMlKemKey lvl=%d>\n",
              level);
      return wc_err;
    }
    if ((wc_err = wc_PQCleanMlKemKey_Decapsulate(&key, ss_cmp, ct, ctlen)) !=
        0) {
      fprintf(stderr,
              "Failed to decapsulate <PQCleanMlKemKey lvl=%d> (err %d)\n",
              level, wc_err);
      return wc_err;
    }
    if (memcmp(ss, ss_cmp, sizeof(ss)) != 0) {
      fprintf(stderr, "<PQCleanMlKemKey lvl=%d> decapsulation is incorrect\n",
              level);
      return -1;
    }
  }

  return 0;
}

static void compare_sha3(void) {
  uint8_t input[4096] = {
      42,
  };
  uint8_t wc_output[512];
  uint8_t pqc_output[512];

  wc_Shake wc_shake;
  shake256incctx pqc_shake256;
  shake128incctx pqc_shake128;
  wc_InitShake256(&wc_shake, NULL, INVALID_DEVID);
  /* NOTE: absorb = update + finalize but no output */
  wc_Shake256_Update(&wc_shake, input, sizeof(input));
  wc_Shake256_Update(&wc_shake, input, sizeof(input));
  wc_Shake256_Final(&wc_shake, wc_output, sizeof(wc_output));
  // wc_Shake256_Free(&wc_shake);

  shake256_inc_init(&pqc_shake256);
  shake256_inc_absorb(&pqc_shake256, input, sizeof(input));
  shake256_inc_absorb(&pqc_shake256, input, sizeof(input));
  shake256_inc_finalize(&pqc_shake256);
  shake256_inc_squeeze(pqc_output, sizeof(pqc_output), &pqc_shake256);
  // shake256_inc_ctx_release(&pqc_shake);

  if (memcmp(wc_output, pqc_output, sizeof(wc_output)) == 0) {
    printf("Shake256 agree\n");
  } else {
    printf("Shake256 disagree\n");
  }

  wc_InitShake128(&wc_shake, NULL, INVALID_DEVID);
  /* NOTE: absorb = update + finalize but no output */
  wc_Shake128_Update(&wc_shake, input, sizeof(input));
  wc_Shake128_Update(&wc_shake, input, sizeof(input));
  wc_Shake128_Final(&wc_shake, wc_output, sizeof(wc_output));
  // wc_Shake128_Free(&wc_shake);

  shake128_inc_init(&pqc_shake128);
  shake128_inc_absorb(&pqc_shake128, input, sizeof(input));
  shake128_inc_absorb(&pqc_shake128, input, sizeof(input));
  shake128_inc_finalize(&pqc_shake128);
  shake128_inc_squeeze(pqc_output, sizeof(pqc_output), &pqc_shake128);
  // shake128_inc_ctx_release(&pqc_shake);

  if (memcmp(wc_output, pqc_output, sizeof(wc_output)) == 0) {
    printf("Shake128 agree\n");
  } else {
    printf("Shake128 disagree\n");
  }

  /* Absorb some 100MB of data and squeeze */
  struct timespec start, end;
  uint64_t pqclean_usec, wc_usec;

  size_t large_input_len = 100 * 1000 * 1000; /* 100 million bytes */
  uint8_t *large_input = malloc(large_input_len);

  clock_gettime(CLOCK_MONOTONIC, &start);
  shake128_inc_init(&pqc_shake128);
  shake128_inc_absorb(&pqc_shake128, large_input, large_input_len);
  shake128_inc_finalize(&pqc_shake128);
  shake128_inc_squeeze(pqc_output, sizeof(pqc_output), &pqc_shake128);
  clock_gettime(CLOCK_MONOTONIC, &end);
  pqclean_usec = (end.tv_sec - start.tv_sec) * 1000000L +
                 (end.tv_nsec - start.tv_nsec) / 1000L;
  printf("fips202 took %" PRIu64 " microseconds.\n", pqclean_usec);

  clock_gettime(CLOCK_MONOTONIC, &start);
  wc_InitShake128(&wc_shake, NULL, INVALID_DEVID);
  wc_Shake128_Update(&wc_shake, large_input, large_input_len);
  wc_Shake128_Final(&wc_shake, wc_output, sizeof(wc_output));
  clock_gettime(CLOCK_MONOTONIC, &end);
  wc_usec = (end.tv_sec - start.tv_sec) * 1000000L +
            (end.tv_nsec - start.tv_nsec) / 1000L;
  printf("wolfssl took %" PRIu64 " microseconds.\n", wc_usec);

  free(large_input);
}

int main(void) {
  WC_RNG rng;
  wc_InitRng(&rng);
  int ret = 0;

  if (0) {
    compare_sha3();
  }

  if (1) {
    test_wc_sphincs_correctness(1, SPHINCS_FAST_VARIANT, ROUNDS, &rng);
    test_wc_sphincs_correctness(1, SPHINCS_SMALL_VARIANT, ROUNDS, &rng);
    test_wc_pqcleanmlkem_correctness(1, ROUNDS, &rng);
    test_wc_sphincs_correctness(3, SPHINCS_FAST_VARIANT, ROUNDS, &rng);
    test_wc_sphincs_correctness(3, SPHINCS_SMALL_VARIANT, ROUNDS, &rng);
    test_wc_pqcleanmlkem_correctness(3, ROUNDS, &rng);
    test_wc_sphincs_correctness(5, SPHINCS_FAST_VARIANT, ROUNDS, &rng);
    test_wc_sphincs_correctness(5, SPHINCS_SMALL_VARIANT, ROUNDS, &rng);
    test_wc_pqcleanmlkem_correctness(5, ROUNDS, &rng);
    test_wc_falcon_correctness(1, ROUNDS, &rng);
    test_wc_falcon_correctness(5, ROUNDS, &rng);
  }

  if (0) {
    ret = benchmark_test(NULL);
    bench_pqcleanmlkem(1);
    bench_mlkem(WC_ML_KEM_512);
    bench_pqcleanmlkem(3);
    bench_mlkem(WC_ML_KEM_768);
    bench_pqcleanmlkem(5);
    bench_mlkem(WC_ML_KEM_1024);
    printf("Bench finished: %d\n", ret);
  }

  return ret;
}

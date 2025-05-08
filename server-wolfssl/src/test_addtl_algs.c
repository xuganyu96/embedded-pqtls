#include <string.h>
#include <wolfcrypt/benchmark/benchmark.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/pqclean_mlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sphincs.h>

#define ROUNDS 5

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

int main(void) {
  WC_RNG rng;
  wc_InitRng(&rng);
  int ret = 0;
  int err = 0;

  // err |= test_wc_pqcleanmlkem_correctness(1, ROUNDS, &rng);
  // err |= test_wc_pqcleanmlkem_correctness(3, ROUNDS, &rng);
  // err |= test_wc_pqcleanmlkem_correctness(5, ROUNDS, &rng);
  // err |= test_wc_falcon_correctness(1, ROUNDS, &rng);
  // err |= test_wc_falcon_correctness(5, ROUNDS, &rng);
  // err |= test_wc_sphincs_correctness(1, SPHINCS_FAST_VARIANT, ROUNDS, &rng);
  // err |= test_wc_sphincs_correctness(1, SPHINCS_SMALL_VARIANT, ROUNDS, &rng);
  // err |= test_wc_sphincs_correctness(3, SPHINCS_FAST_VARIANT, ROUNDS, &rng);
  // err |= test_wc_sphincs_correctness(3, SPHINCS_SMALL_VARIANT, ROUNDS, &rng);
  // err |= test_wc_sphincs_correctness(5, SPHINCS_FAST_VARIANT, ROUNDS, &rng);
  // err |= test_wc_sphincs_correctness(5, SPHINCS_SMALL_VARIANT, ROUNDS, &rng);

  bench_pqcleanmlkem(1);
  bench_mlkem(WC_ML_KEM_512);

  bench_pqcleanmlkem(3);
  bench_mlkem(WC_ML_KEM_768);

  bench_pqcleanmlkem(5);
  bench_mlkem(WC_ML_KEM_1024);

  if (!err) {
    printf("Ok.\n");
  }

#if 0
  ret = benchmark_test(NULL);
  printf("Bench finished: %d\n", ret);
#endif

  return ret;
}

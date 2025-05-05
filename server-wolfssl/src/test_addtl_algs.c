#include "wolfssl/wolfcrypt/random.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sphincs.h>

int test_sphincs_correctness(WC_RNG *rng, int level, int optim) {
  sphincs_key key;
  int fail, verified;
  uint8_t msg[512];
  uint8_t sig[SPHINCS_MAX_SIG_SIZE];
  uint32_t siglen = sizeof(sig);

  wc_sphincs_init(&key);
  if (key.prvKeySet != 0 || key.pubKeySet != 0) {
    fprintf(stderr, "init key did not unset privKeySet or pubKeySet\n");
    return -1;
  }

  wc_sphincs_set_level_and_optim(&key, level, optim);
  fail = wc_sphincs_make_key(&key, rng);
  if (fail) {
    fprintf(stderr, "Failed to generate SPHINCS keypair\n");
    return -1;
  }

  fail = wc_sphincs_sign_msg(msg, sizeof(msg), sig, &siglen, &key, rng);
  if (fail) {
    fprintf(stderr, "Failed to sign message\n");
    return -1;
  }

  fail = wc_sphincs_verify_msg(sig, siglen, msg, sizeof(msg), &verified, &key);
  if (fail) {
    fprintf(stderr, "Verify msg function call fails\n");
    return -1;
  } else if (!verified) {
    fprintf(stderr, "signature is bad\n");
    return -1;
  }

  return 0;
}

int main(void) {
  WC_RNG rng;
  wc_InitRng(&rng);
  int fail;

  fail = test_sphincs_correctness(&rng, 1, SPHINCS_FAST_VARIANT);
  if (fail) {
    fprintf(stderr, "sphincs-shake-128f-simple Fail (err %d)\n", fail);
    return fail;
  } else {
    printf("sphincs-shake-128f-simple Ok.\n");
  }
  fail = test_sphincs_correctness(&rng, 1, SPHINCS_SMALL_VARIANT);
  if (fail) {
    fprintf(stderr, "sphincs-shake-128s-simple Fail (err %d)\n", fail);
    return fail;
  } else {
    printf("sphincs-shake-128s-simple Ok.\n");
  }
  fail = test_sphincs_correctness(&rng, 3, SPHINCS_FAST_VARIANT);
  if (fail) {
    fprintf(stderr, "sphincs-shake-192f-simple Fail (err %d)\n", fail);
    return fail;
  } else {
    printf("sphincs-shake-192f-simple Ok.\n");
  }
  printf("Ok.\n");
  return 0;
}

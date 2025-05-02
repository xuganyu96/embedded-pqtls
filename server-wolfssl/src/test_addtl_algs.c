#include "wolfssl/wolfcrypt/random.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sphincs.h>

int main(void) {
  sphincs_key key;
  WC_RNG rng;
  wc_InitRng(&rng);
  int sphincs_err;

  wc_sphincs_init(&key);
  wc_sphincs_set_level_and_optim(&key, 1, SPHINCS_FAST_VARIANT);
  sphincs_err = wc_sphincs_make_key(&key, &rng);
  if (sphincs_err) {
    printf("Failed to make SPHINCS key (err %d)\n", sphincs_err);
    return sphincs_err;
  }

  return 0;
}

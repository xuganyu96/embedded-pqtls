#include <wolfcrypt/benchmark/benchmark.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sphincs.h>

int main(void) {
  WC_RNG rng;
  wc_InitRng(&rng);

  int ret;
  ret = benchmark_test(NULL);
  printf("Bench finished: %d\n", ret);

  return ret;
}

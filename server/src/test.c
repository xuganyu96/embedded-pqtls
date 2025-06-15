#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <wolfssl/wolfcrypt/random.h>
#include <crypto_kem/ot-ml-kem-1024/clean/api.h>
#include <common/randombytes.h>

int main(void) {
    uint8_t pk[PQCLEAN_OTMLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_OTMLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[PQCLEAN_OTMLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[PQCLEAN_OTMLKEM1024_CLEAN_CRYPTO_BYTES];
    uint8_t ss_cmp[PQCLEAN_OTMLKEM1024_CLEAN_CRYPTO_BYTES];
    WC_RNG rng;
    int ret;
    wc_InitRng(&rng);
    PQCLEAN_set_wc_rng(&rng);

    ret = PQCLEAN_OTMLKEM1024_CLEAN_crypto_kem_keypair(pk, sk);
    if (ret != 0){
        fprintf(stderr, "keygen failed\n");
    };
    ret = PQCLEAN_OTMLKEM1024_CLEAN_crypto_kem_enc(ct, ss, pk);
    if (ret != 0){
        fprintf(stderr, "encap failed\n");
    };
    ret = PQCLEAN_OTMLKEM1024_CLEAN_crypto_kem_dec(ss_cmp, ct, sk);
    if (ret != 0){
        fprintf(stderr, "decap failed\n");
    };
    if (memcmp(ss, ss_cmp, sizeof(ss)) != 0) {
        fprintf(stderr, "decap incorrect\n");
    }
    printf("Ok.\n");

    return 0;
}

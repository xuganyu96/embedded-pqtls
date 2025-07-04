#include "wolfssl/wolfcrypt/hash.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/settings.h>

int main(void) {
    RsaKey key;
    WC_RNG rng;
    wc_InitRng(&rng);
    int ret;

    byte msg[48];
    byte digest[32];
    byte sig[RSA_MAX_SIZE / 8], pss[RSA_MAX_SIZE / 8];
    wc_RNG_GenerateBlock(&rng, msg, sizeof(msg));

    if ((ret = wc_InitRsaKey(&key, NULL)) < 0) {
        printf("InitRsaKey returned %d\n", ret);
        return -1;
    }
    if ((ret = wc_MakeRsaKey(&key, RSA_MIN_SIZE, WC_RSA_EXPONENT, &rng)) < 0) {
        printf("MakeRsaKey returned %d\n", ret);
        return -1;
    }
    if ((ret = wc_Sha256Hash(msg, sizeof(msg), digest)) < 0) {
        printf("wc_Sha256Hash returned %d\n", ret);
        return -1;
    }
    if ((ret = wc_RsaPSS_Sign(digest, sizeof(digest), sig, sizeof(sig),
                              WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &key, &rng)) <
        0) {
        printf("RsaPSS_Sign returned %d\n", ret);
        return -1;
    }
    printf("RsaPSS size %d\n", ret);

    if ((ret = wc_RsaPSS_VerifyCheck(sig, sizeof(sig), pss, sizeof(pss), digest,
                                     sizeof(digest), WC_HASH_TYPE_SHA256,
                                     WC_MGF1SHA256, &key)) < 0) {
        printf("RsaPSS_Verify returned %d\n", ret);
        return -1;
    }
    printf("Ok.\n");
    return 0;
}

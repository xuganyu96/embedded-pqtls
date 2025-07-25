#include <stdint.h>
#include <stdio.h>

#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"

int main(void) {
    int err;
    ecc_key root_key;
    enum ecc_curve_ids curve_id = ECC_SECP256R1;
    WC_RNG rng;
    wc_InitRng(&rng);

    /* Generate keypair, serialize to DER  */
    if ((err = wc_ecc_init(&root_key)) < 0) {
        fprintf(stderr, "Failed to init ECC key (%d)\n", err);
        return -1;
    }
    if ((err = wc_ecc_make_key(&rng, wc_ecc_get_curve_size_from_id(curve_id),
                               &root_key)) < 0) {
        fprintf(stderr, "Failed to make ECC key (%d)\n", err);
        return -1;
    }
    if ((err = wc_ecc_check_key(&root_key)) < 0) {
        fprintf(stderr, "ECC key check failed (%d)\n", err);
        return -1;
    }

    printf("Ok.\n");
    return 0;
}

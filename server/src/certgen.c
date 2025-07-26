#include <stdint.h>
#include <stdio.h>

#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"

#define MAX_DER_SZ 12000
#define MAX_PEM_SZ MAX_DER_SZ

int main(void) {
    int err, der_len;
    size_t written;
    ecc_key key;
    FILE *fd;
    int curve_size = wc_ecc_get_curve_size_from_id(ECC_SECP256R1);
    uint8_t der[MAX_DER_SZ];
    WC_RNG rng;
    const char keyfile[] = "root.key";

    wc_InitRng(&rng);

    if ((err = wc_ecc_init(&key)) < 0) {
        fprintf(stderr, "Failed to init ECC key (err=%d)\n", err);
        exit(EXIT_FAILURE);
    }
    if ((err = wc_ecc_make_key(&rng, curve_size, &key)) < 0) {
        fprintf(stderr, "Failed to make ECC key (err=%d)\n", err);
        exit(EXIT_FAILURE);
    }
    if ((err = wc_ecc_check_key(&key)) < 0) {
        fprintf(stderr, "ECC key check failed (err=%d)\n", err);
        exit(EXIT_FAILURE);
    }
    if ((err = wc_EccKeyToDer(&key, der, sizeof(der))) <= 0) {
        fprintf(stderr, "Failed to DER-encode ECC key (err=%d)\n", err);
        exit(EXIT_FAILURE);
    }
    der_len = err;

    if ((fd = fopen(keyfile, "wb")) == NULL) {
        fprintf(stderr, "Failed to open file %s\n", keyfile);
        exit(EXIT_FAILURE);
    }
    written = fwrite(der, sizeof(uint8_t), der_len, fd);
    printf("Wrote %zu to %s\n", written, keyfile);
    fclose(fd);


    printf("Ok.\n");
    return 0;
}

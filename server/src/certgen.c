#include <stdint.h>
#include <stdio.h>

#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"

#define MAX_DER_SZ 12000
#define MAX_PEM_SZ MAX_DER_SZ
#define COUNTRY "CA"
#define STATE "ON"
#define LOCALITY "Waterloo"
#define ORG "University of Waterloo"

static void set_certname(CertName *id, const char *country, const char *state,
                         const char *locality, const char *org,
                         const char *common_name) {
    if (id == NULL) {
        return;
    }
    if (country != NULL) {
        strncpy(id->country, country, CTC_NAME_SIZE);
    }
    if (state != NULL) {
        strncpy(id->state, state, CTC_NAME_SIZE);
    }
    if (locality != NULL) {
        strncpy(id->locality, locality, CTC_NAME_SIZE);
    }
    if (org != NULL) {
        strncpy(id->org, org, CTC_NAME_SIZE);
    }
    if (common_name != NULL) {
        strncpy(id->commonName, common_name, CTC_NAME_SIZE);
    }
}

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

    /* ECDSA key */
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

    /* certificate */
    Cert cert;
    if ((err = wc_InitCert(&cert)) < 0) {
        fprintf(stderr, "Failed to init cert (err=%d)\n", err);
        exit(EXIT_FAILURE);
    }
    set_certname(&cert.subject, COUNTRY, STATE, LOCALITY, ORG,
                 "*.eng.uwaterloo.ca");
    set_certname(&cert.issuer, COUNTRY, STATE, LOCALITY, ORG,
                 "certauthority.eng.uwaterloo.ca");

    printf("Ok.\n");
    return 0;
}

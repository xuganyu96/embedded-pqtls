#include <stdint.h>
#include <stdio.h>

#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"

int main(void) {
    int err, der_sz;
    ecc_key root_key;
    Cert root_cert;
    enum ecc_curve_ids curve_id = ECC_SECP256R1;
    enum CertType root_key_type = ECC_TYPE;
    enum Ctc_SigType root_key_sigtype = CTC_SHA256wECDSA;
    uint8_t der[8192];
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

    /* Fill in the data section of the certificate */
    wc_InitCert(&root_cert);
    root_cert.sigType = root_key_sigtype;
    root_cert.isCA = 1;
    // TODO: fill in subject, issuer, dates
    if ((der_sz = wc_MakeCert_ex(&root_cert, der, sizeof(der), root_key_type,
                                 &root_key, &rng)) <= 0) {
        fprintf(stderr, "Failed to make cert (%d)\n", der_sz);
        exit(-1);
    }
    if ((der_sz = wc_SignCert_ex(root_cert.bodySz, root_cert.sigType, der,
                                 sizeof(der), root_key_type, &root_key, &rng)) <
        0) {
        fprintf(stderr, "Failed to sign cert (%d)\n", der_sz);
        exit(-1);
    }

    printf("Root cert (%d B)\n", der_sz);
    return 0;
}

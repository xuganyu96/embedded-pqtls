#include <stdint.h>
#include <stdio.h>

#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"

int main(void) {
    int err, der_sz, pem_sz;
    ecc_key key;
    Cert cert;
    enum ecc_curve_ids curve_id = ECC_SECP256R1;
    enum CertType key_type = ECC_TYPE;
    enum Ctc_SigType key_sigtype = CTC_SHA256wECDSA;
    uint8_t der[8192], pem[8192];
    WC_RNG rng;
    wc_InitRng(&rng);

    /* Generate keypair, serialize to DER  */
    if ((err = wc_ecc_init(&key)) < 0) {
        fprintf(stderr, "Failed to init ECC key (%d)\n", err);
        return -1;
    }
    if ((err = wc_ecc_make_key(&rng, wc_ecc_get_curve_size_from_id(curve_id),
                               &key)) < 0) {
        fprintf(stderr, "Failed to make ECC key (%d)\n", err);
        return -1;
    }
    if ((err = wc_ecc_check_key(&key)) < 0) {
        fprintf(stderr, "ECC key check failed (%d)\n", err);
        return -1;
    }

    /* Fill in the data section of the certificate */
    wc_InitCert(&cert);
    cert.sigType = key_sigtype;
    cert.isCA = 1;
    // TODO: fill in subject, issuer, dates
    if ((der_sz = wc_MakeCert_ex(&cert, der, sizeof(der), key_type, &key,
                                 &rng)) <= 0) {
        fprintf(stderr, "Failed to make cert (%d)\n", der_sz);
        exit(-1);
    }
    if ((der_sz = wc_SignCert_ex(cert.bodySz, cert.sigType, der, sizeof(der),
                                 key_type, &key, &rng)) < 0) {
        fprintf(stderr, "Failed to sign cert (%d)\n", der_sz);
        exit(-1);
    }

    /* Convert to PEM and write to file */
    if ((pem_sz = wc_DerToPem(der, der_sz, pem, sizeof(pem), CERT_TYPE)) <= 0) {
        fprintf(stderr, "Failed to make PEM (%d)\n", pem_sz);
        exit(-1);
    }
    pem[pem_sz] = '\0';
    printf("%s\n", pem);

    return 0;
}

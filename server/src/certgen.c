#include <stdint.h>
#include <stdio.h>

#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"

#define MAX_DER_SZ 12000
#define MAX_PEM_SZ MAX_DER_SZ
#define COUNTRY "CA"
#define STATE "ON"
#define LOCALITY "Waterloo"
#define ORG "University of Waterloo"
/* UTCTime format: YYMMDDHHMMSSZ */
#define NOT_BEFORE_DATE "250101000000Z"
#define NOT_AFTER_DATE "350101000000Z"

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

/* Copy the date string from `datestr` to the destination
 */
static void set_utctime(byte *dst, int *dst_sz, const char *datestr) {
    dst[0] = ASN_UTC_TIME;
    dst[1] = ASN_UTC_TIME_SIZE - 1;
    memcpy(dst + 2, datestr, strlen(datestr));
    *dst_sz = 2 + strlen(datestr);
}

int main(void) {
    int err, der_len, pem_len;
    size_t written;
    ecc_key key;
    FILE *fd;
    int curve_size = wc_ecc_get_curve_size_from_id(ECC_SECP256R1);
    uint8_t der[MAX_DER_SZ], pem[MAX_PEM_SZ];
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
    int key_keytype = ECC_TYPE;
    int key_sigtype = CTC_SHA256wECDSA;
    if ((err = wc_InitCert(&cert)) < 0) {
        fprintf(stderr, "Failed to init cert (err=%d)\n", err);
        exit(EXIT_FAILURE);
    }
    /* certificate: identity information */
    set_certname(&cert.subject, COUNTRY, STATE, LOCALITY, ORG,
                 "*.eng.uwaterloo.ca");
    set_certname(&cert.issuer, COUNTRY, STATE, LOCALITY, ORG,
                 "certauthority.eng.uwaterloo.ca");
    set_utctime(cert.beforeDate, &cert.beforeDateSz, NOT_BEFORE_DATE);
    set_utctime(cert.afterDate, &cert.afterDateSz, NOT_AFTER_DATE);
    cert.isCA = 1;
    /* certificate: make and sign */
    cert.sigType = key_sigtype;
    if ((err = wc_MakeCert_ex(&cert, der, sizeof(der), key_keytype, &key,
                              &rng)) <= 0) {
        fprintf(stderr, "Failed to encode certificate body (err=%d)\n", err);
        exit(EXIT_FAILURE);
    }
    der_len = err;
    if ((err = wc_SignCert_ex(cert.bodySz, key_sigtype, der, sizeof(der),
                              key_keytype, &key, &rng)) <= 0) {
        fprintf(stderr, "Failed to sign certificate (err=%d)\n", err);
        exit(EXIT_FAILURE);
    }
    der_len = err;
    if ((err = wc_DerToPem(der, der_len, pem, sizeof(pem), CERT_TYPE)) <= 0) {
        fprintf(stderr, "Failed to convert DER to PEM (err=%d)\n", err);
        exit(EXIT_FAILURE);
    }
    pem_len = err;

    /* TODO: convert to PEM */
    const char certfile[] = "root.crt";
    if ((fd = fopen(certfile, "wb")) == NULL) {
        fprintf(stderr, "Failed to open %s\n", certfile);
        exit(EXIT_FAILURE);
    }
    written = fwrite(pem, sizeof(uint8_t), pem_len, fd);
    printf("Wrote %zu bytes to %s\n", written, certfile);
    fclose(fd);

    printf("Ok.\n");
    return 0;
}

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#define LEAF_COUNTRY "CA"
#define LEAF_STATE "ON"
#define LEAF_LOCALITY "Waterloo"
#define LEAF_ORG "Communication Security Lab"
#define LEAF_COMMONNAME "*.eng.uwaterloo.ca"
#define ROOT_COUNTRY LEAF_COUNTRY
#define ROOT_STATE LEAF_STATE
#define ROOT_LOCALITY LEAF_LOCALITY
#define ROOT_ORG LEAF_ORG
#define ROOT_COMMONNAME "*.eng.uwaterloo.ca"
#define NOT_BEFORE_DATE "250101000000Z"
#define NOT_AFTER_DATE "350101000000Z"
#define DER_MAX_SIZE 1000000

static void set_certname(CertName *cert_name, const char *country,
                         const char *state, const char *locality,
                         const char *org, const char *common_name) {
    strncpy(cert_name->country, country, CTC_NAME_SIZE);
    strncpy(cert_name->state, state, CTC_NAME_SIZE);
    strncpy(cert_name->locality, locality, CTC_NAME_SIZE);
    strncpy(cert_name->org, org, CTC_NAME_SIZE);
    strncpy(cert_name->commonName, common_name, CTC_NAME_SIZE);
}

// https://obj-sys.com/asn1tutorial/node15.html
// datestr must follow the UTCTime formatting
static void set_before_date_utctime(Cert *cert, const char *datestr) {
    cert->beforeDate[0] = ASN_UTC_TIME;
    cert->beforeDate[1] = ASN_UTC_TIME_SIZE - 1;
    memcpy(cert->beforeDate + 2, datestr, strlen(datestr));
    cert->beforeDateSz = 2 + strlen(datestr);
}

// https://obj-sys.com/asn1tutorial/node15.html
// datestr must follow the UTCTime formatting
static void set_after_date_utctime(Cert *cert, const char *datestr) {
    cert->afterDate[0] = ASN_UTC_TIME;
    cert->afterDate[1] = ASN_UTC_TIME_SIZE - 1;
    memcpy(cert->afterDate + 2, datestr, strlen(datestr));
    cert->afterDateSz = 2 + strlen(datestr);
}

/* Generate a self-signed certificate. Write the certificate and the private key
 * in PEM format to the input buffers.
 *
 * On input, *cert_len and *key_len encode the capacity of the buffers; on
 * output, they contain the actual length of data.
 *
 * Return 0 on success.
 */
int certgen(uint8_t *cert_pem, size_t *cert_len, uint8_t *key_pem,
            size_t *key_len, WC_RNG *rng) {
    int ret = 0;
    int level = WC_ML_DSA_44;
    uint8_t der[DER_MAX_SIZE];
    enum Ctc_SigType sig_type = CTC_ML_DSA_LEVEL2;
    enum CertType key_type = ML_DSA_LEVEL2_TYPE;

    /* Generate keypair */
    dilithium_key key;
    if ((ret = wc_dilithium_init(&key)) < 0)
        return ret;
    if ((ret = wc_dilithium_set_level(&key, level)) < 0)
        return ret;
    if ((ret = wc_dilithium_make_key(&key, rng)) < 0)
        return ret;
    if ((ret = wc_Dilithium_PrivateKeyToDer(&key, der, sizeof(der))) < 0)
        return ret;
    if ((ret = wc_DerToPem(der, ret, key_pem, *key_len,
                           PKCS8_PRIVATEKEY_TYPE)) < 0)
        return ret;
    *key_len = ret;

    /* Generate certificate */
    Cert cert;
    if ((ret = wc_InitCert(&cert)) < 0)
        return ret;
    cert.sigType = sig_type;
    cert.isCA = 1;
    set_certname(&cert.subject, ROOT_COUNTRY, ROOT_STATE, ROOT_LOCALITY,
                 ROOT_ORG, ROOT_COMMONNAME);
    set_certname(&cert.issuer, ROOT_COUNTRY, ROOT_STATE, ROOT_LOCALITY,
                 ROOT_ORG, ROOT_COMMONNAME);
    set_before_date_utctime(&cert, NOT_BEFORE_DATE);
    set_after_date_utctime(&cert, NOT_AFTER_DATE);
    ret = wc_MakeCert_ex(&cert, der, sizeof(der), key_type, &key, rng);
    if ((ret = wc_SignCert_ex(cert.bodySz, cert.sigType, der, sizeof(der),
                              key_type, &key, rng)) < 0)
        return ret;

    if ((ret = wc_DerToPem(der, ret, cert_pem, *cert_len, CERT_TYPE)) < 0)
        return ret;
    *cert_len = ret;

    return 0;
}

int main(void) {
    int ret = 0;
    WC_RNG rng;
    wc_InitRng(&rng);
    uint8_t cert_pem[DER_MAX_SIZE], key_pem[DER_MAX_SIZE];
    size_t cert_len = sizeof(cert_pem), key_len = sizeof(key_pem);
    ret = certgen(cert_pem, &cert_len, key_pem, &key_len, &rng);
    if (ret == 0) {
        printf("Cert PEM %zu, key PEM %zu\n", cert_len, key_len);
    } else {
        printf("err %d\n", ret);
    }
    return ret;
}

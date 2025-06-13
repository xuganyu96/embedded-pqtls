/* Generate a certificate chain: root, int, leaf, client */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sphincs.h>
#include <wolfssl/wolfcrypt/types.h>
#ifdef WOLFSSL_HAVE_KEMTLS
#include <wolfssl/wolfcrypt/hqc.h>
#include <wolfssl/wolfcrypt/pqclean_mlkem.h>
#endif

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

#define BUF_MAX_SIZE 100000
#define PATH_MAX_SIZE 1024

/* GYX: supported key types and sig types
 * ---------- classical ----------
 * RSA_TYPE + CTC_SHA256wRSA | CTC_SHA384wRSA | CTC_SHA512wRSA
 * ECC_TYPE + CTC_SHA256wECDSA | CTC_SHA384wECDSA | CTC_SHA512wECDSA
 * ED25519_TYPE + CTC_ED25519
 * ED448_TYPE + CTC_ED448
 *
 * ---------- post-quantum ----------
 * ML_DSA_LEVELx_TYPE + CTC_ML_DSA_LEVELx (x = 2, 3, 5)
 * SPHINCS_FAST_LEVELx_TYPE + CTC_SPHINCS_FAST_LEVELx (x = 1, 3)
 * SPHINCS_SMALL_LEVELx_TYPE + CTC_SPHINCS_SMALL_LEVELx (x = 1, 3, 5)
 * FALCON_LEVELx_TYPE + CTC_FALCON_LEVELx (x = 1, 5)
 *
 * NOTE: SPHINCS_FAST_LEVEL5 is too large
 * NOTES: cannot load SPHINCS or Falcon private key
 *
 * ---------- KEMTLS ----------
 * ML_KEM_LEVELx_TYPE + CTC_ML_KEM_LEVELx (x = 1, 3, 5)
 * HQC_LEVELx_TYPE + CTC_HQC_LEVELx (x = 1, 3, 5)
 */
static enum CertType root_key_type = ML_DSA_LEVEL2_TYPE;
static enum Ctc_SigType root_sig_type = CTC_ML_DSA_LEVEL2;
static enum CertType int_key_type = ML_DSA_LEVEL2_TYPE;
static enum Ctc_SigType int_sig_type = CTC_ML_DSA_LEVEL2;
/* ML-KEM-512 OID: 2.16.840.1.101.3.4.4.1
 * HQC-128 OID: 2.16.840.1.101.3.4.4.4
 * ML-DSA-44 OID: 2.16.840.1.101.3.4.3.17 */
static enum CertType leaf_key_type = HQC_LEVEL1_TYPE;
static enum Ctc_SigType leaf_sig_type = CTC_ML_DSA_LEVEL2;
static enum CertType client_key_type = ML_DSA_LEVEL2_TYPE;
static enum Ctc_SigType client_sig_type = CTC_ML_DSA_LEVEL2;

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

/* A collection of keyType values (i.e. CertType enum in `asn_public.h`)
 */
typedef struct certchain_suite {
    enum CertType root_key_type;
    enum Ctc_SigType root_sig_type;
    enum CertType int_key_type;
    enum Ctc_SigType int_sig_type;
    enum CertType leaf_key_type;
    enum Ctc_SigType leaf_sig_type;
    enum CertType client_key_type;
    enum Ctc_SigType client_sig_type;
} certchain_suite_t;

/* A collection of buffers containing the output of certificat chain generation
 *
 * TODO: statically allocating almost a mebabyte of stack memory is not deal,
 * but since this runs on a desktop (MacOS stack size can be increased to 65MB)
 * this is okay.
 */
typedef struct certchain_out {
    byte root_cert_pem[BUF_MAX_SIZE];
    size_t root_cert_len;
    byte root_key_pem[BUF_MAX_SIZE];
    size_t root_key_len;
    byte int_cert_pem[BUF_MAX_SIZE];
    size_t int_cert_len;
    byte int_key_pem[BUF_MAX_SIZE];
    size_t int_key_len;
    byte leaf_cert_pem[BUF_MAX_SIZE];
    size_t leaf_cert_len;
    byte leaf_key_pem[BUF_MAX_SIZE];
    size_t leaf_key_len;
    byte client_cert_pem[BUF_MAX_SIZE];
    size_t client_cert_len;
    byte client_key_pem[BUF_MAX_SIZE];
    size_t client_key_len;
} certchain_out_t;

static int get_server_chain(certchain_out_t *out, uint8_t *chain, size_t len,
                            int include_root) {
    size_t min_len = out->leaf_cert_len + out->int_cert_len;
    if (include_root) {
        min_len += out->root_cert_len;
    }
    if (len < min_len) {
        return BUFFER_E;
    }
    size_t offset = 0;
    memcpy(chain + offset, out->leaf_cert_pem, out->leaf_cert_len);
    offset += out->leaf_cert_len;
    memcpy(chain + offset, out->int_cert_pem, out->int_cert_len);
    offset += out->int_cert_len;
    if (include_root) {
        memcpy(chain + offset, out->root_cert_pem, out->root_cert_len);
    }

    return 0;
}

static int get_client_chain(certchain_out_t *out, uint8_t *chain, size_t len,
                            int include_root) {
    size_t min_len = out->client_cert_len;
    if (include_root)
        min_len += out->root_cert_len;
    if (len < min_len) {
        return BUFFER_E;
    }
    size_t offset = 0;
    memcpy(chain + offset, out->client_cert_pem, out->client_cert_len);
    offset += out->client_cert_len;
    if (include_root)
        memcpy(chain + offset, out->root_cert_pem, out->root_cert_len);

    return 0;
}

int is_ml_dsa(enum CertType key_type) {
    return ((key_type == ML_DSA_LEVEL2_TYPE) ||
            (key_type == ML_DSA_LEVEL3_TYPE) ||
            (key_type == ML_DSA_LEVEL5_TYPE));
}

int is_sphincs(enum CertType key_type) {
    return ((key_type == SPHINCS_FAST_LEVEL1_TYPE) ||
            (key_type == SPHINCS_SMALL_LEVEL1_TYPE) ||
            (key_type == SPHINCS_FAST_LEVEL3_TYPE) ||
            (key_type == SPHINCS_SMALL_LEVEL3_TYPE) ||
            (key_type == SPHINCS_FAST_LEVEL5_TYPE) ||
            (key_type == SPHINCS_SMALL_LEVEL5_TYPE));
}

int is_falcon(enum CertType key_type) {
    return ((key_type == FALCON_LEVEL1_TYPE) ||
            (key_type == FALCON_LEVEL5_TYPE));
}

#ifdef WOLFSSL_HAVE_KEMTLS
int is_mlkem(enum CertType key_type) {
    return ((key_type == ML_KEM_LEVEL1_TYPE) ||
            (key_type == ML_KEM_LEVEL3_TYPE) ||
            (key_type == ML_KEM_LEVEL5_TYPE));
}

int is_hqc(enum CertType key_type) {
    return ((key_type == HQC_LEVEL1_TYPE) || (key_type == HQC_LEVEL3_TYPE) ||
            (key_type == HQC_LEVEL5_TYPE));
}
#endif /* WOLFSSL_HAVE_KEMTLS */

/* Allocate memory for key types and assign it to `key`
 *
 * Return 0 upon success
 */
static int malloc_key(void **key, enum CertType key_type, size_t *key_size) {
    size_t capacity = 0;
    if (is_ml_dsa(key_type)) {
        capacity = sizeof(MlDsaKey);
#ifdef HAVE_SPHINCS
    } else if (is_sphincs(key_type)) {
        capacity = sizeof(sphincs_key);
#endif
#ifdef HAVE_FALCON
    } else if (is_falcon(key_type)) {
        capacity = sizeof(falcon_key);
#endif
#ifdef WOLFSSL_HAVE_KEMTLS
    } else if (is_mlkem(key_type)) {
        capacity = sizeof(PQCleanMlKemKey);
    } else if (is_hqc(key_type)) {
        capacity = sizeof(HqcKey);
#endif
    } else if (key_type == RSA_TYPE) {
        capacity = sizeof(RsaKey);
    } else if (key_type == ECC_TYPE) {
        capacity = sizeof(ecc_key);
    } else if (key_type == ED25519_TYPE) {
        capacity = sizeof(ed25519_key);
    } else if (key_type == ED448_TYPE) {
        capacity = sizeof(ed448_key);
    } else { /* CertType not supported */
        return BAD_FUNC_ARG;
    }

    if ((*key = malloc(capacity)) == NULL) {
        return MEMORY_E;
    } else {
        *key_size = capacity;
    }

    return 0;
}

/* A wrapper around the function calls needed to generate an RSA-2048 keypair
 *
 * TODO: there is exactly one RsaKey type, but there might be multiple RSA
 *       signature types, which is the case for ECDSA and EdDSA as well
 */
static int gen_rsa2048(RsaKey *key, uint8_t *pem, size_t *pem_len,
                       WC_RNG *rng) {
    int ret = 0;
    uint8_t der[BUF_MAX_SIZE];
    int der_sz, pem_sz;
    if ((ret = wc_InitRsaKey_ex(key, NULL, INVALID_DEVID)) < 0) {
        return ret;
    }
    if ((ret = wc_MakeRsaKey(key, 2048, WC_RSA_EXPONENT, rng)) < 0) {
        return ret;
    }
    der_sz = wc_RsaKeyToDer(key, der, sizeof(der));
    if (der_sz <= 0) {
        return der_sz;
    }
    pem_sz = wc_DerToPem(der, der_sz, pem, *pem_len, RSA_TYPE);
    if (pem_sz <= 0) {
        return pem_sz;
    }
    *pem_len = pem_sz;

    return ret;
}

/* Init and make ECDSA key
 *
 * Return 0 upon success
 */
static int gen_ecdsa(ecc_key *key, enum Ctc_SigType sig_type, uint8_t *pem,
                     size_t *pem_len, WC_RNG *rng) {
    int ret = 0;
    int curve_id;
    uint8_t der[BUF_MAX_SIZE];
    int der_sz, pem_sz;

    switch (sig_type) {
    case CTC_SHA256wECDSA:
        curve_id = ECC_SECP256R1;
        break;
    case CTC_SHA384wECDSA:
        curve_id = ECC_SECP384R1;
        break;
    case CTC_SHA512wECDSA:
        curve_id = ECC_SECP521R1;
        break;
    default:
        return BAD_FUNC_ARG;
    }
    int keysize = wc_ecc_get_curve_size_from_id(curve_id);

    if ((ret = wc_ecc_init_ex(key, NULL, INVALID_DEVID)) < 0) {
        return ret;
    }
    if ((ret = wc_ecc_make_key_ex(rng, keysize, key, curve_id)) < 0) {
        return ret;
    }
    if ((ret = wc_ecc_check_key(key)) < 0) {
        return ret;
    }
    der_sz = wc_EccKeyToDer(key, der, sizeof(der));
    if (der_sz <= 0) {
        return der_sz;
    }
    pem_sz = wc_DerToPem(der, der_sz, pem, *pem_len, ECC_TYPE);
    if (pem_sz <= 0) {
        return pem_sz;
    }
    *pem_len = pem_sz;

    return ret;
}

static int gen_ed25519(ed25519_key *key, uint8_t *pem, size_t *pem_len,
                       WC_RNG *rng) {
    int ret = 0;
    uint8_t der[BUF_MAX_SIZE];
    int der_sz, pem_sz;
    if ((ret = wc_ed25519_init(key)) < 0) {
        return ret;
    }
    if ((ret = wc_ed25519_make_key(rng, 32, key)) < 0) {
        return ret;
    }
    der_sz = wc_Ed25519KeyToDer(key, der, sizeof(der));
    if (der_sz <= 0) {
        return der_sz;
    }
    pem_sz = wc_DerToPem(der, der_sz, pem, *pem_len, ED25519_TYPE);
    if (pem_sz <= 0) {
        return pem_sz;
    }
    *pem_len = pem_sz;

    return ret;
}

static int gen_ed448(ed448_key *key, uint8_t *pem, size_t *pem_len,
                     WC_RNG *rng) {
    int ret = 0;
    uint8_t der[BUF_MAX_SIZE];
    int der_sz, pem_sz;
    if ((ret = wc_ed448_init(key)) < 0) {
        return ret;
    }
    if ((ret = wc_ed448_make_key(rng, 57, key)) < 0) {
        return ret;
    }
    der_sz = wc_Ed448KeyToDer(key, der, sizeof(der));
    if (der_sz <= 0) {
        return der_sz;
    }
    pem_sz = wc_DerToPem(der, der_sz, pem, *pem_len, ED448_TYPE);
    if (pem_sz <= 0) {
        return pem_sz;
    }
    *pem_len = pem_sz;
    return ret;
}

static int gen_mldsa(MlDsaKey *key, enum CertType key_type, uint8_t *pem,
                     size_t *pem_len, WC_RNG *rng) {
    int level, ret, der_sz, pem_sz;
    uint8_t der[BUF_MAX_SIZE];

    switch (key_type) {
    case ML_DSA_LEVEL2_TYPE:
        level = WC_ML_DSA_44;
        break;
    case ML_DSA_LEVEL3_TYPE:
        level = WC_ML_DSA_65;
        break;
    case ML_DSA_LEVEL5_TYPE:
        level = WC_ML_DSA_87;
        break;
    default:
        return BAD_FUNC_ARG;
    }

    if ((ret = wc_MlDsaKey_Init(key, NULL, INVALID_DEVID)) < 0) {
        return ret;
    }
    if ((ret = wc_MlDsaKey_SetParams(key, level)) < 0) {
        return ret;
    }
    if ((ret = wc_MlDsaKey_MakeKey(key, rng)) < 0) {
        return ret;
    }
    der_sz = wc_MlDsaKey_PrivateKeyToDer(key, der, sizeof(der));
    if (der_sz <= 0) {
        return der_sz;
    }
    pem_sz = wc_DerToPem(der, der_sz, pem, *pem_len, PKCS8_PRIVATEKEY_TYPE);
    if (pem_sz <= 0) {
        return pem_sz;
    }
    *pem_len = pem_sz;

    return ret;
}

#ifdef HAVE_SPHINCS
static int gen_sphincs(sphincs_key *key, enum CertType key_type, uint8_t *pem,
                       size_t *pem_len, WC_RNG *rng) {
    int ret, der_sz, pem_sz;
    uint8_t der[BUF_MAX_SIZE];
    byte level, optim;
    switch (key_type) {
    case SPHINCS_FAST_LEVEL1_TYPE:
        level = 1;
        optim = FAST_VARIANT;
        break;
    case SPHINCS_SMALL_LEVEL1_TYPE:
        level = 1;
        optim = SMALL_VARIANT;
        break;
    case SPHINCS_FAST_LEVEL3_TYPE:
        level = 3;
        optim = FAST_VARIANT;
        break;
    case SPHINCS_SMALL_LEVEL3_TYPE:
        level = 3;
        optim = SMALL_VARIANT;
        break;
    case SPHINCS_FAST_LEVEL5_TYPE:
        level = 5;
        optim = FAST_VARIANT;
        break;
    case SPHINCS_SMALL_LEVEL5_TYPE:
        level = 5;
        optim = SMALL_VARIANT;
        break;
    default:
        return BAD_FUNC_ARG;
    }

    if ((ret = wc_sphincs_init(key)) < 0) {
        return ret;
    }
    if ((ret = wc_sphincs_set_level_and_optim(key, level, optim)) < 0) {
        return ret;
    }
    if ((ret = wc_sphincs_make_key(key, rng)) < 0) {
        return ret;
    }
    der_sz = wc_Sphincs_PrivateKeyToDer(key, der, sizeof(der));
    if (der_sz <= 0) {
        return der_sz;
    }
    pem_sz = wc_DerToPem(der, der_sz, pem, *pem_len, PKCS8_PRIVATEKEY_TYPE);
    if (pem_sz <= 0) {
        return pem_sz;
    }
    *pem_len = pem_sz;

    return ret;
}
#endif /* HAVE_SPHINCS */

#ifdef HAVE_FALCON
static int gen_falcon(falcon_key *key, enum CertType key_type, uint8_t *pem,
                      size_t *pem_len, WC_RNG *rng) {
    byte level;
    int ret, der_sz, pem_sz;
    uint8_t der[BUF_MAX_SIZE];

    switch (key_type) {
    case FALCON_LEVEL1_TYPE:
        level = 1;
        break;
    case FALCON_LEVEL5_TYPE:
        level = 5;
        break;
    default:
        return BAD_FUNC_ARG;
    }

    if ((ret = wc_falcon_init(key)) < 0) {
        return ret;
    }
    if ((ret = wc_falcon_set_level(key, level)) < 0) {
        return ret;
    }
    if ((ret = wc_falcon_make_key(key, rng)) < 0) {
        return ret;
    }
    der_sz = wc_Falcon_PrivateKeyToDer(key, der, sizeof(der));
    if (der_sz <= 0) {
        return der_sz;
    }
    pem_sz = wc_DerToPem(der, der_sz, pem, *pem_len, PKCS8_PRIVATEKEY_TYPE);
    if (pem_sz <= 0) {
        return pem_sz;
    }
    *pem_len = pem_sz;

    return ret;
}
#endif /* HAVE_FALCON */

#ifdef WOLFSSL_HAVE_KEMTLS
static int gen_mlkem(PQCleanMlKemKey *key, enum CertType key_type, uint8_t *pem,
                     size_t *pem_len, WC_RNG *rng) {
    int level, ret, der_sz, pem_sz;
    uint8_t der[BUF_MAX_SIZE];

    switch (key_type) {
    case ML_KEM_LEVEL1_TYPE:
        level = 1;
        break;
    case ML_KEM_LEVEL3_TYPE:
        level = 3;
        break;
    case ML_KEM_LEVEL5_TYPE:
        level = 5;
        break;
    default:
        return BAD_FUNC_ARG;
    }

    if ((ret = wc_PQCleanMlKemKey_Init(key)) < 0) {
        return ret;
    }
    if ((ret = wc_PQCleanMlKemKey_SetLevel(key, level)) < 0) {
        return ret;
    }
    if ((ret = wc_PQCleanMlKemKey_MakeKey(key, rng)) < 0) {
        return ret;
    }
    der_sz = wc_PQCleanMlKemKey_PrivateKeyToDer(key, der, sizeof(der));
    if (der_sz <= 0) {
        return der_sz;
    }
    pem_sz = wc_DerToPem(der, der_sz, pem, *pem_len, PKCS8_PRIVATEKEY_TYPE);
    if (pem_sz <= 0) {
        return pem_sz;
    }
    *pem_len = pem_sz;
    return ret;
}

static int gen_hqc(HqcKey *key, enum CertType key_type, uint8_t *pem,
                   size_t *pem_len, WC_RNG *rng) {
    int level, ret, der_sz, pem_sz;
    uint8_t der[BUF_MAX_SIZE];

    switch (key_type) {
    case HQC_LEVEL1_TYPE:
        level = 1;
        break;
    case HQC_LEVEL3_TYPE:
        level = 3;
        break;
    case HQC_LEVEL5_TYPE:
        level = 5;
        break;
    default:
        return BAD_FUNC_ARG;
    }

    if ((ret = wc_HqcKey_Init(key)) < 0) {
        return ret;
    }
    if ((ret = wc_HqcKey_SetLevel(key, level)) < 0) {
        return ret;
    }
    if ((ret = wc_HqcKey_MakeKey(key, rng)) < 0) {
        return ret;
    }
    der_sz = wc_HqcKey_PrivateKeyToDer(key, der, sizeof(der));
    if (der_sz <= 0) {
        return der_sz;
    }
    pem_sz = wc_DerToPem(der, der_sz, pem, *pem_len, PKCS8_PRIVATEKEY_TYPE);
    if (pem_sz <= 0) {
        return pem_sz;
    }
    *pem_len = pem_sz;
    return ret;
}
#endif /* WOLFSSL_HAVE_KEMTLS */

/* Given appropriate key type, generate a keypair with matching primitive
 * (ML-DSA or SPHINCS or Falcon etc.) and assign it to `key`, then export the
 * private key to `pem`
 *
 * The keypair will be allocated from the heap, so it will need to be freed
 * later.
 *
 * sig_type is specifically used for generating ECDSA keypair, supported values
 * are CTC_SHA256wECDSA (using P-256), CTC_SHA3844wECDSA (using P-384), and
 * CTC_SHA512wECDSA (using P-521). In all other cases sig_type is ignored.
 *
 * pem_len contains the capacity of the pem buffer at input, and will contain
 * the length of data after return
 */
static int gen_keypair(void **key, enum CertType key_type, size_t *key_size,
                       enum Ctc_SigType sig_type, uint8_t *pem, size_t *pem_len,
                       WC_RNG *rng) {
    int ret = 0;

    if ((key == NULL) || (rng == NULL))
        return BAD_FUNC_ARG;
    if ((ret = malloc_key(key, key_type, key_size)) != 0) {
        fprintf(stderr, "Failed to allocate space for key (err %d)\n", ret);
        return ret;
    }

    /* inelegant, giant switch case block; can we do better? */
    switch (key_type) {
    case RSA_TYPE:
        ret = gen_rsa2048(*key, pem, pem_len, rng);
        break;
    case ECC_TYPE:
        ret = gen_ecdsa(*key, sig_type, pem, pem_len, rng);
        break;
    case ED25519_TYPE:
        ret = gen_ed25519(*key, pem, pem_len, rng);
        break;
    case ED448_TYPE:
        ret = gen_ed448(*key, pem, pem_len, rng);
        break;
    case ML_DSA_LEVEL2_TYPE:
    case ML_DSA_LEVEL3_TYPE:
    case ML_DSA_LEVEL5_TYPE:
        ret = gen_mldsa(*key, key_type, pem, pem_len, rng);
        break;
#ifdef HAVE_SPHINCS
    case SPHINCS_FAST_LEVEL1_TYPE:
    case SPHINCS_SMALL_LEVEL1_TYPE:
    case SPHINCS_FAST_LEVEL3_TYPE:
    case SPHINCS_SMALL_LEVEL3_TYPE:
    case SPHINCS_FAST_LEVEL5_TYPE:
    case SPHINCS_SMALL_LEVEL5_TYPE:
        ret = gen_sphincs(*key, key_type, pem, pem_len, rng);
        break;
#endif
#ifdef HAVE_FALCON
    case FALCON_LEVEL1_TYPE:
    case FALCON_LEVEL5_TYPE:
        ret = gen_falcon(*key, key_type, pem, pem_len, rng);
        break;
#endif
#ifdef WOLFSSL_HAVE_KEMTLS
    case ML_KEM_LEVEL1_TYPE:
    case ML_KEM_LEVEL3_TYPE:
    case ML_KEM_LEVEL5_TYPE:
        ret = gen_mlkem(*key, key_type, pem, pem_len, rng);
        break;
    case HQC_LEVEL1_TYPE:
    case HQC_LEVEL3_TYPE:
    case HQC_LEVEL5_TYPE:
        ret = gen_hqc(*key, key_type, pem, pem_len, rng);
        break;
#endif
    default:
        fprintf(stderr, "enum CertType %d not supported\n", key_type);
        return BAD_FUNC_ARG;
    }

    return ret;
}

/* Generate a certificate chain according to the suite and write the output to
 * `out`.
 *
 * The chain contains a root certificate, an intermediate certificate, a leaf
 * certificate for server authentication, and a client certificate for client
 * authentication. For the purpose of this project, it is sufficient to output
 * the root certificate, the server certificate chain, the client certificate
 * chain, the server authentication key, and the client authentication key.
 * Things like the root key and the intermediate key are single-use and
 * discarded.
 *
 * Return 0 upon success, or non-zero error code upon failure.
 */
static int gen_cert_chain(certchain_suite_t suite, certchain_out_t *out,
                          WC_RNG *rng) {
    int err;

    void *root_key = NULL, *int_key = NULL, *leaf_key = NULL,
         *client_key = NULL;
    size_t root_key_sz = 0, int_key_sz = 0, leaf_key_sz = 0, client_key_sz = 0,
           key_pem_sz;
    int root_cert_der_sz, root_cert_pem_sz, int_cert_der_sz, int_cert_pem_sz,
        leaf_cert_der_sz, leaf_cert_pem_sz, client_cert_der_sz,
        client_cert_pem_sz;
    uint8_t root_cert_der[BUF_MAX_SIZE], int_cert_der[BUF_MAX_SIZE],
        leaf_cert_der[BUF_MAX_SIZE], client_cert_der[BUF_MAX_SIZE];
    Cert root_cert, int_cert, leaf_cert, client_cert;

    /* root certificate */
    key_pem_sz = sizeof(out->root_key_pem);
    if ((err = gen_keypair(&root_key, suite.root_key_type, &root_key_sz,
                           suite.root_sig_type, out->root_key_pem, &key_pem_sz,
                           rng)) != 0) {
        fprintf(stderr, "Failed to generate root key pair (err %d)\n", err);
        goto cleanup;
    } else {
        out->root_key_len = key_pem_sz;
        printf("root key PEM size %zu\n", out->root_key_len);
    }
    wc_InitCert(&root_cert);
    root_cert.sigType = suite.root_sig_type;
    root_cert.isCA = 1;
    set_certname(&root_cert.subject, ROOT_COUNTRY, ROOT_STATE, ROOT_LOCALITY,
                 ROOT_ORG, ROOT_COMMONNAME);
    set_certname(&root_cert.issuer, ROOT_COUNTRY, ROOT_STATE, ROOT_LOCALITY,
                 ROOT_ORG, ROOT_COMMONNAME);
    set_before_date_utctime(&root_cert, NOT_BEFORE_DATE);
    set_after_date_utctime(&root_cert, NOT_AFTER_DATE);
    if ((root_cert_der_sz =
             wc_MakeCert_ex(&root_cert, root_cert_der, sizeof(root_cert_der),
                            suite.root_key_type, root_key, rng)) <= 0) {
        err = root_cert_der_sz;
        fprintf(stderr, "Failed to make root cert body (err %d)\n", err);
        goto cleanup;
    } else {
        printf("root cert (unsigned) DER size %d\n", root_cert_der_sz);
    }
    root_cert_der_sz = wc_SignCert_ex(root_cert.bodySz, root_cert.sigType,
                                      root_cert_der, sizeof(root_cert_der),
                                      suite.root_key_type, root_key, rng);
    if (root_cert_der_sz <= 0) {
        err = root_cert_der_sz;
        fprintf(stderr, "Failed to sign root cert (err %d)\n", err);
        goto cleanup;
    } else {
        printf("root cert (signed) DER size %d\n", root_cert_der_sz);
    }
    root_cert_pem_sz =
        wc_DerToPem(root_cert_der, root_cert_der_sz, out->root_cert_pem,
                    sizeof(out->root_cert_pem), CERT_TYPE);
    if (root_cert_pem_sz <= 0) {
        err = root_cert_pem_sz;
        fprintf(stderr, "Failed to export root cert PEM (err %d)\n", err);
        goto cleanup;
    } else {
        out->root_cert_len = (size_t)root_cert_pem_sz;
        printf("root cert PEM size %zu\n", out->root_cert_len);
    }

    /* intermediate certificate */
    key_pem_sz = sizeof(out->int_key_pem);
    if ((err = gen_keypair(&int_key, suite.int_key_type, &int_key_sz,
                           suite.int_sig_type, out->int_key_pem, &key_pem_sz,
                           rng)) != 0) {
        fprintf(stderr, "Failed to generate intermediate key (err %d)\n", err);
        goto cleanup;
    } else {
        out->int_key_len = key_pem_sz;
        printf("key PEM size %zu\n", out->int_key_len);
    }
    wc_InitCert(&int_cert);
    int_cert.sigType = suite.root_sig_type;
    int_cert.isCA = 1;
    wc_SetIssuerBuffer(&int_cert, root_cert_der, root_cert_der_sz);
    set_certname(&int_cert.subject, ROOT_COUNTRY, ROOT_STATE, ROOT_LOCALITY,
                 ROOT_ORG, ROOT_COMMONNAME);
    set_before_date_utctime(&int_cert, NOT_BEFORE_DATE);
    set_after_date_utctime(&int_cert, NOT_AFTER_DATE);
    if ((int_cert_der_sz =
             wc_MakeCert_ex(&int_cert, int_cert_der, sizeof(int_cert_der),
                            suite.int_key_type, int_key, rng)) <= 0) {
        err = int_cert_der_sz;
        fprintf(stderr, "Failed to make unsigned int certificate (err %d)\n",
                err);
        goto cleanup;
    } else {
        printf("int cert (unsigned) DER size %d\n", int_cert_der_sz);
    }
    if ((int_cert_der_sz = wc_SignCert_ex(
             int_cert.bodySz, int_cert.sigType, int_cert_der,
             sizeof(int_cert_der), suite.root_key_type, root_key, rng)) <= 0) {
        err = int_cert_der_sz;
        fprintf(stderr, "Failed to sign int certificate (err %d)\n", err);
        goto cleanup;
    } else {
        printf("int cert (signed) DER size %d\n", int_cert_der_sz);
    }
    if ((int_cert_pem_sz =
             wc_DerToPem(int_cert_der, int_cert_der_sz, out->int_cert_pem,
                         sizeof(out->int_cert_pem), CERT_TYPE)) <= 0) {
        err = int_cert_pem_sz;
        fprintf(stderr, "Failed to export int cert PEM (err %d)\n", err);
        goto cleanup;
    } else {
        out->int_cert_len = (size_t)int_cert_pem_sz;
        printf("int cert PEM size %zu\n", out->int_cert_len);
    }

    /* leaf certificate */
    key_pem_sz = sizeof(out->leaf_key_pem);
    if ((err = gen_keypair(&leaf_key, suite.leaf_key_type, &leaf_key_sz,
                           suite.leaf_sig_type, out->leaf_key_pem, &key_pem_sz,
                           rng)) != 0) {
        fprintf(stderr, "Failed to generate leaf key (err %d)\n", err);
        goto cleanup;
    } else {
        out->leaf_key_len = key_pem_sz;
        printf("leaf key PEM size %zu\n", out->leaf_key_len);
    }
    wc_InitCert(&leaf_cert);
    leaf_cert.sigType = suite.int_sig_type;
    wc_SetIssuerBuffer(&leaf_cert, int_cert_der, int_cert_der_sz);
    set_certname(&leaf_cert.subject, LEAF_COUNTRY, LEAF_STATE, LEAF_LOCALITY,
                 LEAF_ORG, LEAF_COMMONNAME);
    set_before_date_utctime(&leaf_cert, NOT_BEFORE_DATE);
    set_after_date_utctime(&leaf_cert, NOT_AFTER_DATE);
    if ((leaf_cert_der_sz =
             wc_MakeCert_ex(&leaf_cert, leaf_cert_der, sizeof(leaf_cert_der),
                            suite.leaf_key_type, leaf_key, rng)) <= 0) {
        err = leaf_cert_der_sz;
        fprintf(stderr, "Failed to make unsigned leaf certificate (err %d)\n",
                err);
        goto cleanup;
    } else {
        printf("leaf cert (unsigned) DER size %d\n", leaf_cert_der_sz);
    }
    if ((leaf_cert_der_sz = wc_SignCert_ex(
             leaf_cert.bodySz, leaf_cert.sigType, leaf_cert_der,
             sizeof(leaf_cert_der), suite.int_key_type, int_key, rng)) <= 0) {
        err = leaf_cert_der_sz;
        fprintf(stderr, "Failed to sign leaf certificate (err %d)\n", err);
        goto cleanup;
    } else {
        printf("leaf cert (signed) DER size %d\n", leaf_cert_der_sz);
    }
    if ((leaf_cert_pem_sz =
             wc_DerToPem(leaf_cert_der, leaf_cert_der_sz, out->leaf_cert_pem,
                         sizeof(out->leaf_cert_pem), CERT_TYPE)) <= 0) {
        err = leaf_cert_pem_sz;
        fprintf(stderr, "Failed to export leaf cert PEM (err %d)\n", err);
        goto cleanup;
    } else {
        out->leaf_cert_len = (size_t)leaf_cert_pem_sz;
        printf("leaf cert PEM size %zu\n", out->leaf_cert_len);
    }

    /* client certificate */
    key_pem_sz = sizeof(out->client_key_pem);
    if ((err = gen_keypair(&client_key, suite.client_key_type, &client_key_sz,
                           suite.client_sig_type, out->client_key_pem,
                           &key_pem_sz, rng)) != 0) {
        fprintf(stderr, "Failed to generate client key (err %d)\n", err);
        goto cleanup;
    } else {
        out->client_key_len = key_pem_sz;
        printf("client key PEM size %zu\n", out->client_key_len);
    }
    wc_InitCert(&client_cert);
    client_cert.sigType = suite.root_sig_type;
    wc_SetIssuerBuffer(&client_cert, root_cert_der, root_cert_der_sz);
    set_certname(&client_cert.subject, LEAF_COUNTRY, LEAF_STATE, LEAF_LOCALITY,
                 LEAF_ORG, LEAF_COMMONNAME);
    set_before_date_utctime(&client_cert, NOT_BEFORE_DATE);
    set_after_date_utctime(&client_cert, NOT_AFTER_DATE);
    if ((client_cert_der_sz = wc_MakeCert_ex(
             &client_cert, client_cert_der, sizeof(client_cert_der),
             suite.client_key_type, client_key, rng)) <= 0) {
        err = client_cert_der_sz;
        fprintf(stderr, "Failed to make unsigned client certificate (err %d)\n",
                err);
        goto cleanup;
    } else {
        printf("client cert (unsigned) DER size %d\n", client_cert_der_sz);
    }
    if ((client_cert_der_sz =
             wc_SignCert_ex(client_cert.bodySz, client_cert.sigType,
                            client_cert_der, sizeof(client_cert_der),
                            suite.root_key_type, root_key, rng)) <= 0) {
        err = client_cert_der_sz;
        fprintf(stderr, "Failed to sign client certificate (err %d)\n", err);
        goto cleanup;
    } else {
        printf("client cert (signed) DER size %d\n", client_cert_der_sz);
    }
    if ((client_cert_pem_sz = wc_DerToPem(
             client_cert_der, client_cert_der_sz, out->client_cert_pem,
             sizeof(out->leaf_cert_pem), CERT_TYPE)) <= 0) {
        err = client_cert_pem_sz;
        fprintf(stderr, "Failed to export leaf cert PEM (err %d)\n", err);
        goto cleanup;
    } else {
        out->client_cert_len = (size_t)client_cert_pem_sz;
        printf("client cert PEM size %zu\n", out->client_cert_len);
    }

cleanup:
    if (root_key) {
        memset(root_key, 0, root_key_sz);
        free(root_key);
    }
    if (int_key) {
        memset(int_key, 0, int_key_sz);
        free(int_key);
    }
    if (leaf_key) {
        memset(leaf_key, 0, leaf_key_sz);
        free(leaf_key);
    }
    if (client_key) {
        memset(client_key, 0, client_key_sz);
        free(client_key);
    }
    return err;
}

/* holds the path to the directory */
typedef struct {
    char certdir[PATH_MAX_SIZE];
} cli_args_t;

static int parse_args(cli_args_t *args, int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <dir>\n", argv[0]);
        return -1;
    }

    const char *dir = argv[1];
    struct stat st;
    if (stat(dir, &st) != 0) {
        fprintf(stderr, "Error accessing the %s", dir);
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: '%s' is not a directory.\n", dir);
        return -1;
    }

    strncpy(args->certdir, dir, sizeof(args->certdir));
    return 0;
}

/* write PEM to <dir>/<filename>
 *
 * Return 0 on success
 */
static int export_pem(const char *dir, const char *filename, uint8_t *pem,
                      size_t pemlen) {
    char filepath[PATH_MAX_SIZE];
    snprintf(filepath, sizeof(filepath), "%s/%s", dir, filename);
    FILE *file = fopen(filepath, "w");
    if (!file) {
        fprintf(stderr, "Failed to open %s\n", filepath);
        return -1;
    }
    size_t written = fwrite(pem, sizeof(uint8_t), pemlen, file);
    if (written < pemlen) {
        fprintf(stderr, "Partial write: %zu out of %zu bytes\n", written,
                pemlen);
        fclose(file);
        return -1;
    }
    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {
    int ret = 0;
    cli_args_t cli_args;
    WC_RNG rng;
    wc_InitRng(&rng);
    certchain_out_t out;
    uint8_t server_chain_pem[BUF_MAX_SIZE * 3],
        client_chain_pem[BUF_MAX_SIZE * 2];

    memset(&cli_args, 0, sizeof(cli_args_t));
    ret = parse_args(&cli_args, argc, argv);
    if (ret != 0)
        return ret;

    certchain_suite_t suite = {root_key_type,   root_sig_type,  int_key_type,
                               int_sig_type,    leaf_key_type,  leaf_sig_type,
                               client_key_type, client_sig_type};
    ret = gen_cert_chain(suite, &out, &rng);
    if (ret != 0)
        return ret;
    size_t server_chain_len =
        out.root_cert_len + out.int_cert_len + out.leaf_cert_len;
    size_t client_chain_len = out.root_cert_len + out.client_cert_len;
    get_server_chain(&out, server_chain_pem, sizeof(server_chain_pem), 0);
    get_client_chain(&out, client_chain_pem, sizeof(client_chain_pem), 0);

    export_pem(cli_args.certdir, "root.crt", out.root_cert_pem,
               out.root_cert_len);
    export_pem(cli_args.certdir, "root.key", out.root_key_pem,
               out.root_key_len);
    export_pem(cli_args.certdir, "int.crt", out.int_cert_pem, out.int_cert_len);
    export_pem(cli_args.certdir, "int.key", out.int_key_pem, out.int_key_len);
    export_pem(cli_args.certdir, "leaf.crt", out.leaf_cert_pem,
               out.leaf_cert_len);
    export_pem(cli_args.certdir, "leaf.key", out.leaf_key_pem,
               out.leaf_key_len);
    export_pem(cli_args.certdir, "client.crt", out.client_cert_pem,
               out.client_cert_len);
    export_pem(cli_args.certdir, "client.key", out.client_key_pem,
               out.client_key_len);
    export_pem(cli_args.certdir, "server-chain.crt", server_chain_pem,
               server_chain_len);
    export_pem(cli_args.certdir, "client-chain.crt", client_chain_pem,
               client_chain_len);

    return ret;
}

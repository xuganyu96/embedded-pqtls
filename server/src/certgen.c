#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/oid_sum.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/rsa.h"

#define IS_CA 1
#define NOT_CA 0
#define MAX_DIRPATH_SZ 512
#define MAX_DER_SZ 12000
#define MAX_PEM_SZ MAX_DER_SZ
#define COUNTRY "CA"
#define STATE "ON"
#define LOCALITY "Waterloo"
#define ORG "University of Waterloo"
/* UTCTime format: YYMMDDHHMMSSZ */
#define BEFORE_DATE "250101000000Z"
#define LONG_AFTER_DATE "350101000000Z"   /* 10 years */
#define MEDIUM_AFTER_DATE "280501115930Z" /* 3 years */
#define SHORT_AFTER_DATE "261230115930Z"  /* 1-2 years */

/* TODO: WolfSSL does not support signing certificate from Certificate Signing
 * Request (CSR) in the same way OpenSSL could. This program is very much
 * limited to the certificate chain structure that
 */
#define HELP_STR                                                               \
    "Usage: certgen <root> <int> <server> <client> <dir>\n"                    \
    "Generate a certificate chain and write the files to <dir>\n"              \
    "The first four arguments must be one of the supported signature type:\n"  \
    "    - sha256rsa: 2048-bit RSA w/ SHA-256\n"                               \
    "    - sha384rsa: 2048-bit RSA w/ SHA-384\n"                               \
    "    - sha512rsa: 2048-bit RSA w/ SHA-512\n"                               \
    "    - sha256ecdsa: ECDSA with P-256\n"                                    \
    "    - sha384ecdsa: ECDSA with P-384\n"                                    \
    "    - sha512ecdsa: ECDSA with P-521\n"                                    \
    "    - ed25519: EdDSA with curve 25519\n"                                  \
    "    - ed448: EdDSA with curve 448\n"                                      \
    "    - mldsa44: ML-DSA-44\n"                                               \
    "    - mldsa65: ML-DSA-65\n"                                               \
    "    - mldsa87: ML-DSA-87"
#define SIGTYPE_SHA256RSA "sha256rsa"
#define SIGTYPE_SHA384RSA "sha384rsa"
#define SIGTYPE_SHA512RSA "sha512rsa"
#define SIGTYPE_SHA256ECDSA "sha256ecdsa"
#define SIGTYPE_SHA384ECDSA "sha384ecdsa"
#define SIGTYPE_SHA512ECDSA "sha512ecdsa"
#define SIGTYPE_ED25519 "ed25519"
#define SIGTYPE_ED448 "ed448"
#define SIGTYPE_MLDSA44 "mldsa44"
#define SIGTYPE_MLDSA65 "mldsa65"
#define SIGTYPE_MLDSA87 "mldsa87"

/* Write data to <dir>/<filename>
 *
 * It is safe to assume that `dir` will not end on a slash
 */
static int write_to_file(const char *dir, const char *filename, uint8_t *data,
                         size_t len) {
    int err = 0;
    char filepath[MAX_DIRPATH_SZ];
    snprintf(filepath, sizeof(filepath), "%s/%s", dir, filename);
    FILE *dst = fopen(filepath, "wb");
    if (dst == NULL) {
        fprintf(stderr, "Failed to open %s\n", filepath);
        return -1;
    }
    size_t written = fwrite(data, sizeof(uint8_t), len, dst);
    if (written < len) {
        fprintf(stderr, "Wrote %zu out of %zu bytes\n", written, len);
    }
    fclose(dst);

    return err;
}

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
 *
 * @param dst: must be cert->beforeDate or cert->afterDate
 * @param dst_sz: must be pointer to cert->beforeDateSz or cert->afterDateSz
 */
static void set_utctime(byte *dst, int *dst_sz, const char *datestr) {
    dst[0] = ASN_UTC_TIME;
    dst[1] = ASN_UTC_TIME_SIZE - 1;
    memcpy(dst + 2, datestr, strlen(datestr));
    *dst_sz = 2 + strlen(datestr);
}

void example(void) {
    int err, der_len, pem_len;
    size_t written;
    ecc_key key;
    FILE *fd;
    int curve_size = wc_ecc_get_curve_size_from_id(ECC_SECP256R1);
    uint8_t der[MAX_DER_SZ], pem[MAX_PEM_SZ];
    WC_RNG rng;
    const char keyfile[] = "root.key";
    const char certfile[] = "root.crt";

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
    set_utctime(cert.beforeDate, &cert.beforeDateSz, BEFORE_DATE);
    set_utctime(cert.afterDate, &cert.afterDateSz, LONG_AFTER_DATE);
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

    if ((fd = fopen(certfile, "wb")) == NULL) {
        fprintf(stderr, "Failed to open %s\n", certfile);
        exit(EXIT_FAILURE);
    }
    written = fwrite(pem, sizeof(uint8_t), pem_len, fd);
    printf("Wrote %zu bytes to %s\n", written, certfile);
    fclose(fd);

    printf("Ok.\n");
}

struct CliArgs {
    int root_key_type;
    int root_sig_type;
    int int_key_type;
    int int_sig_type;
    int server_key_type;
    int server_sig_type;
    int client_key_type;
    int client_sig_type;
    char certdir[MAX_DIRPATH_SZ];
};

/* Given the name of signature type, set the appropriate key_type and sig_type
 *
 * Return 0 on success
 */
static int get_keytype_sigtype(int *key_type, int *sig_type, const char *name) {
    if ((key_type == NULL) || (sig_type == NULL) || (name == NULL)) {
        return BAD_FUNC_ARG;
    }
    if (strncmp(name, SIGTYPE_SHA256RSA, sizeof(SIGTYPE_SHA256RSA)) == 0) {
        *key_type = RSA_TYPE;
        *sig_type = CTC_SHA256wRSA;
        return 0;
    }
    if (strncmp(name, SIGTYPE_SHA384RSA, sizeof(SIGTYPE_SHA384RSA)) == 0) {
        *key_type = RSA_TYPE;
        *sig_type = CTC_SHA384wRSA;
        return 0;
    }
    if (strncmp(name, SIGTYPE_SHA512RSA, sizeof(SIGTYPE_SHA512RSA)) == 0) {
        *key_type = RSA_TYPE;
        *sig_type = CTC_SHA512wRSA;
        return 0;
    }
    if (strncmp(name, SIGTYPE_SHA256ECDSA, sizeof(SIGTYPE_SHA256ECDSA)) == 0) {
        *key_type = ECC_TYPE;
        *sig_type = CTC_SHA256wECDSA;
        return 0;
    }
    if (strncmp(name, SIGTYPE_SHA384ECDSA, sizeof(SIGTYPE_SHA384ECDSA)) == 0) {
        *key_type = ECC_TYPE;
        *sig_type = CTC_SHA384wECDSA;
        return 0;
    }
    if (strncmp(name, SIGTYPE_SHA512ECDSA, sizeof(SIGTYPE_SHA512ECDSA)) == 0) {
        *key_type = ECC_TYPE;
        *sig_type = CTC_SHA512wECDSA;
        return 0;
    }
    if (strncmp(name, SIGTYPE_ED25519, sizeof(SIGTYPE_ED25519)) == 0) {
        *key_type = ED25519_TYPE;
        *sig_type = CTC_ED25519;
        return 0;
    }
    if (strncmp(name, SIGTYPE_ED448, sizeof(SIGTYPE_ED448)) == 0) {
        *key_type = ED448_TYPE;
        *sig_type = CTC_ED448;
        return 0;
    }
    if (strncmp(name, SIGTYPE_MLDSA44, sizeof(SIGTYPE_MLDSA44)) == 0) {
        *key_type = ML_DSA_LEVEL2_TYPE;
        *sig_type = CTC_ML_DSA_LEVEL2;
    }
    if (strncmp(name, SIGTYPE_MLDSA65, sizeof(SIGTYPE_MLDSA65)) == 0) {
        *key_type = ML_DSA_LEVEL3_TYPE;
        *sig_type = CTC_ML_DSA_LEVEL3;
    }
    if (strncmp(name, SIGTYPE_MLDSA87, sizeof(SIGTYPE_MLDSA87)) == 0) {
        *key_type = ML_DSA_LEVEL5_TYPE;
        *sig_type = CTC_ML_DSA_LEVEL5;
    }
    return BAD_FUNC_ARG;
}

/* Return 1 if dirpath points to a valid directory, 0 otherwise */
static int is_valid_dir(const char *dirpath) {
    struct stat dirstat;
    if (stat(dirpath, &dirstat) != 0) {
        return 0;
    }
    if (strlen(dirpath) > MAX_DIRPATH_SZ) {
        fprintf(stderr, "Error: directory path exceeds limit\n");
        return 0;
    }
    return S_ISDIR(dirstat.st_mode);
}

int CliArgs_init(struct CliArgs *args) {
    if (args == NULL) {
        return BAD_FUNC_ARG;
    }
    memset(args, 0, sizeof(struct CliArgs));
    return 0;
}

/* Parse command-line arguments.
 *
 * TODO: learn getopt or getopt_long so root/int/server/client can be optional
 * arguments with defaults, but for now forcing explicit specification is fine
 *
 * Return 0 upon success
 */
int CliArgs_parse(struct CliArgs *args, int argc, char *argv[]) {
    if (argc != 6) {
        return -1;
    }
    int err;
    if ((err = get_keytype_sigtype(&args->root_key_type, &args->root_sig_type,
                                   argv[1])) < 0) {
        return err;
    }
    if ((err = get_keytype_sigtype(&args->int_key_type, &args->int_sig_type,
                                   argv[2])) < 0) {
        return err;
    }
    if ((err = get_keytype_sigtype(&args->server_key_type,
                                   &args->server_sig_type, argv[3])) < 0) {
        return err;
    }
    if ((err = get_keytype_sigtype(&args->client_key_type,
                                   &args->client_sig_type, argv[4])) < 0) {
        return err;
    }

    if (!is_valid_dir(argv[5])) {
        return -1;
    }
    strncpy(args->certdir, argv[5], sizeof(args->certdir));
    unsigned long certdir_len = strlen(args->certdir);
    if ((certdir_len > 0) && (args->certdir[certdir_len - 1] == '/')) {
        args->certdir[certdir_len - 1] = '\0';
    }
    fprintf(stderr, "Certificates will be written to %s\n", args->certdir);

    return 0;
}

#ifdef WOLFSSL_KEY_GEN
/* Allocate space for an RSA key. Only 2048-bit RSA is supported for now.
 *
 * Return 0 on success.
 */
int alloc_make_rsa_key(void **key, int key_type, int sig_type, WC_RNG *rng) {
    int err = 0;
    int is_valid_sig_type = (sig_type == CTC_SHA256wRSA) ||
                            (sig_type == CTC_SHA384wRSA) ||
                            (sig_type == CTC_SHA512wRSA);
    if ((key == NULL) || (rng == NULL) || (key_type != RSA_TYPE) ||
        !is_valid_sig_type) {
        return BAD_FUNC_ARG;
    }

    RsaKey *rsakey = malloc(sizeof(RsaKey));
    if (!rsakey) {
        fprintf(stderr, "Failed to allocate for RsaKey\n");
        return MEMORY_E;
    }
    if ((err = wc_InitRsaKey(rsakey, NULL)) < 0) {
        fprintf(stderr, "Failed to init RSA key (err=%d)\n", err);
        goto cleanup;
    }
    if ((err = wc_MakeRsaKey(rsakey, RSA_MIN_SIZE, WC_RSA_EXPONENT, rng)) < 0) {
        fprintf(stderr, "Failed to make %d-bit RSA key (err=%d)\n",
                RSA_MIN_SIZE, err);
        goto cleanup;
    }
#ifdef WOLFSSL_RSA_KEY_CHECK
    if ((err = wc_CheckRsaKey(rsakey)) < 0) {
        fprintf(stderr, "RSA key check failed (err=%d)\n", err);
        goto cleanup;
    }
#endif

cleanup:
    if (err != 0) {
        /* Something went wrong, free the key */
        wc_FreeRsaKey(rsakey);
        if (rsakey) {
            free(rsakey);
        }
    } else {
        *key = rsakey;
    }

    return err;
}
#endif

/* Allocate space for an ECC key, then generate a keypair.
 *
 * NIST Curve P-256 is enabled if HAVE_ECC is enabled
 * P-384 requires HAVE_ECC384 and WOLFSSL_SHA384
 * P-521 requires HAVE_ECC521 and WOLFSSL_SHA512
 */
static int alloc_make_ecc_key(void **key, int key_type, int sig_type,
                              WC_RNG *rng) {
    int err = 0;
    int curve_id;
    int is_valid_sig_type = (sig_type == CTC_SHA256wECDSA) ||
                            (sig_type == CTC_SHA384wECDSA) ||
                            (sig_type == CTC_SHA512wECDSA);
    if ((key == NULL) || (key_type != ECC_TYPE) || !is_valid_sig_type ||
        (rng == NULL)) {
        return BAD_FUNC_ARG;
    }
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
        return NOT_COMPILED_IN;
    }

    ecc_key *_key = malloc(sizeof(ecc_key));
    if (_key == NULL) {
        return MEMORY_E;
    }
    if ((err = wc_ecc_init(_key)) < 0) {
        fprintf(stderr, "Failed to init ECC key (err=%d)\n", err);
        goto cleanup;
    }
    if ((err = wc_ecc_make_key(rng, wc_ecc_get_curve_size_from_id(curve_id),
                               _key)) < 0) {
        fprintf(stderr, "Failed to make ECC key (err=%d)\n", err);
        goto cleanup;
    }
    if ((err = wc_ecc_check_key(_key)) < 0) {
        fprintf(stderr, "ECC key check failed (err=%d)\n", err);
    }

cleanup:
    if (err != 0) {
        /* something went wrong, need to free the key */
        wc_ecc_free(_key);
        free(_key);
        return err;
    }
    /* everything worked, swap the input pointer with the internal pointer */
    *key = _key;
    return err;
}

/* Using key_type and sig_type as hints, allocate space for the some
 * cryptographic key type, then generate a random key for that type
 */
int alloc_make_key(void **key, int key_type, int sig_type, WC_RNG *rng) {
    int err;

    switch (key_type) {
#ifdef WOLFSSL_KEY_GEN
    case RSA_TYPE:
        err = alloc_make_rsa_key(key, key_type, sig_type, rng);
        break;
#endif
    case ECC_TYPE:
        err = alloc_make_ecc_key(key, key_type, sig_type, rng);
        break;
#ifdef HAVE_ED25519
    case ED25519_TYPE:
        err = alloc_make_ed25519_key(key, key_type, sig_type, rng);
        break;
#endif
#ifdef HAVE_ED448
    case ED448_TYPE:
        err = alloc_make_ed448_key(key, key_type, sig_type, rng);
        break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL2_TYPE:
    case ML_DSA_LEVEL3_TYPE:
    case ML_DSA_LEVEL5_TYPE:
        err = alloc_make_mldsa_key(key, key_type, sig_type, rng);
        break;
#endif
    default:
        err = BAD_FUNC_ARG;
        break;
    }

    return err;
}

/* A wrapper around the various KeyToDer methods
 */
int key_to_der(void *key, int key_type, byte *buf, word32 bufcap) {
    int err = 0;

    if ((key == NULL) || (buf == NULL) || (bufcap <= 0)) {
        return BAD_FUNC_ARG;
    }

    switch (key_type) {
#ifdef WOLFSSL_KEY_GEN
    case RSA_TYPE:
        err = wc_RsaKeyToDer(key, buf, bufcap);
        break;
#endif
#ifdef HAVE_ECC
    case ECC_TYPE:
        err = wc_EccKeyToDer(key, buf, bufcap);
        break;
#endif
#ifdef HAVE_ED25519
    case ED25519_TYPE:
        break;
#endif
#ifdef HAVE_ED448
    case ED448_TYPE:
        break;
#endif
#ifdef HAVE_DILITHIUM
    case ML_DSA_LEVEL2_TYPE:
    case ML_DSA_LEVEL3_TYPE:
    case ML_DSA_LEVEL5_TYPE:
        break;
#endif
    default:
        return NOT_COMPILED_IN;
    }

    return err;
}

int free_key(void *key, int key_type, int sig_type) {
    (void)sig_type;
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    switch (key_type) {
#ifdef WOLFSSL_KEY_GEN
    case RSA_TYPE:
        wc_FreeRsaKey(key);
        break;
#endif
#ifdef HAVE_ECC
    case ECC_TYPE:
        wc_ecc_free(key);
        break;
#endif
    default:
        return NOT_COMPILED_IN;
    }
    free(key);
    return 0;
}

/* Make a signed certificate based on the identity information supplied in
 * subj_cert, containing the public key from subj_key.
 *
 * If issuer_cert, issuer_key, issuer_key_type, and issuer_sig_type are all
 * supplied, then subj_cert will be signed by the supplied issuer. If not, then
 * subj_cert will be self-signed
 *
 * Return the length of the DER encoding upon success.
 */
int make_sign_cert(Cert *subj_cert, void *subj_key, int subj_key_type,
                   int subj_sig_type, int subj_is_ca, Cert *issuer_cert,
                   void *issuer_key, int issuer_key_type, int issuer_sig_type,
                   byte *out, word32 outcap, WC_RNG *rng) {
    int err = 0;
    byte der[MAX_DER_SZ];
    int dersz;

    int self_signed = (issuer_cert == NULL) || (issuer_key == NULL);

    /* Copy issuer information */
    if (self_signed) {
        set_certname(&subj_cert->issuer, subj_cert->subject.country,
                     subj_cert->subject.state, subj_cert->subject.locality,
                     subj_cert->subject.org, subj_cert->subject.commonName);
    } else {
        set_certname(&subj_cert->issuer, issuer_cert->subject.country,
                     issuer_cert->subject.state, issuer_cert->subject.locality,
                     issuer_cert->subject.org, issuer_cert->subject.commonName);
    }
    subj_cert->sigType = subj_sig_type;
    subj_cert->isCA = subj_is_ca;

    if ((err = wc_MakeCert_ex(subj_cert, der, sizeof(der), subj_key_type,
                              subj_key, rng)) < 0) {
        fprintf(stderr, "Failed to make cert (err=%d)\n", err);
        return err;
    }
    if (self_signed) {
        err = wc_SignCert_ex(subj_cert->bodySz, subj_sig_type, der, sizeof(der),
                             subj_key_type, subj_key, rng);
    } else {
        err = wc_SignCert_ex(subj_cert->bodySz, issuer_sig_type, der,
                             sizeof(der), issuer_key_type, issuer_key, rng);
    }
    if (err <= 0) {
        fprintf(stderr, "Failed to sign cert (err=%d)\n", err);
    }
    dersz = err;
    if ((err = wc_DerToPem(der, dersz, out, outcap, CERT_TYPE)) <= 0) {
        fprintf(stderr, "Failed to encode cert to PEM (err=%d)\n", err);
    }

    return err;
}

/* Generate a certificate chain: root -> int -> server and root -> client
 *
 * The final output should include five files:
 * - server.crt: PEM-encoded certificate chain including server and int pubkey
 * - server.key: DER-encoded private key for server authentication
 * - client.crt: PEM-encoded certificate including client pubkey
 * - client.key: DER-encoded private key for client authentication
 * - root.crt: PEM-encoded certificate including root CA's public key
 */
int generate_cert_chain(struct CliArgs *args, WC_RNG *rng) {
    int err = 0;

    void *root_key = NULL, *int_key = NULL, *server_key = NULL,
         *client_key = NULL;
    Cert root_cert, int_cert, server_cert, client_cert;
    byte buf1[MAX_PEM_SZ], buf2[MAX_PEM_SZ];
    int buf1sz, buf2sz;

    if ((err = alloc_make_key(&root_key, args->root_key_type,
                              args->root_sig_type, rng)) < 0) {
        fprintf(stderr, "Failed to allocate or make root key (err=%d)\n", err);
        goto cleanup;
    }
    if ((err = alloc_make_key(&int_key, args->int_key_type, args->int_sig_type,
                              rng)) < 0) {
        fprintf(stderr, "Failed to allocate or make int key (err=%d)\n", err);
        goto cleanup;
    }
    if ((err = alloc_make_key(&server_key, args->server_key_type,
                              args->server_sig_type, rng)) < 0) {
        fprintf(stderr, "Failed to allocate or make server key (err=%d)\n",
                err);
        goto cleanup;
    }
    if ((err = key_to_der(server_key, args->server_key_type, buf1,
                          sizeof(buf1))) <= 0) {
        fprintf(stderr, "Failed to write server key to DER (err=%d)\n", err);
        goto cleanup;
    }
    buf1sz = err;
    if ((err = write_to_file(args->certdir, "server.key", buf1, buf1sz)) < 0) {
        goto cleanup;
    }
    if ((err = alloc_make_key(&client_key, args->client_key_type,
                              args->client_sig_type, rng)) < 0) {
        fprintf(stderr, "Failed to allocate or make client key (err=%d)\n",
                err);
        goto cleanup;
    }
    if ((err = key_to_der(client_key, args->client_key_type, buf1,
                          sizeof(buf1))) <= 0) {
        goto cleanup;
    }
    buf1sz = err;
    if ((err = write_to_file(args->certdir, "client.key", buf1, buf1sz)) < 0) {
        goto cleanup;
    }

    if ((err = wc_InitCert(&root_cert)) < 0)
        goto cleanup;
    set_certname(&root_cert.subject, COUNTRY, STATE, LOCALITY, ORG, "root");
    set_utctime(root_cert.beforeDate, &root_cert.beforeDateSz, BEFORE_DATE);
    set_utctime(root_cert.afterDate, &root_cert.afterDateSz, LONG_AFTER_DATE);
    if ((err = wc_InitCert(&int_cert)) < 0)
        goto cleanup;
    set_certname(&int_cert.subject, COUNTRY, STATE, LOCALITY, ORG,
                 "intermediate");
    set_utctime(int_cert.beforeDate, &int_cert.beforeDateSz, BEFORE_DATE);
    set_utctime(int_cert.afterDate, &int_cert.afterDateSz, LONG_AFTER_DATE);
    if ((err = wc_InitCert(&server_cert)) < 0)
        goto cleanup;
    set_certname(&server_cert.subject, COUNTRY, STATE, LOCALITY, ORG, "server");
    set_utctime(server_cert.beforeDate, &server_cert.beforeDateSz, BEFORE_DATE);
    set_utctime(server_cert.afterDate, &server_cert.afterDateSz,
                LONG_AFTER_DATE);
    if ((err = wc_InitCert(&client_cert)) < 0)
        goto cleanup;
    set_certname(&client_cert.subject, COUNTRY, STATE, LOCALITY, ORG, "client");
    set_utctime(client_cert.beforeDate, &client_cert.beforeDateSz, BEFORE_DATE);
    set_utctime(client_cert.afterDate, &client_cert.afterDateSz,
                LONG_AFTER_DATE);

    if ((err = make_sign_cert(&root_cert, root_key, args->root_key_type,
                              args->root_sig_type, IS_CA, NULL, NULL, 0, 0,
                              buf1, sizeof(buf1), rng)) < 0) {
        goto cleanup;
    }
    buf1sz = err;
    if ((err = write_to_file(args->certdir, "root.crt", buf1, buf1sz)) < 0) {
        goto cleanup;
    }
    if ((err = make_sign_cert(&int_cert, int_key, args->int_key_type,
                              args->int_sig_type, IS_CA, &root_cert, root_key,
                              args->root_key_type, args->root_sig_type, buf1,
                              sizeof(buf1), rng)) < 0) {
        goto cleanup;
    }
    buf1sz = err;
    if ((err = make_sign_cert(&server_cert, server_key, args->server_key_type,
                              args->server_sig_type, NOT_CA, &int_cert, int_key,
                              args->int_key_type, args->int_sig_type, buf2,
                              sizeof(buf2), rng)) < 0) {
        goto cleanup;
    }
    buf2sz = err;
    memcpy(buf2 + buf2sz, buf1, buf1sz);
    if ((err = write_to_file(args->certdir, "server.crt", buf2,
                             buf1sz + buf2sz)) < 0) {
        goto cleanup;
    }
    if ((err = make_sign_cert(&client_cert, client_key, args->client_key_type,
                              args->client_sig_type, NOT_CA, &root_cert,
                              root_key, args->root_key_type,
                              args->root_sig_type, buf1, sizeof(buf1), rng)) <
        0) {
        goto cleanup;
    }
    buf1sz = err;
    if ((err = write_to_file(args->certdir, "client.crt", buf1, buf1sz)) < 0) {
        goto cleanup;
    }

cleanup:
    if (root_key) {
        free_key(root_key, args->root_key_type, args->root_sig_type);
        root_key = NULL;
    }
    if (int_key) {
        free_key(int_key, args->int_key_type, args->int_sig_type);
        int_key = NULL;
    }
    if (server_key) {
        free_key(server_key, args->server_key_type, args->server_sig_type);
        server_key = NULL;
    }
    if (client_key) {
        free_key(client_key, args->client_key_type, args->client_sig_type);
        client_key = NULL;
    }

    return err;
}

int main(int argc, char *argv[]) {
    int err;
    struct CliArgs args;
    CliArgs_init(&args);
    if ((err = CliArgs_parse(&args, argc, argv)) < 0) {
        printf("%s\n", HELP_STR);
        exit(EXIT_FAILURE);
    }

    WC_RNG rng;
    wc_InitRng(&rng);
    if ((err = generate_cert_chain(&args, &rng)) < 0) {
        fprintf(stderr, "Failed to generate cert chain (err=%d)\n", err);
        exit(EXIT_FAILURE);
    }
    return 0;
}

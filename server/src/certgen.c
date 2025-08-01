#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"

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
    "    - sha256rsa: 2048-bit RSA\n"                                          \
    "    - sha256ecdsa: ECDSA with P-256\n"                                    \
    "    - sha384ecdsa: ECDSA with P-384\n"                                    \
    "    - sha512ecdsa: ECDSA with P-521\n"                                    \
    "    - ed25519: EdDSA with curve 25519\n"                                  \
    "    - ed448: EdDSA with curve 448\n"                                      \
    "    - mldsa44: ML-DSA-44\n"                                               \
    "    - mldsa65: ML-DSA-65\n"                                               \
    "    - mldsa87: ML-DSA-87"
#define SIGTYPE_SHA256RSA "sha256rsa"
#define SIGTYPE_SHA256ECDSA "sha256ecdsa"
#define SIGTYPE_SHA384ECDSA "sha384ecdsa"
#define SIGTYPE_SHA512ECDSA "sha512ecdsa"
#define SIGTYPE_ED25519 "ed25519"
#define SIGTYPE_ED448 "ed448"
#define SIGTYPE_MLDSA44 "mldsa44"
#define SIGTYPE_MLDSA65 "mldsa65"
#define SIGTYPE_MLDSA87 "mldsa87"

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

static int alloc_make_ecc_key(void **key, int key_type, int sig_type,
                              WC_RNG *rng) {
    int err = BAD_FUNC_ARG;

    int is_valid_sig_type = (sig_type == CTC_SHA256wECDSA) ||
                            (sig_type == CTC_SHA384wECDSA) ||
                            (sig_type == CTC_SHA512wECDSA);
    if ((key == NULL) || (key_type != ECC_TYPE) || !is_valid_sig_type ||
        (rng == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* TODO: alloc key, make key */

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

int free_key(void *key, int key_type, int sig_type) { return -1; }

int make_sign_cert(Cert *subj_cert, void *subj_key, int subj_key_type,
                   int subj_sig_type, Cert *issuer_cert, void *issuer_key,
                   int issuer_key_type, int issuer_sig_type) {
    /* TODO: write to buffer, or write to file? */
    return -1;
}

int generate_cert_chain(struct CliArgs *args, WC_RNG *rng) {
    int err = 0;

    void *root_key = NULL, *int_key = NULL, *server_key = NULL,
         *client_key = NULL;
    Cert root_cert, int_cert, server_cert, client_cert;

    if ((err = alloc_make_key(&root_key, args->root_key_type,
                              args->root_sig_type, rng)) < 0) {
        goto cleanup;
    }
    if ((err = alloc_make_key(&int_key, args->int_key_type, args->int_sig_type,
                              rng)) < 0) {
        goto cleanup;
    }
    if ((err = alloc_make_key(&server_key, args->server_key_type,
                              args->server_sig_type, rng)) < 0) {
        goto cleanup;
    }
    if ((err = alloc_make_key(&client_key, args->client_key_type,
                              args->client_sig_type, rng)) < 0) {
        goto cleanup;
    }

    /* TODO: InitCert, set subject identities */
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
                              args->root_sig_type, NULL, NULL, 0, 0)) < 0) {
        goto cleanup;
    }
    if ((err = make_sign_cert(&int_cert, int_key, args->int_key_type,
                              args->int_sig_type, &root_cert, root_key,
                              args->root_key_type, args->root_sig_type)) < 0) {
        goto cleanup;
    }
    if ((err = make_sign_cert(&server_cert, server_key, args->server_key_type,
                              args->server_sig_type, &int_cert, int_key,
                              args->int_key_type, args->int_sig_type)) < 0) {
        goto cleanup;
    }
    if ((err = make_sign_cert(&client_cert, client_key, args->client_key_type,
                              args->client_sig_type, &root_cert, root_key,
                              args->root_key_type, args->root_sig_type)) < 0) {
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

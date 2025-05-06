/**
 * Generate a certificate chain: root, int, leaf, client
 * BUG: sometimes the output of certgen will cause client to reject server's
 * certificates
 */
#include <stdint.h>
#include <stdio.h>

#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/dilithium.h"
#include "wolfssl/wolfcrypt/types.h"

#ifndef QUIET
#define DEBUG_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_printf(...) ((void)0)
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
#define CERT_DER_MAX_SIZE 100000
#define KEY_DER_MAX_SIZE 100000
#define CERT_PEM_MAX_SIZE 100000
#define KEY_PEM_MAX_SIZE 100000
#define PATH_MAX_SIZE 1024

/* TODO: will enum type work? */
#define USE_ML_DSA_44 1
#define USE_ML_DSA_65 2
#define USE_ML_DSA_87 3
#define USE_SPHINCS_128F 4
#define USE_SPHINCS_128S 5
#define USE_SPHINCS_192F 6
#define USE_SPHINCS_192S 7
#define USE_SPHINCS_256F 8
#define USE_SPHINCS_256S 9
#define USE_FALCON_512 10
#define USE_FALCON_1024 11

#define ROOT_KEY_TYPE USE_ML_DSA_87
#define INT_KEY_TYPE USE_ML_DSA_65
#define LEAF_KEY_TYPE USE_ML_DSA_44
#define CLIENT_KEY_TYPE USE_ML_DSA_44

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

int main(int argc, char *argv[]) {
  int wc_err;
  RNG rng;
  wc_InitRng(&rng);

  // root certificate
  Cert root_cert;
#if (ROOT_KEY_TYPE == USE_ML_DSA_87)
  MlDsaKey root_key;
  int root_key_sig_type = CTC_ML_DSA_LEVEL5;
  int root_key_type = ML_DSA_LEVEL5_TYPE;
  int root_key_level = 5;
#else
#error "unsupported signature type"
#endif
  uint8_t root_cert_der[CERT_DER_MAX_SIZE], root_cert_pem[CERT_PEM_MAX_SIZE],
      root_key_der[KEY_DER_MAX_SIZE], root_key_pem[CERT_PEM_MAX_SIZE];
  int root_cert_der_size, root_cert_pem_size, root_key_der_size,
      root_key_pem_size;
  wc_InitCert(&root_cert);
  root_cert.sigType = root_key_sig_type;
  root_cert.isCA = 1;
  set_certname(&root_cert.subject, ROOT_COUNTRY, ROOT_STATE, ROOT_LOCALITY,
               ROOT_ORG, ROOT_COMMONNAME);
  set_certname(&root_cert.issuer, ROOT_COUNTRY, ROOT_STATE, ROOT_LOCALITY,
               ROOT_ORG, ROOT_COMMONNAME);
  set_before_date_utctime(&root_cert, NOT_BEFORE_DATE);
  set_after_date_utctime(&root_cert, NOT_AFTER_DATE);
#if (ROOT_KEY_TYPE == USE_ML_DSA_87 || ROOT_KEY_TYPE == USE_ML_DSA_65 ||       \
     ROOT_KEY_TYPE == USE_ML_DSA_44)
  wc_err = wc_MlDsaKey_Init(&root_key, NULL, INVALID_DEVID);
#endif
  if (wc_err != 0) {
    fprintf(stderr, "Failed to init root key (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
#if (ROOT_KEY_TYPE == USE_ML_DSA_87 || ROOT_KEY_TYPE == USE_ML_DSA_65 ||       \
     ROOT_KEY_TYPE == USE_ML_DSA_44)
  wc_err = wc_MlDsaKey_SetParams(&root_key, root_key_level);
#endif
  if (wc_err != 0) {
    fprintf(stderr, "Failed to set root key params (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
#if (ROOT_KEY_TYPE == USE_ML_DSA_87 || ROOT_KEY_TYPE == USE_ML_DSA_65 ||       \
     ROOT_KEY_TYPE == USE_ML_DSA_44)
  wc_err = wc_MlDsaKey_MakeKey(&root_key, &rng);
#endif
  if (wc_err != 0) {
    fprintf(stderr, "Failed to generate root key pair (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
  root_cert_der_size =
      wc_MakeCert_ex(&root_cert, root_cert_der, sizeof(root_cert_der),
                     root_key_type, &root_key, &rng);
  if (root_cert_der_size < 0) {
    fprintf(stderr, "Failed to make unsigned root certificate (err %d)\n",
            root_cert_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("root cert (unsigned) DER size %d\n", root_cert_der_size);
  }
  root_cert_der_size =
      wc_SignCert_ex(root_cert.bodySz, root_cert.sigType, root_cert_der,
                     sizeof(root_cert_der), root_key_type, &root_key, &rng);
  if (root_cert_der_size < 0) {
    fprintf(stderr, "Failed to sign root cert body (err %d)\n",
            root_cert_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("root cert (signed) DER size %d\n", root_cert_der_size);
  }
#if (ROOT_KEY_TYPE == USE_ML_DSA_87 || ROOT_KEY_TYPE == USE_ML_DSA_65 ||       \
     ROOT_KEY_TYPE == USE_ML_DSA_44)
  root_key_der_size = wc_MlDsaKey_PrivateKeyToDer(&root_key, root_key_der,
                                                  sizeof(root_key_der));
#endif
  if (root_key_der_size < 0) {
    fprintf(stderr, "Failed to convert root key to DER (err %d)\n",
            root_key_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("root key DER size %d\n", root_key_der_size);
  }
  root_key_pem_size = wc_DerToPem(root_key_der, root_key_der_size, root_key_pem,
                                  sizeof(root_key_pem), PKCS8_PRIVATEKEY_TYPE);
  if (root_key_pem_size < 0) {
    fprintf(stderr, "Failed to convert root key to PEM (err %d)\n",
            root_key_pem_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("root key PEM size %d\n", root_key_pem_size);
  }
  root_cert_pem_size =
      wc_DerToPem(root_cert_der, root_cert_der_size, root_cert_pem,
                  sizeof(root_cert_pem), CERT_TYPE);
  if (root_cert_pem_size < 0) {
    fprintf(stderr, "Failed to convert root cert to PEM (err %d)\n",
            root_cert_pem_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("root cert PEM size %d\n", root_cert_pem_size);
  }

  // intermediate
  Cert int_cert;
#if (INT_KEY_TYPE == USE_ML_DSA_65)
  MlDsaKey int_key;
  int int_key_sig_type = CTC_ML_DSA_LEVEL3;
  int int_key_type = ML_DSA_LEVEL3_TYPE;
  int int_key_level = 3;
#endif
  uint8_t int_cert_der[CERT_DER_MAX_SIZE], int_cert_pem[CERT_PEM_MAX_SIZE],
      int_key_der[KEY_DER_MAX_SIZE], int_key_pem[CERT_PEM_MAX_SIZE];
  int int_cert_der_size, int_cert_pem_size, int_key_der_size, int_key_pem_size;
  wc_InitCert(&int_cert);
  int_cert.sigType = root_key_sig_type;
  int_cert.isCA = 1;
  wc_SetIssuerBuffer(&int_cert, root_cert_der, root_cert_der_size);
  set_certname(&int_cert.subject, ROOT_COUNTRY, ROOT_STATE, ROOT_LOCALITY,
               ROOT_ORG, ROOT_COMMONNAME);
  set_before_date_utctime(&int_cert, NOT_BEFORE_DATE);
  set_after_date_utctime(&int_cert, NOT_AFTER_DATE);
#if (INT_KEY_TYPE == USE_ML_DSA_87 || INT_KEY_TYPE == USE_ML_DSA_65 ||         \
     INT_KEY_TYPE == USE_ML_DSA_44)
  wc_err = wc_MlDsaKey_Init(&int_key, NULL, INVALID_DEVID);
#endif
  if (wc_err != 0) {
    fprintf(stderr, "Failed to init intermediate key (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
#if (INT_KEY_TYPE == USE_ML_DSA_87 || INT_KEY_TYPE == USE_ML_DSA_65 ||         \
     INT_KEY_TYPE == USE_ML_DSA_44)
  wc_err = wc_MlDsaKey_SetParams(&int_key, int_key_level);
#endif
  if (wc_err != 0) {
    fprintf(stderr, "Failed to set intermediate key level (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
#if (INT_KEY_TYPE == USE_ML_DSA_87 || INT_KEY_TYPE == USE_ML_DSA_65 ||         \
     INT_KEY_TYPE == USE_ML_DSA_44)
  wc_err = wc_MlDsaKey_MakeKey(&int_key, &rng);
#endif
  if (wc_err != 0) {
    fprintf(stderr, "Failed to generate intermediate keypair (err %d)\n",
            wc_err);
    exit(EXIT_FAILURE);
  }
  int_cert_der_size =
      wc_MakeCert_ex(&int_cert, int_cert_der, sizeof(int_cert_der),
                     int_key_type, &int_key, &rng);
  if (int_cert_der_size < 0) {
    fprintf(stderr, "Failed to make unsigned int certificate (err %d)\n",
            int_cert_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("int cert (unsigned) DER size %d\n", int_cert_der_size);
  }
  int_cert_der_size =
      wc_SignCert_ex(int_cert.bodySz, int_cert.sigType, int_cert_der,
                     sizeof(int_cert_der), root_key_type, &root_key, &rng);
  if (int_cert_der_size < 0) {
    fprintf(stderr, "Failed to sign int cert body (err %d)\n",
            int_cert_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("int cert (signed) DER size %d\n", int_cert_der_size);
  }
#if (INT_KEY_TYPE == USE_ML_DSA_87 || INT_KEY_TYPE == USE_ML_DSA_65 ||         \
     INT_KEY_TYPE == USE_ML_DSA_44)
  int_key_der_size =
      wc_MlDsaKey_PrivateKeyToDer(&int_key, int_key_der, sizeof(int_key_der));
#endif
  if (int_key_der_size < 0) {
    fprintf(stderr, "Failed to convert int key to DER (err %d)\n",
            int_key_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("int key DER size %d\n", int_key_der_size);
  }
  int_key_pem_size = wc_DerToPem(int_key_der, int_key_der_size, int_key_pem,
                                 sizeof(int_key_pem), PKCS8_PRIVATEKEY_TYPE);
  if (int_key_pem_size < 0) {
    fprintf(stderr, "Failed to convert int key to PEM (err %d)\n",
            int_key_pem_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("int key PEM size %d\n", int_key_pem_size);
  }
  int_cert_pem_size = wc_DerToPem(int_cert_der, int_cert_der_size, int_cert_pem,
                                  sizeof(int_cert_pem), CERT_TYPE);
  if (int_cert_pem_size < 0) {
    fprintf(stderr, "Failed to convert int cert to PEM (err %d)\n",
            int_cert_pem_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("int cert PEM size %d\n", int_cert_pem_size);
  }

  // leaf certificate
  Cert leaf_cert;
#if (LEAF_KEY_TYPE == USE_ML_DSA_44)
  MlDsaKey leaf_key;
  int leaf_key_type = ML_DSA_LEVEL2_TYPE;
  int leaf_key_level = 2;
#endif
  uint8_t leaf_cert_der[CERT_DER_MAX_SIZE], leaf_cert_pem[CERT_PEM_MAX_SIZE],
      leaf_key_der[KEY_DER_MAX_SIZE], leaf_key_pem[CERT_PEM_MAX_SIZE];
  int leaf_cert_der_size, leaf_cert_pem_size, leaf_key_der_size,
      leaf_key_pem_size;
  wc_InitCert(&leaf_cert);
  leaf_cert.sigType = int_key_sig_type;
  wc_SetIssuerBuffer(&leaf_cert, int_cert_der, int_cert_der_size);
  set_certname(&leaf_cert.subject, LEAF_COUNTRY, LEAF_STATE, LEAF_LOCALITY,
               LEAF_ORG, LEAF_COMMONNAME);
  set_before_date_utctime(&leaf_cert, NOT_BEFORE_DATE);
  set_after_date_utctime(&leaf_cert, NOT_AFTER_DATE);
#if (LEAF_KEY_TYPE == USE_ML_DSA_87 || LEAF_KEY_TYPE == USE_ML_DSA_65 ||       \
     LEAF_KEY_TYPE == USE_ML_DSA_44)
  wc_err = wc_MlDsaKey_Init(&leaf_key, NULL, INVALID_DEVID);
#endif
  if (wc_err != 0) {
    fprintf(stderr, "Failed to init leaf key (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
#if (LEAF_KEY_TYPE == USE_ML_DSA_87 || LEAF_KEY_TYPE == USE_ML_DSA_65 ||       \
     LEAF_KEY_TYPE == USE_ML_DSA_44)
  wc_err = wc_MlDsaKey_SetParams(&leaf_key, leaf_key_level);
#endif
  if (wc_err != 0) {
    fprintf(stderr, "Failed to set leaf key params (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
#if (LEAF_KEY_TYPE == USE_ML_DSA_87 || LEAF_KEY_TYPE == USE_ML_DSA_65 ||       \
     LEAF_KEY_TYPE == USE_ML_DSA_44)
  wc_err = wc_MlDsaKey_MakeKey(&leaf_key, &rng);
#endif
  if (wc_err != 0) {
    fprintf(stderr, "Failed to generate leaf keypair (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
  leaf_cert_der_size =
      wc_MakeCert_ex(&leaf_cert, leaf_cert_der, sizeof(leaf_cert_der),
                     leaf_key_type, &leaf_key, &rng);
  if (leaf_cert_der_size < 0) {
    fprintf(stderr, "Failed to make unsigned leaf certificate (err %d)\n",
            leaf_cert_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("leaf cert (unsigned) DER size %d\n", leaf_cert_der_size);
  }
  leaf_cert_der_size =
      wc_SignCert_ex(leaf_cert.bodySz, leaf_cert.sigType, leaf_cert_der,
                     sizeof(leaf_cert_der), int_key_type, &int_key, &rng);
  if (leaf_cert_der_size < 0) {
    fprintf(stderr, "Failed to sign leaf cert body (err %d)\n",
            leaf_cert_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("leaf cert (signed) DER size %d\n", leaf_cert_der_size);
  }
#if (LEAF_KEY_TYPE == USE_ML_DSA_87 || LEAF_KEY_TYPE == USE_ML_DSA_65 ||       \
     LEAF_KEY_TYPE == USE_ML_DSA_44)
  leaf_key_der_size = wc_MlDsaKey_PrivateKeyToDer(&leaf_key, leaf_key_der,
                                                  sizeof(leaf_key_der));
#endif
  if (leaf_key_der_size < 0) {
    fprintf(stderr, "Failed to convert leaf key to DER (err %d)\n",
            leaf_key_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("leaf key DER size %d\n", leaf_key_der_size);
  }
  leaf_key_pem_size = wc_DerToPem(leaf_key_der, leaf_key_der_size, leaf_key_pem,
                                  sizeof(leaf_key_pem), PKCS8_PRIVATEKEY_TYPE);
  if (leaf_key_pem_size < 0) {
    fprintf(stderr, "Failed to convert leaf key to PEM (err %d)\n",
            leaf_key_pem_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("leaf key PEM size %d\n", leaf_key_pem_size);
  }
  leaf_cert_pem_size =
      wc_DerToPem(leaf_cert_der, leaf_cert_der_size, leaf_cert_pem,
                  sizeof(leaf_cert_pem), CERT_TYPE);
  if (leaf_cert_pem_size < 0) {
    fprintf(stderr, "Failed to convert leaf cert to PEM (err %d)\n",
            leaf_cert_pem_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("leaf cert PEM size %d\n", leaf_cert_pem_size);
  }

  // client certificate
  Cert client_cert;
#if (CLIENT_KEY_TYPE == USE_ML_DSA_44)
  MlDsaKey client_key;
  int client_key_type = ML_DSA_LEVEL2_TYPE;
  int client_key_level = 2;
#endif
  uint8_t client_cert_der[CERT_DER_MAX_SIZE],
      client_cert_pem[CERT_PEM_MAX_SIZE], client_key_der[KEY_DER_MAX_SIZE],
      client_key_pem[CERT_PEM_MAX_SIZE];
  int client_cert_der_size, client_cert_pem_size, client_key_der_size,
      client_key_pem_size;
  wc_InitCert(&client_cert);
  client_cert.sigType = root_key_sig_type;
  wc_SetIssuerBuffer(&client_cert, root_cert_der, root_cert_der_size);
  set_certname(&client_cert.subject, LEAF_COUNTRY, LEAF_STATE, LEAF_LOCALITY,
               LEAF_ORG, LEAF_COMMONNAME);
  set_before_date_utctime(&client_cert, NOT_BEFORE_DATE);
  set_after_date_utctime(&client_cert, NOT_AFTER_DATE);
#if (CLIENT_KEY_TYPE == USE_ML_DSA_87 || CLIENT_KEY_TYPE == USE_ML_DSA_65 ||   \
     CLIENT_KEY_TYPE == USE_ML_DSA_44)
  wc_err = wc_MlDsaKey_Init(&client_key, NULL, INVALID_DEVID);
#endif
  if (wc_err != 0) {
    fprintf(stderr, "Failed to init client key (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
#if (CLIENT_KEY_TYPE == USE_ML_DSA_87 || CLIENT_KEY_TYPE == USE_ML_DSA_65 ||   \
     CLIENT_KEY_TYPE == USE_ML_DSA_44)
  wc_err = wc_MlDsaKey_SetParams(&client_key, client_key_level);
#endif
  if (wc_err != 0) {
    fprintf(stderr, "Failed to set client params (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
#if (CLIENT_KEY_TYPE == USE_ML_DSA_87 || CLIENT_KEY_TYPE == USE_ML_DSA_65 ||   \
     CLIENT_KEY_TYPE == USE_ML_DSA_44)
  wc_err = wc_MlDsaKey_MakeKey(&client_key, &rng);
#endif
  if (wc_err != 0) {
    fprintf(stderr, "Failed to generate client keypair (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
  client_cert_der_size =
      wc_MakeCert_ex(&client_cert, client_cert_der, sizeof(client_cert_der),
                     client_key_type, &client_key, &rng);
  if (client_cert_der_size < 0) {
    fprintf(stderr, "Failed to make unsigned client certificate (err %d)\n",
            client_cert_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("client cert (unsigned) DER size %d\n", client_cert_der_size);
  }
  client_cert_der_size =
      wc_SignCert_ex(client_cert.bodySz, client_cert.sigType, client_cert_der,
                     sizeof(client_cert_der), root_key_type, &root_key, &rng);
  if (client_cert_der_size < 0) {
    fprintf(stderr, "Failed to sign client cert body (err %d)\n",
            client_cert_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("client cert (signed) DER size %d\n", client_cert_der_size);
  }
#if (CLIENT_KEY_TYPE == USE_ML_DSA_87 || CLIENT_KEY_TYPE == USE_ML_DSA_65 ||   \
     CLIENT_KEY_TYPE == USE_ML_DSA_44)
  client_key_der_size = wc_MlDsaKey_PrivateKeyToDer(&client_key, client_key_der,
                                                    sizeof(client_key_der));
#endif
  if (client_key_der_size < 0) {
    fprintf(stderr, "Failed to convert client key to DER (err %d)\n",
            client_key_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("client key DER size %d\n", client_key_der_size);
  }
  client_key_pem_size =
      wc_DerToPem(client_key_der, client_key_der_size, client_key_pem,
                  sizeof(client_key_pem), PKCS8_PRIVATEKEY_TYPE);
  if (client_key_pem_size < 0) {
    fprintf(stderr, "Failed to convert client key to PEM (err %d)\n",
            client_key_pem_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("client key PEM size %d\n", client_key_pem_size);
  }
  client_cert_pem_size =
      wc_DerToPem(client_cert_der, client_cert_der_size, client_cert_pem,
                  sizeof(client_cert_pem), CERT_TYPE);
  if (client_cert_pem_size < 0) {
    fprintf(stderr, "Failed to convert client cert to PEM (err %d)\n",
            client_cert_pem_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("client cert PEM size %d\n", client_cert_pem_size);
  }

  // CLI entrypoint
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <dir>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  const char *dir = argv[1];
  struct stat st;
  if (stat(dir, &st) != 0) {
    perror("Error accessing the directory");
    exit(EXIT_FAILURE);
  }
  if (!S_ISDIR(st.st_mode)) {
    fprintf(stderr, "Error: '%s' is not a directory.\n", dir);
    exit(EXIT_FAILURE);
  }

  // write certificates and keys
  char filepath[PATH_MAX_SIZE];
  FILE *file;
  int written;
  snprintf(filepath, sizeof(filepath), "%s/root.crt", dir);
  file = fopen(filepath, "w");
  if (!file) {
    fprintf(stderr, "Failed to open %s for writing\n", filepath);
    exit(EXIT_FAILURE);
  }
  written = fwrite(root_cert_pem, sizeof(uint8_t), root_cert_pem_size, file);
  if (written < root_cert_pem_size) {
    fprintf(stderr, "Partial write: %d out of %d bytes\n", written,
            root_cert_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);
  snprintf(filepath, sizeof(filepath), "%s/root.key", dir);
  file = fopen(filepath, "w");
  if (!file) {
    fprintf(stderr, "Failed to open %s for writing\n", filepath);
    exit(EXIT_FAILURE);
  }
  written = fwrite(root_key_pem, sizeof(uint8_t), root_key_pem_size, file);
  if (written < root_key_pem_size) {
    fprintf(stderr, "Partial write: %d out of %d bytes\n", written,
            root_key_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);

  snprintf(filepath, sizeof(filepath), "%s/int.crt", dir);
  file = fopen(filepath, "w");
  if (!file) {
    fprintf(stderr, "Failed to open %s for writing\n", filepath);
    exit(EXIT_FAILURE);
  }
  written = fwrite(int_cert_pem, sizeof(uint8_t), int_cert_pem_size, file);
  if (written < int_cert_pem_size) {
    fprintf(stderr, "Partial write: %d out of %d bytes\n", written,
            int_cert_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);
  snprintf(filepath, sizeof(filepath), "%s/int.key", dir);
  file = fopen(filepath, "w");
  if (!file) {
    fprintf(stderr, "Failed to open %s for writing\n", filepath);
    exit(EXIT_FAILURE);
  }
  written = fwrite(int_key_pem, sizeof(uint8_t), int_key_pem_size, file);
  if (written < int_key_pem_size) {
    fprintf(stderr, "Partial write: %d out of %d bytes\n", written,
            int_key_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);

  snprintf(filepath, sizeof(filepath), "%s/leaf.crt", dir);
  file = fopen(filepath, "w");
  if (!file) {
    fprintf(stderr, "Failed to open %s for writing\n", filepath);
    exit(EXIT_FAILURE);
  }
  written = fwrite(leaf_cert_pem, sizeof(uint8_t), leaf_cert_pem_size, file);
  if (written < leaf_cert_pem_size) {
    fprintf(stderr, "Partial write: %d out of %d bytes\n", written,
            leaf_cert_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);
  snprintf(filepath, sizeof(filepath), "%s/leaf.key", dir);
  file = fopen(filepath, "w");
  if (!file) {
    fprintf(stderr, "Failed to open %s for writing\n", filepath);
    exit(EXIT_FAILURE);
  }
  written = fwrite(leaf_key_pem, sizeof(uint8_t), leaf_key_pem_size, file);
  if (written < leaf_key_pem_size) {
    fprintf(stderr, "Partial write: %d out of %d bytes\n", written,
            leaf_key_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);

  snprintf(filepath, sizeof(filepath), "%s/client.crt", dir);
  file = fopen(filepath, "w");
  if (!file) {
    fprintf(stderr, "Failed to open %s for writing\n", filepath);
    exit(EXIT_FAILURE);
  }
  written =
      fwrite(client_cert_pem, sizeof(uint8_t), client_cert_pem_size, file);
  if (written < client_cert_pem_size) {
    fprintf(stderr, "Partial write: %d out of %d bytes\n", written,
            client_cert_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);
  snprintf(filepath, sizeof(filepath), "%s/client.key", dir);
  file = fopen(filepath, "w");
  if (!file) {
    fprintf(stderr, "Failed to open %s for writing\n", filepath);
    exit(EXIT_FAILURE);
  }
  written = fwrite(client_key_pem, sizeof(uint8_t), client_key_pem_size, file);
  if (written < client_key_pem_size) {
    fprintf(stderr, "Partial write: %d out of %d bytes\n", written,
            client_key_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);

  snprintf(filepath, sizeof(filepath), "%s/server-chain.crt", dir);
  file = fopen(filepath, "w");
  if (!file) {
    fprintf(stderr, "Failed to open %s for writing\n", filepath);
    exit(EXIT_FAILURE);
  }
  written = fwrite(leaf_cert_pem, sizeof(uint8_t), leaf_cert_pem_size, file);
  if (written < leaf_cert_pem_size) {
    fprintf(stderr, "Partial write: %d out of %d bytes\n", written,
            leaf_cert_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  written = fwrite(int_cert_pem, sizeof(uint8_t), int_cert_pem_size, file);
  if (written < int_cert_pem_size) {
    fprintf(stderr, "Partial write: %d out of %d bytes\n", written,
            int_cert_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  written = fwrite(root_cert_pem, sizeof(uint8_t), root_cert_pem_size, file);
  if (written < root_cert_pem_size) {
    fprintf(stderr, "Partial write: %d out of %d bytes\n", written,
            root_cert_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);

  snprintf(filepath, sizeof(filepath), "%s/client-chain.crt", dir);
  file = fopen(filepath, "w");
  if (!file) {
    fprintf(stderr, "Failed to open %s for writing\n", filepath);
    exit(EXIT_FAILURE);
  }
  written =
      fwrite(client_cert_pem, sizeof(uint8_t), client_cert_pem_size, file);
  if (written < client_cert_pem_size) {
    fprintf(stderr, "Partial write: %d out of %d bytes\n", written,
            client_cert_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  written = fwrite(root_cert_pem, sizeof(uint8_t), root_cert_pem_size, file);
  if (written < root_cert_pem_size) {
    fprintf(stderr, "Partial write: %d out of %d bytes\n", written,
            root_cert_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);

  return 0;
}

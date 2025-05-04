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
#include "wolfssl/wolfcrypt/sphincs.h"
#include "wolfssl/wolfcrypt/types.h"

#ifndef QUIET
#define DEBUG_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_printf(...) ((void)0)
#endif

#define wc_MlDsa_KeyToDer wc_Dilithium_PrivateKeyToDer
#define CERTS_DIR "certs"
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
#define CERT_DER_MAX_SIZE 44000
#define CERT_PEM_MAX_SIZE 44000
#define KEY_DER_MAX_SIZE 8192
#define KEY_PEM_MAX_SIZE 12000
#define PATH_MAX_SIZE 1024

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
  // MlDsaKey root_key;
  sphincs_key root_key;
  int root_key_type = SPHINCS_FAST_LEVEL1_TYPE;
  uint8_t root_cert_der[CERT_DER_MAX_SIZE], root_cert_pem[CERT_PEM_MAX_SIZE],
      root_key_der[KEY_DER_MAX_SIZE], root_key_pem[CERT_PEM_MAX_SIZE];
  int root_cert_der_size, root_cert_pem_size, root_key_der_size,
      root_key_pem_size;
  wc_InitCert(&root_cert);
  // root_cert.sigType = CTC_ML_DSA_LEVEL2;
  root_cert.sigType = CTC_SPHINCS_FAST_LEVEL1;
  root_cert.isCA = 1;
  set_certname(&root_cert.subject, ROOT_COUNTRY, ROOT_STATE, ROOT_LOCALITY,
               ROOT_ORG, ROOT_COMMONNAME);
  set_certname(&root_cert.issuer, ROOT_COUNTRY, ROOT_STATE, ROOT_LOCALITY,
               ROOT_ORG, ROOT_COMMONNAME);
  set_before_date_utctime(&root_cert, NOT_BEFORE_DATE);
  set_after_date_utctime(&root_cert, NOT_AFTER_DATE);
  // wc_err = wc_MlDsaKey_Init(&root_key, NULL, INVALID_DEVID);
  wc_err = wc_sphincs_init(&root_key);
  if (wc_err != 0) {
    fprintf(stderr, "Failed to init SPHINCS+ key (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
  // wc_err = wc_MlDsaKey_SetParams(&root_key, 2);
  wc_err = wc_sphincs_set_level_and_optim(&root_key, 1, SPHINCS_FAST_VARIANT);
  if (wc_err != 0) {
    fprintf(stderr, "Failed to set SPHINCS+ params to 128f (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
  // wc_err = wc_MlDsaKey_MakeKey(&root_key, &rng);
  wc_err = wc_sphincs_make_key(&root_key, &rng);
  if (wc_err != 0) {
    fprintf(stderr, "Failed to generate ML-DSA-44 keypair (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
  // root_cert_der_size =
  //     wc_MakeCert_ex(&root_cert, root_cert_der, sizeof(root_cert_der),
  //                    ML_DSA_LEVEL2_TYPE, &root_key, &rng);
  root_cert_der_size =
      wc_MakeCert_ex(&root_cert, root_cert_der, sizeof(root_cert_der),
                     SPHINCS_FAST_LEVEL1_TYPE, &root_key, &rng);
  if (root_cert_der_size < 0) {
    fprintf(stderr, "Failed to make unsigned root certificate (err %d)\n",
            root_cert_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("root cert (unsigned) DER size %d\n", root_cert_der_size);
  }
  // root_cert_der_size = wc_SignCert_ex(root_cert.bodySz, root_cert.sigType,
  //                                     root_cert_der, sizeof(root_cert_der),
  //                                     ML_DSA_LEVEL2_TYPE, &root_key, &rng);
  root_cert_der_size = wc_SignCert_ex(
      root_cert.bodySz, root_cert.sigType, root_cert_der, sizeof(root_cert_der),
      root_key_type, &root_key, &rng);
  if (root_cert_der_size < 0) {
    fprintf(stderr, "Failed to sign root cert body (err %d)\n",
            root_cert_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("root cert (signed) DER size %d\n", root_cert_der_size);
  }
  // root_key_der_size =
  //     wc_MlDsa_KeyToDer(&root_key, root_key_der, sizeof(root_key_der));
  root_key_der_size =
      wc_Sphincs_KeyToDer(&root_key, root_key_der, sizeof(root_key_der));
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
  MlDsaKey int_key;
  int int_key_type = ML_DSA_LEVEL2_TYPE;
  uint8_t int_cert_der[CERT_DER_MAX_SIZE], int_cert_pem[CERT_PEM_MAX_SIZE],
      int_key_der[KEY_DER_MAX_SIZE], int_key_pem[CERT_PEM_MAX_SIZE];
  int int_cert_der_size, int_cert_pem_size, int_key_der_size, int_key_pem_size;
  wc_InitCert(&int_cert);
  int_cert.sigType = CTC_SPHINCS_FAST_LEVEL1;
  int_cert.isCA = 1;
  wc_SetIssuerBuffer(&int_cert, root_cert_der, root_cert_der_size);
  set_certname(&int_cert.subject, ROOT_COUNTRY, ROOT_STATE, ROOT_LOCALITY,
               ROOT_ORG, ROOT_COMMONNAME);
  set_before_date_utctime(&int_cert, NOT_BEFORE_DATE);
  set_after_date_utctime(&int_cert, NOT_AFTER_DATE);
  wc_err = wc_MlDsaKey_Init(&int_key, NULL, INVALID_DEVID);
  if (wc_err != 0) {
    fprintf(stderr, "Failed to init ML-DSA key (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
  wc_err = wc_MlDsaKey_SetParams(&int_key, 2);
  if (wc_err != 0) {
    fprintf(stderr, "Failed to set ML-DSA level to 2 (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
  wc_err = wc_MlDsaKey_MakeKey(&int_key, &rng);
  if (wc_err != 0) {
    fprintf(stderr, "Failed to generate ML-DSA-44 keypair (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
  int_cert_der_size =
      wc_MakeCert_ex(&int_cert, int_cert_der, sizeof(int_cert_der),
                     ML_DSA_LEVEL2_TYPE, &int_key, &rng);
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
  int_key_der_size =
      wc_MlDsa_KeyToDer(&int_key, int_key_der, sizeof(int_key_der));
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
  MlDsaKey leaf_key;
  uint8_t leaf_cert_der[CERT_DER_MAX_SIZE], leaf_cert_pem[CERT_PEM_MAX_SIZE],
      leaf_key_der[KEY_DER_MAX_SIZE], leaf_key_pem[CERT_PEM_MAX_SIZE];
  int leaf_cert_der_size, leaf_cert_pem_size, leaf_key_der_size,
      leaf_key_pem_size;
  wc_InitCert(&leaf_cert);
  leaf_cert.sigType = CTC_ML_DSA_LEVEL2;
  wc_SetIssuerBuffer(&leaf_cert, int_cert_der, int_cert_der_size);
  set_certname(&leaf_cert.subject, LEAF_COUNTRY, LEAF_STATE, LEAF_LOCALITY,
               LEAF_ORG, LEAF_COMMONNAME);
  set_before_date_utctime(&leaf_cert, NOT_BEFORE_DATE);
  set_after_date_utctime(&leaf_cert, NOT_AFTER_DATE);
  wc_err = wc_MlDsaKey_Init(&leaf_key, NULL, INVALID_DEVID);
  if (wc_err != 0) {
    fprintf(stderr, "Failed to init leaf ML-DSA key (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
  wc_err = wc_MlDsaKey_SetParams(&leaf_key, 2);
  if (wc_err != 0) {
    fprintf(stderr, "Failed to set leaf ML-DSA level to 2 (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
  wc_err = wc_MlDsaKey_MakeKey(&leaf_key, &rng);
  if (wc_err != 0) {
    fprintf(stderr, "Failed to generate leaf ML-DSA-44 keypair (err %d)\n",
            wc_err);
    exit(EXIT_FAILURE);
  }
  leaf_cert_der_size =
      wc_MakeCert_ex(&leaf_cert, leaf_cert_der, sizeof(leaf_cert_der),
                     ML_DSA_LEVEL2_TYPE, &leaf_key, &rng);
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
  leaf_key_der_size =
      wc_MlDsa_KeyToDer(&leaf_key, leaf_key_der, sizeof(leaf_key_der));
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
  MlDsaKey client_key;
  uint8_t client_cert_der[CERT_DER_MAX_SIZE],
      client_cert_pem[CERT_PEM_MAX_SIZE], client_key_der[KEY_DER_MAX_SIZE],
      client_key_pem[CERT_PEM_MAX_SIZE];
  int client_cert_der_size, client_cert_pem_size, client_key_der_size,
      client_key_pem_size;
  wc_InitCert(&client_cert);
  client_cert.sigType = CTC_ML_DSA_LEVEL2;
  wc_SetIssuerBuffer(&client_cert, root_cert_der, root_cert_der_size);
  set_certname(&client_cert.subject, LEAF_COUNTRY, LEAF_STATE, LEAF_LOCALITY,
               LEAF_ORG, LEAF_COMMONNAME);
  set_before_date_utctime(&client_cert, NOT_BEFORE_DATE);
  set_after_date_utctime(&client_cert, NOT_AFTER_DATE);
  wc_err = wc_MlDsaKey_Init(&client_key, NULL, INVALID_DEVID);
  if (wc_err != 0) {
    fprintf(stderr, "Failed to init client ML-DSA key (err %d)\n", wc_err);
    exit(EXIT_FAILURE);
  }
  wc_err = wc_MlDsaKey_SetParams(&client_key, 2);
  if (wc_err != 0) {
    fprintf(stderr, "Failed to set client ML-DSA level to 2 (err %d)\n",
            wc_err);
    exit(EXIT_FAILURE);
  }
  wc_err = wc_MlDsaKey_MakeKey(&client_key, &rng);
  if (wc_err != 0) {
    fprintf(stderr, "Failed to generate client ML-DSA-44 keypair (err %d)\n",
            wc_err);
    exit(EXIT_FAILURE);
  }
  client_cert_der_size =
      wc_MakeCert_ex(&client_cert, client_cert_der, sizeof(client_cert_der),
                     ML_DSA_LEVEL2_TYPE, &client_key, &rng);
  if (client_cert_der_size < 0) {
    fprintf(stderr, "Failed to make unsigned client certificate (err %d)\n",
            client_cert_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("client cert (unsigned) DER size %d\n", client_cert_der_size);
  }
  client_cert_der_size = wc_SignCert_ex(
      client_cert.bodySz, client_cert.sigType, client_cert_der,
      sizeof(client_cert_der), root_key_type, &root_key, &rng);
  if (client_cert_der_size < 0) {
    fprintf(stderr, "Failed to sign client cert body (err %d)\n",
            client_cert_der_size);
    exit(EXIT_FAILURE);
  } else {
    DEBUG_printf("client cert (signed) DER size %d\n", client_cert_der_size);
  }
  client_key_der_size =
      wc_MlDsa_KeyToDer(&client_key, client_key_der, sizeof(client_key_der));
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

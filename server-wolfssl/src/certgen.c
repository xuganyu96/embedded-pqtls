/**
 * Generate certificate chain
 *
 * Verify the outputs using openssl:

cat certs/server-leaf.crt certs/server-root.crt > certs/server-chain.crt
openssl s_server -cert certs/server-chain.crt -key certs/server-leaf.key \
    -port 8000

openssl s_client -connect localhost:8000 -CAfile certs/server-root.crt \
    -verify_return_error < /dev/null
 */
#include <stdio.h>
#include <string.h>

#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/rsa.h"

#define SUBJ_COUNTRY "CA" // Canada
#define SUBJ_STATE "ON"   // Ontario
#define SUBJ_LOCALITY "Waterloo"
#define SUBJ_ORGANIZATION "Communication Security Lab"
#define SUBJ_COMMON_NAME "OTPYRC40.eng.uwaterloo.ca"
#define CA_COMMON_NAME "root.eng.uwaterloo.ca"
#define LEAF_COMMON_NAME "leaf.eng.uwaterloo.ca"
#define SUBJ_EMAIL "no-reply@eng.uwaterloo.ca"
// Can be made larger: certgen will definitely run on a browser
#define DER_CERT_MAX_SIZE 4096
#define PEM_CERT_MAX_SIZE 8192
#define DER_KEY_MAX_SIZE 4096
#define PEM_KEY_MAX_SIZE 4096
#define FILE_PATH_MAX_SIZE 1024
#define ECC_KEY_SIZE 32 // TODO: which size corresponds to which curve?
#define NOT_BEFORE_DATE "250101000000Z"
#define NOT_AFTER_DATE "350101000000Z"

int main(int argc, char *argv[0]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <dir>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  const char *dir = argv[1];

  // Check if the path is a directory
  struct stat st;
  if (stat(dir, &st) != 0) {
    perror("Error accessing the directory");
    exit(EXIT_FAILURE);
  }

  if (!S_ISDIR(st.st_mode)) {
    fprintf(stderr, "Error: '%s' is not a directory.\n", dir);
    exit(EXIT_FAILURE);
  }

  Cert root_cert;
  RsaKey root_key;
  RNG rng;
  int rsa_err, root_cert_der_size, root_cert_pem_size;
  uint8_t root_cert_pem[PEM_CERT_MAX_SIZE], root_cert_der[DER_CERT_MAX_SIZE];

  // TODO: InitCert sets sigType to CTC_SHAwRSA, change to something else, later
  // add support for signing with ML-DSA
  wc_InitCert(&root_cert);
  root_cert.sigType = CTC_SHA256wRSA; // NOTE: or `openssl s_server will fail`
  root_cert.isCA = 1;                 // NOTE: or `openssl s_client will fail`
  // Root certificate will be self signed
  strncpy(root_cert.subject.country, SUBJ_COUNTRY, CTC_NAME_SIZE);
  strncpy(root_cert.subject.state, SUBJ_STATE, CTC_NAME_SIZE);
  strncpy(root_cert.subject.locality, SUBJ_LOCALITY, CTC_NAME_SIZE);
  strncpy(root_cert.subject.org, SUBJ_ORGANIZATION, CTC_NAME_SIZE);
  strncpy(root_cert.subject.commonName, CA_COMMON_NAME, CTC_NAME_SIZE);
  strncpy(root_cert.subject.email, SUBJ_EMAIL, CTC_NAME_SIZE);
  root_cert.beforeDate[0] = ASN_UTC_TIME;
  root_cert.beforeDate[1] = ASN_UTC_TIME_SIZE - 1;
  memcpy(root_cert.beforeDate + 2, NOT_BEFORE_DATE, strlen(NOT_BEFORE_DATE));
  root_cert.beforeDateSz = 15;
  root_cert.afterDate[0] = ASN_UTC_TIME;
  root_cert.afterDate[1] = ASN_UTC_TIME_SIZE - 1;
  memcpy(root_cert.afterDate + 2, NOT_AFTER_DATE, strlen(NOT_AFTER_DATE));
  root_cert.afterDateSz = 15;

  wc_InitRng(&rng);
  wc_InitRsaKey(&root_key, NULL);
  rsa_err = wc_MakeRsaKey(&root_key, 2048, 65537, &rng);
  if (rsa_err != 0) {
    fprintf(stderr, "RSA keygen failed (err %d)\n", rsa_err);
    exit(EXIT_FAILURE);
  }

  root_cert_der_size = wc_MakeSelfCert(&root_cert, root_cert_der,
                                       sizeof(root_cert_der), &root_key, &rng);
  if (root_cert_der_size < 0) {
    fprintf(stderr, "Failed to self-sign certificate (err %d)\n",
            root_cert_der_size);
    exit(EXIT_FAILURE);
  }

  root_cert_pem_size =
      wc_DerToPem(root_cert_der, root_cert_der_size, root_cert_pem,
                  sizeof(root_cert_pem), CERT_TYPE);
  if (root_cert_pem_size < 0) {
    fprintf(stderr, "Failed to convert certificate DER to PEM (err %d)\n",
            root_cert_pem_size);
    exit(EXIT_FAILURE);
  }

  uint8_t root_key_der[4096];
  int root_key_der_size;
  if ((root_key_der_size =
           wc_RsaKeyToDer(&root_key, root_key_der, sizeof(root_key_der))) < 0) {
    fprintf(stderr, "Failed to convert RSA key to DER (err %d)\n",
            root_key_der_size);
    exit(EXIT_FAILURE);
  }
  uint8_t root_key_pem[4096];
  int root_key_pem_size;
  if ((root_key_pem_size =
           wc_DerToPem(root_key_der, root_key_der_size, root_key_pem,
                       sizeof(root_key_pem), PRIVATEKEY_TYPE)) < 0) {
    fprintf(stderr, "Failed to convert RSA key to PEM (err %d)\n",
            root_key_pem_size);
    exit(EXIT_FAILURE);
  }

  char root_cert_filepath[FILE_PATH_MAX_SIZE],
      root_key_filepath[FILE_PATH_MAX_SIZE];
  int written;
  FILE *file;
  snprintf(root_cert_filepath, sizeof(root_cert_filepath), "%s/server-root.crt",
           dir);
  file = fopen(root_cert_filepath, "w");
  if (!file) {
    perror("Error opening file for writing");
    exit(EXIT_FAILURE);
  }
  written = fwrite(root_cert_pem, sizeof(uint8_t), root_cert_pem_size, file);
  if (written < root_cert_pem_size) {
    fprintf(stderr, "Wrote %d out of %d bytes\n", written, root_cert_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);
  snprintf(root_key_filepath, sizeof(root_key_filepath), "%s/server-root.key",
           dir);
  file = fopen(root_key_filepath, "w");
  if (!file) {
    perror("Error opening file for writing");
    exit(EXIT_FAILURE);
  }
  written = fwrite(root_key_pem, sizeof(uint8_t), root_key_pem_size, file);
  if (written < root_key_pem_size) {
    fprintf(stderr, "Wrote %d out of %d bytes\n", written, root_key_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);

  // leaf certificate
  Cert leaf_cert;
  wc_InitCert(&leaf_cert);
  leaf_cert.sigType = CTC_SHA256wRSA;
  strncpy(leaf_cert.subject.country, SUBJ_COUNTRY, CTC_NAME_SIZE);
  strncpy(leaf_cert.subject.state, SUBJ_STATE, CTC_NAME_SIZE);
  strncpy(leaf_cert.subject.locality, SUBJ_LOCALITY, CTC_NAME_SIZE);
  strncpy(leaf_cert.subject.org, SUBJ_ORGANIZATION, CTC_NAME_SIZE);
  strncpy(leaf_cert.subject.commonName, LEAF_COMMON_NAME, CTC_NAME_SIZE);
  strncpy(leaf_cert.subject.email, SUBJ_EMAIL, CTC_NAME_SIZE);
  leaf_cert.beforeDate[0] = ASN_UTC_TIME;
  leaf_cert.beforeDate[1] = ASN_UTC_TIME_SIZE - 1;
  memcpy(leaf_cert.beforeDate + 2, NOT_BEFORE_DATE, strlen(NOT_BEFORE_DATE));
  leaf_cert.beforeDateSz = 15;
  leaf_cert.afterDate[0] = ASN_UTC_TIME;
  leaf_cert.afterDate[1] = ASN_UTC_TIME_SIZE - 1;
  memcpy(leaf_cert.afterDate + 2, NOT_AFTER_DATE, strlen(NOT_AFTER_DATE));
  leaf_cert.afterDateSz = 15;
  if (wc_SetIssuerBuffer(&leaf_cert, root_cert_der, root_cert_der_size) != 0) {
    fprintf(stderr, "Failed to set issuer\n");
    exit(EXIT_FAILURE);
  }
  ecc_key leaf_key;
  wc_ecc_init(&leaf_key);
  if (wc_ecc_make_key(&rng, ECC_KEY_SIZE, &leaf_key) != 0) {
    fprintf(stderr, "Failed to make %d byte ECC key\n", ECC_KEY_SIZE);
    exit(EXIT_FAILURE);
  }
  uint8_t leaf_cert_der[DER_CERT_MAX_SIZE], leaf_cert_pem[PEM_CERT_MAX_SIZE];
  int leaf_cert_der_size, leaf_cert_pem_size;
  if ((leaf_cert_der_size =
           wc_MakeCert(&leaf_cert, leaf_cert_der, sizeof(leaf_cert_der), NULL,
                       &leaf_key, &rng)) < 0) {
    fprintf(stderr, "Failed to make leaf certificate (err %d)\n",
            leaf_cert_der_size);
    exit(EXIT_FAILURE);
  }
  leaf_cert_der_size =
      wc_SignCert(leaf_cert.bodySz, leaf_cert.sigType, leaf_cert_der,
                  sizeof(leaf_cert_der), &root_key, NULL, &rng);
  if (leaf_cert_der_size < 0) {
    fprintf(stderr, "Failed to sign leaf certificate (err %d)\n",
            leaf_cert_der_size);
    exit(EXIT_FAILURE);
  }
  leaf_cert_pem_size =
      wc_DerToPem(leaf_cert_der, leaf_cert_der_size, leaf_cert_pem,
                  sizeof(leaf_cert_pem), CERT_TYPE);
  if (leaf_cert_pem_size < 0) {
    fprintf(stderr, "Failed to convert leaf certificate to PEM (err %d)\n",
            leaf_cert_pem_size);
    exit(EXIT_FAILURE);
  }
  uint8_t leaf_key_der[DER_KEY_MAX_SIZE], leaf_key_pem[PEM_KEY_MAX_SIZE];
  int leaf_key_der_size, leaf_key_pem_size;
  leaf_key_der_size =
      wc_EccKeyToDer(&leaf_key, leaf_key_der, sizeof(leaf_key_der));
  if (leaf_key_der_size < 0) {
    fprintf(stderr, "Failed to convert leaf key to DER (err %d)\n",
            leaf_key_der_size);
    exit(EXIT_FAILURE);
  }
  leaf_key_pem_size = wc_DerToPem(leaf_key_der, leaf_key_der_size, leaf_key_pem,
                                  sizeof(leaf_key_pem), ECC_TYPE);
  if (leaf_key_pem_size < 0) {
    fprintf(stderr, "Failed to convert leaf key to PEM (err %d)\n",
            leaf_key_pem_size);
    exit(EXIT_FAILURE);
  }

  char leaf_cert_filepath[FILE_PATH_MAX_SIZE],
      leaf_key_filepath[FILE_PATH_MAX_SIZE];
  snprintf(leaf_cert_filepath, sizeof(leaf_cert_filepath), "%s/server-leaf.crt",
           dir);
  file = fopen(leaf_cert_filepath, "w");
  if (!file) {
    fprintf(stderr, "Failed to open %s to write\n", leaf_cert_filepath);
    exit(EXIT_FAILURE);
  }
  written = fwrite(leaf_cert_pem, sizeof(uint8_t), leaf_cert_pem_size, file);
  if (written < leaf_cert_pem_size) {
    fprintf(stderr, "Wrote %d out of %d bytes\n", written, leaf_cert_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);
  snprintf(leaf_key_filepath, sizeof(leaf_key_filepath), "%s/server-leaf.key",
           dir);
  file = fopen(leaf_key_filepath, "w");
  if (!file) {
    fprintf(stderr, "Failed to open %s to write\n", leaf_key_filepath);
    exit(EXIT_FAILURE);
  }
  written = fwrite(leaf_key_pem, sizeof(uint8_t), leaf_key_pem_size, file);
  if (written < leaf_key_pem_size) {
    fprintf(stderr, "Wrote %d out of %d bytes\n", written, leaf_key_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);

  char chain_cert_filepath[FILE_PATH_MAX_SIZE];
  snprintf(chain_cert_filepath, sizeof(chain_cert_filepath),
           "%s/server-chain.crt", dir);
  file = fopen(chain_cert_filepath, "w");
  if (!file) {
    fprintf(stderr, "Failed to open %s to write\n", chain_cert_filepath);
    exit(EXIT_FAILURE);
  }
  written = fwrite(leaf_cert_pem, sizeof(uint8_t), leaf_cert_pem_size, file);
  if (written < leaf_cert_pem_size) {
    fprintf(stderr, "Wrote %d out of %d bytes\n", written, leaf_cert_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  written = fwrite(root_cert_pem, sizeof(uint8_t), root_cert_pem_size, file);
  if (written < root_cert_pem_size) {
    fprintf(stderr, "Wrote %d out of %d bytes\n", written, root_cert_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);

  return EXIT_SUCCESS;
}

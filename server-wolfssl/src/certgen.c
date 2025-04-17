/**
 * Generate certificate chain
 *
 * Load certificate and key to some server (e.g. rustls/examples/tlsserver-mio)
 * then load CA certificate into curl:
 * >>> curl --cacert ca-cert.pem https://example-server:8000
 */
#include <stdio.h>
#include <string.h>

#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/rsa.h"

#define SUBJ_COUNTRY "CA" // Canada
#define SUBJ_STATE "ON"   // Ontario
#define SUBJ_LOCALITY "Waterloo"
#define SUBJ_ORGANIZATION "Communication Security Lab"
#define SUBJ_COMMON_NAME "OTPYRC40.eng.uwaterloo.ca"
#define SUBJ_EMAIL "no-reply@eng.uwaterloo.ca"
// Can be made larger: certgen will definitely run on a browser
#define DER_CERT_MAX_SIZE 4096
#define PEM_CERT_MAX_SIZE 8192
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

  // Root certificate will be self signed
  strncpy(root_cert.subject.country, SUBJ_COUNTRY, CTC_NAME_SIZE);
  strncpy(root_cert.subject.state, SUBJ_STATE, CTC_NAME_SIZE);
  strncpy(root_cert.subject.locality, SUBJ_LOCALITY, CTC_NAME_SIZE);
  strncpy(root_cert.subject.org, SUBJ_ORGANIZATION, CTC_NAME_SIZE);
  strncpy(root_cert.subject.commonName, SUBJ_COMMON_NAME, CTC_NAME_SIZE);
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

  uint8_t rsa_key_der[4096];
  int rsa_key_der_size;
  if ((rsa_key_der_size =
           wc_RsaKeyToDer(&root_key, rsa_key_der, sizeof(rsa_key_der))) < 0) {
    fprintf(stderr, "Failed to convert RSA key to DER (err %d)\n",
            rsa_key_der_size);
    exit(EXIT_FAILURE);
  }
  uint8_t rsa_key_pem[4096];
  int rsa_key_pem_size;
  if ((rsa_key_pem_size =
           wc_DerToPem(rsa_key_der, rsa_key_der_size, rsa_key_pem,
                       sizeof(rsa_key_pem), PRIVATEKEY_TYPE)) < 0) {
    fprintf(stderr, "Failed to convert RSA key to PEM (err %d)\n",
            rsa_key_pem_size);
    exit(EXIT_FAILURE);
  }

  char filepath[4096];
  size_t written;
  FILE *file;
  snprintf(filepath, sizeof(filepath), "%s/server-ca.crt", dir);
  file = fopen(filepath, "w");
  if (!file) {
    perror("Error opening file for writing");
    exit(EXIT_FAILURE);
  }
  written = fwrite(root_cert_pem, sizeof(uint8_t), root_cert_pem_size, file);
  if (written < (size_t)root_cert_pem_size) {
    fprintf(stderr, "Wrote %zu out of %d bytes\n", written, root_cert_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);
  snprintf(filepath, sizeof(filepath), "%s/server-ca.key", dir);
  file = fopen(filepath, "w");
  if (!file) {
    perror("Error opening file for writing");
    exit(EXIT_FAILURE);
  }
  written = fwrite(rsa_key_pem, sizeof(uint8_t), rsa_key_pem_size, file);
  if (written < (size_t)rsa_key_pem_size) {
    fprintf(stderr, "Wrote %zu out of %d bytes\n", written, rsa_key_pem_size);
    fclose(file);
    exit(EXIT_FAILURE);
  }
  fclose(file);

  return EXIT_SUCCESS;
}

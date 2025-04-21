#include <stdio.h>

#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/dilithium.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
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
#define CERT_DER_MAX_SIZE 8192
#define KEY_DER_MAX_SIZE 8192
#define CERT_PEM_MAX_SIZE 12000
#define KEY_PEM_MAX_SIZE 12000

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

/**
 * Generate a pair of (self-signed) certificate and key
 *
 * cert/key are the destination buffers. `cap` indicates the capacity of the
 * buffer, and `size` encodes the bytes written to them
 *
 * If der_to_pem is 0, then cert/key will have DER-encoded data; otherwise
 * they will have PEM encoding
 */
int generate_dilithium_self_cert_pair(uint8_t *cert, size_t cert_cap,
                                      size_t *cert_size, uint8_t *key,
                                      size_t key_cap, size_t *key_size,
                                      int der_to_pem, RNG *rng) {
  // TODO: make this method more memory efficient
  Cert root_cert;
  uint8_t root_cert_der[CERT_DER_MAX_SIZE], root_cert_pem[CERT_PEM_MAX_SIZE];
  int root_cert_der_size, root_cert_pem_size;

  // Entity of the certificate
  wc_InitCert(&root_cert);
  root_cert.sigType = CTC_ML_DSA_LEVEL5;
  root_cert.isCA = 1;
  strncpy(root_cert.subject.country, LEAF_COUNTRY, CTC_NAME_SIZE);
  strncpy(root_cert.subject.state, LEAF_STATE, CTC_NAME_SIZE);
  strncpy(root_cert.subject.locality, LEAF_LOCALITY, CTC_NAME_SIZE);
  strncpy(root_cert.subject.org, LEAF_ORG, CTC_NAME_SIZE);
  strncpy(root_cert.subject.commonName, LEAF_COMMONNAME, CTC_NAME_SIZE);
  set_before_date_utctime(&root_cert, NOT_BEFORE_DATE);
  set_after_date_utctime(&root_cert, NOT_AFTER_DATE);

  // TODO: Dilithium and ML-DSA are distinct!
  MlDsaKey root_key;
  uint8_t root_key_der[KEY_DER_MAX_SIZE], root_key_pem[KEY_PEM_MAX_SIZE];
  int root_key_der_size, root_key_pem_size;
  wc_MlDsaKey_Init(&root_key, NULL, INVALID_DEVID);
  wc_MlDsaKey_SetParams(&root_key, 5);
  wc_MlDsaKey_MakeKey(&root_key, rng);
  root_cert_der_size =
      wc_MakeCert_ex(&root_cert, root_cert_der, sizeof(root_cert_der),
                     ML_DSA_LEVEL5_TYPE, &root_key, rng);
  if (root_cert_der_size < 0) {
    fprintf(stderr, "Failed to create root cert body (err %d)\n",
            root_cert_der_size);
    return root_cert_der_size;
  } else {
    DEBUG_printf("root cert (unsigned) DER size %d\n", root_cert_der_size);
  }
  root_cert_der_size =
      wc_SignCert_ex(root_cert.bodySz, root_cert.sigType, root_cert_der,
                     sizeof(root_cert_der), ML_DSA_LEVEL5_TYPE, &root_key, rng);
  if (root_cert_der_size < 0) {
    fprintf(stderr, "Failed to sign root cert body (err %d)\n",
            root_cert_der_size);
    return root_cert_der_size;
  } else {
    DEBUG_printf("root cert (signed) DER size %d\n", root_cert_der_size);
  }
  root_cert_pem_size =
      wc_DerToPem(root_cert_der, root_cert_der_size, root_cert_pem,
                  sizeof(root_cert_pem), CERT_TYPE);
  if (root_cert_pem_size < 0) {
    fprintf(stderr, "Failed to convert root cert to PEM (err %d)\n",
            root_cert_pem_size);
    return root_cert_pem_size;
  } else {
    DEBUG_printf("root cert (signed) PEM size %d\n", root_cert_pem_size);
  }

  // convert DER to PEM
  // TODO: using Dilithium method on ML-DSA?
  if ((root_key_der_size = wc_Dilithium_KeyToDer(&root_key, root_key_der,
                                                 sizeof(root_key_der))) < 0) {
    fprintf(stderr, "Failed to convert dilithium key to der (err %d)\n",
            root_key_der_size);
    return root_key_der_size;
  } else {
    DEBUG_printf("root key DER size %d\n", root_key_der_size);
  }
  root_key_pem_size = wc_DerToPem(root_key_der, root_key_der_size, root_key_pem,
                                  sizeof(root_key_pem), ML_DSA_LEVEL5_TYPE);
  if (root_key_pem_size < 0) {
    fprintf(stderr, "Failed to convert dilithium key to PEM (err %d)\n",
            root_key_pem_size);
    return root_key_pem_size;
  } else {
    DEBUG_printf("root key PEM size %d\n", root_key_pem_size);
  }

  uint8_t *cert_src, *key_src;
  size_t cert_src_size, key_src_size;
  if (der_to_pem) {
    cert_src = root_cert_pem;
    key_src = root_key_pem;
    cert_src_size = root_cert_pem_size;
    key_src_size = root_key_pem_size;
  } else {
    cert_src = root_cert_der;
    key_src = root_key_der;
    cert_src_size = root_cert_der_size;
    key_src_size = root_key_der_size;
  }
  if ((cert_src_size > cert_cap) || (key_src_size > key_cap)) {
    DEBUG_printf("cert size %zu, cert cap %zu, key size %zu, key cap %zu",
                 cert_src_size, cert_cap, key_src_size, key_cap);
    return MEMORY_E;
  }
  memcpy(cert, cert_src, cert_src_size);
  *cert_size = cert_src_size;
  memcpy(key, key_src, key_src_size);
  *key_size = key_src_size;

  return 0;
}

int main(void) {
  int certgen_err;
  RNG rng;
  wc_InitRng(&rng);

  size_t root_cert_cap = MAX(CERT_DER_MAX_SIZE, CERT_PEM_MAX_SIZE);
  size_t root_cert_size;
  uint8_t *root_cert = malloc(root_cert_cap);
  if (!root_cert) {
    DEBUG_printf("Failed to allocate %zu for root_cert\n", root_cert_cap);
    exit(EXIT_FAILURE);
  }
  size_t root_key_cap = MAX(KEY_DER_MAX_SIZE, KEY_PEM_MAX_SIZE);
  size_t root_key_size;
  uint8_t *root_key = malloc(root_key_cap);
  if (!root_key) {
    DEBUG_printf("Failed to allocate %zu for root_key\n", root_key_cap);
    exit(EXIT_FAILURE);
  }

  certgen_err = generate_dilithium_self_cert_pair(
      root_cert, root_cert_cap, &root_cert_size, root_key, root_key_cap,
      &root_key_size, 1, &rng);
  if (certgen_err != 0) {
    DEBUG_printf("Failed to generate root cert (err %d)\n", certgen_err);
    free(root_cert);
    free(root_key);
    exit(EXIT_FAILURE);
  }

  fwrite(root_cert, sizeof(uint8_t), root_cert_size, stdout);
  fwrite(root_key, sizeof(uint8_t), root_key_size, stdout);

  free(root_cert);
  free(root_key);
  return 0;
}

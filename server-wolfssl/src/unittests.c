/* unit tests for Ganyu's modifications to WolfSSL
 */

#include "wolfssl/wolfcrypt/asn_public.h"
#include <stdio.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/pqclean_mlkem.h>
#include <wolfssl/wolfcrypt/random.h>

#define KEY_DER_MAX_SZ 100000
#define WITH_PUBKEY_INFO 1

/* A single RNG for all test cases */
static WC_RNG grng;

static int exit_err(const char *caller, int err) {
  printf("%s returned %d\n", caller, err);
  return err;
}

/* Write data to a file at `path`
 *
 * Return 0 on success
 */
static int dump_to_path(const byte *data, size_t len, const char *path) {
  FILE *dmp = fopen(path, "w");
  if (!dmp)
    return -1;
  fwrite(data, sizeof(byte), len, dmp);
  fclose(dmp);
  return 0;
}

/* test exporting PQClean ML-KEM public key to DER */
static int pqclean_mlkem_der() {
  int err;

  PQCleanMlKemKey key;
  byte der[KEY_DER_MAX_SZ];
  size_t derlen;

  if ((err = wc_PQCleanMlKemKey_Init(&key)) < 0)
    return err;
  if ((err = wc_PQCleanMlKemKey_SetLevel(&key, 1)) < 0)
    return err;
  if ((err = wc_PQCleanMlKemKey_MakeKey(&key, &grng)) < 0)
    return err;
  if ((err = wc_PQCleanMlKemKey_PublicKeyToDer(&key, der, sizeof(der),
                                               WITH_PUBKEY_INFO)) < 0)
    return err;
  int expected = 822;
  if (err != expected) {
    fprintf(stderr, "ERROR: public key encoding should be %d, got %d\n",
            expected, err);
    return -1;
  } else {
    derlen = err;
  }
  /* if the length of encoding is correct, then the content it probably correct
   * Use the asn1 program to debug
   */
  if (0)
    dump_to_path(der, derlen, "/tmp/key");

  return err;
}

/* Create an ssl object and try to load a signature private key
 */
static int ssl_load_sig_privkey() {
  int err = 0;
  byte der[KEY_DER_MAX_SZ];
  word32 der_sz;

  ed25519_key key;
  if ((err = wc_ed25519_init(&key)) < 0)
    return err;
  if ((err = wc_ed25519_make_key(&grng, ED25519_KEY_SIZE, &key)) < 0)
    return err;
  if ((err = wc_Ed25519PrivateKeyToDer(&key, der, sizeof(der))) < 0) {
    return err;
  } else {
    der_sz = err;
  }
  wc_ed25519_free(&key);

  if ((err = wolfSSL_Init()) < 0)
    return err;
  WOLFSSL_CTX *ctx;

  ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
  if (ctx == NULL)
    return -1;
  if ((err = wolfSSL_CTX_use_PrivateKey_buffer(ctx, der, der_sz,
                                               SSL_FILETYPE_DEFAULT)) < 0) {
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return err;
  }
  wolfSSL_CTX_free(ctx);
  wolfSSL_Cleanup();

  return err;
}

/* Create an ssl object and try to load a KEM private key
 */
static int ssl_load_kem_privkey() {
  int err = 0;
  byte der[KEY_DER_MAX_SZ];
  word32 der_sz;

  PQCleanMlKemKey key;
  if ((err = wc_PQCleanMlKemKey_Init(&key)) < 0)
    return err;
  if ((err = wc_PQCleanMlKemKey_SetLevel(&key, 1)) < 0)
    return err;
  if ((err = wc_PQCleanMlKemKey_MakeKey(&key, &grng)) < 0)
    return err;
  if ((err = wc_PQCleanMlKemKey_PrivateKeyToDer(&key, der, sizeof(der))) < 0) {
    return err;
  } else {
    der_sz = err;
  }
  wc_PQCleanMlKemKey_Free(&key);

  if ((err = wolfSSL_Init()) < 0)
    return err;
  WOLFSSL_CTX *ctx;

  ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
  if (ctx == NULL)
    return -1;
  if ((err = wolfSSL_CTX_use_PrivateKey_buffer(ctx, der, der_sz,
                                               SSL_FILETYPE_DEFAULT)) < 0) {
    // TODO: this currently returns -463 (WOLFSSL_BAD_FILE)
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return err;
  }
  wolfSSL_CTX_free(ctx);
  wolfSSL_Cleanup();

  return err;
}

int main(void) {
  int err = 0;

  wc_InitRng(&grng);

  if ((err = pqclean_mlkem_der()) < 0)
    return exit_err("pqclean_mlkem_der", err);
  if ((err = ssl_load_sig_privkey()) < 0)
    return exit_err("ssl_load_sig_privkey", err);
  if ((err = ssl_load_kem_privkey()) < 0)
    return exit_err("ssl_load_kem_privkey", err);

  printf("Ok.\n");
  return err;
}

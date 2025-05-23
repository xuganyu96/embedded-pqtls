/* unit tests for Ganyu's modifications to WolfSSL
 */

#include <stdio.h>
#include <wolfssl/wolfcrypt/settings.h>

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

int main(void) {
  int err = 0;

  wc_InitRng(&grng);

  if ((err = pqclean_mlkem_der()) < 0)
    return exit_err("pqclean_mlkem_der", err);

  printf("Ok.\n");
  return err;
}

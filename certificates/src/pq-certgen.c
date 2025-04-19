/**
* Generate a self-signed certificate using ML-DSA-44 (level 1)
*/
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/dilithium.h"

int main(void) {
  Cert root_cert;
  struct dilithium_key root_key;

  wc_InitCert(&root_cert);

  return 0;
}

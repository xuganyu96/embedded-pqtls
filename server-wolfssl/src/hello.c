#include <stdio.h>

#include "wolfssl/wolfcrypt/asn_public.h"

int main(void) {
  Cert root_cert, inter_cert, leaf_cert;
  wc_InitCert(&root_cert);
  wc_InitCert(&inter_cert);
  wc_InitCert(&leaf_cert);

  return 0;
}

March 21, 2025

# Working with WolfSSL
I need to build WolfSSL from [source](https://github.com/wolfssl/wolfssl).

```bash
git clone --branch v5.7.6-stable --depth 1 git@github.com:wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-kyber --enable-dilithium
make
make check # optional
sudo make install
export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"
```

Example client trying to handshake with `www.raspberrypi.com`

```c
#include "wolfssl/options.h"
#include "wolfssl/ssl.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define SERVER "www.raspberrypi.com"
#define PORT 443
// copied from
// https://github.com/raspberrypi/pico-examples/blob/master/pico_w/wifi/tls_client/tls_verify.c
#define ROOT_CA_CERT                                                           \
  "-----BEGIN CERTIFICATE-----\n\
MIIC+jCCAn+gAwIBAgICEAAwCgYIKoZIzj0EAwIwgbcxCzAJBgNVBAYTAkdCMRAw\n\
DgYDVQQIDAdFbmdsYW5kMRIwEAYDVQQHDAlDYW1icmlkZ2UxHTAbBgNVBAoMFFJh\n\
c3BiZXJyeSBQSSBMaW1pdGVkMRwwGgYDVQQLDBNSYXNwYmVycnkgUEkgRUNDIENB\n\
MR0wGwYDVQQDDBRSYXNwYmVycnkgUEkgUm9vdCBDQTEmMCQGCSqGSIb3DQEJARYX\n\
c3VwcG9ydEByYXNwYmVycnlwaS5jb20wIBcNMjExMjA5MTEzMjU1WhgPMjA3MTEx\n\
MjcxMTMyNTVaMIGrMQswCQYDVQQGEwJHQjEQMA4GA1UECAwHRW5nbGFuZDEdMBsG\n\
A1UECgwUUmFzcGJlcnJ5IFBJIExpbWl0ZWQxHDAaBgNVBAsME1Jhc3BiZXJyeSBQ\n\
SSBFQ0MgQ0ExJTAjBgNVBAMMHFJhc3BiZXJyeSBQSSBJbnRlcm1lZGlhdGUgQ0Ex\n\
JjAkBgkqhkiG9w0BCQEWF3N1cHBvcnRAcmFzcGJlcnJ5cGkuY29tMHYwEAYHKoZI\n\
zj0CAQYFK4EEACIDYgAEcN9K6Cpv+od3w6yKOnec4EbyHCBzF+X2ldjorc0b2Pq0\n\
N+ZvyFHkhFZSgk2qvemsVEWIoPz+K4JSCpgPstz1fEV6WzgjYKfYI71ghELl5TeC\n\
byoPY+ee3VZwF1PTy0cco2YwZDAdBgNVHQ4EFgQUJ6YzIqFh4rhQEbmCnEbWmHEo\n\
XAUwHwYDVR0jBBgwFoAUIIAVCSiDPXut23NK39LGIyAA7NAwEgYDVR0TAQH/BAgw\n\
BgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDaQAwZgIxAJYM+wIM\n\
PC3wSPqJ1byJKA6D+ZyjKR1aORbiDQVEpDNWRKiQ5QapLg8wbcED0MrRKQIxAKUT\n\
v8TJkb/8jC/oBVTmczKlPMkciN+uiaZSXahgYKyYhvKTatCTZb+geSIhc0w/2w==\n\
-----END CERTIFICATE-----\n"

static int net_connect(const char *host, int port) {
  struct sockaddr_in server_addr;
  struct hostent *server;
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    return -1;

  server = gethostbyname(host);
  if (!server)
    return -1;

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);

  if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    close(sockfd);
    return -1;
  }
  return sockfd;
}

static void net_cleanup(int sockfd) { close(sockfd); }

int main() {
  int sockfd;
  WOLFSSL_CTX *ctx;
  WOLFSSL *ssl;

  // Initialize WolfSSL
  wolfSSL_Init();
  wolfSSL_Debugging_ON();
  ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
  if (!ctx) {
    printf("Failed to create WolfSSL context\n");
    return -1;
  }

  wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
  if (wolfSSL_CTX_load_verify_buffer(ctx, (const unsigned char *)ROOT_CA_CERT,
                                     strlen(ROOT_CA_CERT),
                                     WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
    printf("Failed to load CA certificate\n");
    return -1;
  }

  ssl = wolfSSL_new(ctx);
  if (!ssl) {
    printf("Failed to create WolfSSL object\n");
    wolfSSL_CTX_free(ctx);
    return -1;
  }

  // Connect to server
  sockfd = net_connect(SERVER, PORT);
  if (sockfd < 0) {
    printf("Failed to connect to server\n");
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return -1;
  }
  printf("Connected to %s:%d\n", SERVER, PORT);

  wolfSSL_set_fd(ssl, sockfd);

  // Perform SSL handshake
  if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
    int err = wolfSSL_get_error(ssl, 0);
    printf("TLS handshake failed: %d\n", err);
    printf("Error string: %s\n", wolfSSL_ERR_error_string(err, NULL));
    net_cleanup(sockfd);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return -1;
  }

  printf("TLS connection established with %s\n", SERVER);

  // Clean up
  wolfSSL_shutdown(ssl);
  net_cleanup(sockfd);
  wolfSSL_free(ssl);
  wolfSSL_CTX_free(ctx);
  wolfSSL_Cleanup();

  return 0;
}
```

Compile with GCC:

```bash
gcc -O3 -Wall main.c -lwolfssl -o main.out
./main.out
```

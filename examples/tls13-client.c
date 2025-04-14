/**
 * Example TLS 1.3 client.
 * Usage: ./examples/tls13-client.out api.github.com
 */
#include "wolfssl/options.h"
#include "wolfssl/ssl.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_HOSTNAME "api.github.com"
#define PORT 443
#define HTTP_REQUEST                                                           \
  "GET /octocat HTTP/1.1\r\n"                                                  \
  "Host: api.github.com\r\n"                                                   \
  "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) "       \
  "Gecko/20100101 Firefox/136.0\r\n"                                           \
  "Accept: application/json\r\n"                                               \
  "Connection: close\r\n\r\n"
#define USERTRUST_ECC_CA_CERT                                                  \
  "-----BEGIN CERTIFICATE-----\n"                                              \
  "MIICjzCCAhWgAwIBAgIQXIuZxVqUxdJxVt7NiYDMJjAKBggqhkjOPQQDAzCBiDEL\n"         \
  "MAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNl\n"         \
  "eSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMT\n"         \
  "JVVTRVJUcnVzdCBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAwMjAx\n"         \
  "MDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT\n"         \
  "Ck5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUg\n"         \
  "VVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBFQ0MgQ2VydGlm\n"         \
  "aWNhdGlvbiBBdXRob3JpdHkwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQarFRaqflo\n"         \
  "I+d61SRvU8Za2EurxtW20eZzca7dnNYMYf3boIkDuAUU7FfO7l0/4iGzzvfUinng\n"         \
  "o4N+LZfQYcTxmdwlkWOrfzCjtHDix6EznPO/LlxTsV+zfTJ/ijTjeXmjQjBAMB0G\n"         \
  "A1UdDgQWBBQ64QmG1M8ZwpZ2dEl23OA1xmNjmjAOBgNVHQ8BAf8EBAMCAQYwDwYD\n"         \
  "VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjA2Z6EWCNzklwBBHU6+4WMB\n"         \
  "zzuqQhFkoJ2UOQIReVx7Hfpkue4WQrO/isIJxOzksU0CMQDpKmFHjFJKS04YcPbW\n"         \
  "RNZu9YO6bVi9JNlWSOrvxKJGgYhqOkbRqZtNyWHa0V1Xahg=\n"                         \
  "-----END CERTIFICATE-----\n"

static int tcp_connect(const char *host, int port) {
  struct sockaddr_in server_addr;
  struct hostent *server;
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    return -1;

  server = gethostbyname(host); // TODO: use getaddrinfo instead
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

static void tcp_close(int sockfd) { close(sockfd); }

int main(int argc, char **argv) {
  char *hostname = (argc < 2) ? DEFAULT_HOSTNAME : argv[1];

  int sockfd;
  WOLFSSL_CTX *ctx;
  WOLFSSL *ssl;

  // Initialize WolfSSL
  wolfSSL_Init();
  // wolfSSL_Debugging_ON();  // uncomment if we need extra debug input
  ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
  wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
  if (!ctx) {
    printf("Failed to create WolfSSL context\n");
    return -1;
  }

  // Root certificates downloaded from
  // https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites
  // if (wolfSSL_CTX_load_verify_locations(
  //         ctx, "./examples/mozilla-trusted-ca.pem", NULL) != SSL_SUCCESS) {
  //   fprintf(stderr, "Error loading root certificates please check the
  //   file.\n"); exit(EXIT_FAILURE);
  // }
  uint8_t ca_cert[] = USERTRUST_ECC_CA_CERT;
  if (wolfSSL_CTX_load_verify_buffer(ctx, ca_cert, sizeof(ca_cert),
                                     WOLFSSL_FILETYPE_PEM) != SSL_SUCCESS) {
    fprintf(stderr, "Error loading root certificates\n");
    exit(EXIT_FAILURE);
  }

  ssl = wolfSSL_new(ctx);
  if (!ssl) {
    printf("Failed to create WolfSSL object\n");
    wolfSSL_CTX_free(ctx);
    return -1;
  }
  // Uncomment to skip server certificate verification (hint: you should not!)
  wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_PEER, NULL);
  // wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, NULL);

  // Connect to server
  if ((sockfd = tcp_connect(hostname, PORT)) < 0) {
    printf("Failed to connect to server\n");
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return -1;
  }
  printf("Connected to %s:%d\n", hostname, PORT);

  wolfSSL_set_fd(ssl, sockfd);

  // Perform SSL handshake
  int ssl_conn_ret;
  if ((ssl_conn_ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
    // https://www.wolfssl.com/documentation/manuals/wolfssl/chapter08.html
    // Examples shows errmsg only needs 80 bytes
    char errmsg[80];
    int err = wolfSSL_get_error(ssl, ssl_conn_ret);
    printf("TLS handshake failed: %d\n", err);
    wolfSSL_ERR_error_string(err, errmsg);
    printf("Error string: %s\n", errmsg);
    tcp_close(sockfd);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return -1;
  }

  printf("Handshake succeeded %s\n", hostname);
  int txsize = wolfSSL_write(ssl, HTTP_REQUEST, strlen(HTTP_REQUEST));
  if (txsize < 0) {
    printf("Failed to write HTTP request to %s\n", hostname);
  } else {
    printf("Wrote %d bytes from %s\n", txsize, hostname);
  }
  uint8_t rxbuf[65535];
  size_t rxbuflen = 0;
  size_t readlen;
  while ((readlen = wolfSSL_read(ssl, rxbuf + rxbuflen,
                                 sizeof(rxbuf) - rxbuflen)) > 0) {
    rxbuflen += readlen;
  }
  printf("%s\n", rxbuf);

  // Clean up
  wolfSSL_shutdown(ssl);
  tcp_close(sockfd);
  wolfSSL_free(ssl);
  wolfSSL_CTX_free(ctx);
  wolfSSL_Cleanup();

  return 0;
}

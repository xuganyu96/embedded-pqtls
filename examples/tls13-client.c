#include "wolfssl/options.h"
#include "wolfssl/ssl.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_HOSTNAME "www.github.com"
#define PORT 443
#define HTTP_REQUEST "GET /octocat HTTP/1.1\r\n" \
"Host: api.github.com\r\n" \
"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0\r\n" \
"Accept: application/json\r\n" \
"Connection: close\r\n\r\n"

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

int main(int argc, char **argv) {
  char *hostname = (argc < 2) ? DEFAULT_HOSTNAME : argv[1];

  int sockfd;
  WOLFSSL_CTX *ctx;
  WOLFSSL *ssl;

  // Initialize WolfSSL
  wolfSSL_Init();
  // wolfSSL_Debugging_ON();  // uncomment if we need extra debug input
  ctx = wolfSSL_CTX_new(wolfTLS_client_method());
  if (!ctx) {
    printf("Failed to create WolfSSL context\n");
    return -1;
  }
  
  // Root certificates downloaded from 
  // https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites
  if (wolfSSL_CTX_load_verify_locations(
          ctx, "./examples/mozilla-trusted-ca.pem", 0) != SSL_SUCCESS) {
    fprintf(stderr, "Error loading ./ca-cert.pem,"
                    " please check the file.\n");
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
  sockfd = net_connect(hostname, PORT);
  if (sockfd < 0) {
    printf("Failed to connect to server\n");
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return -1;
  }
  printf("Connected to %s:%d\n", hostname, PORT);

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

  printf("Handshake succeeded %s\n", hostname);
  int txsize = wolfSSL_write(ssl, HTTP_REQUEST, strlen(HTTP_REQUEST));
  if (txsize < 0) {
    printf("Failed to write HTTP request to %s\n", hostname);
  } else {
    printf("Wrote %d bytes from %s\n", txsize, hostname);
  }
  uint8_t app_readbuf[65535];
  // Read in a loop until wolfSSL_read returns 0, indicating the end of the
  // message
  int readsize = wolfSSL_read(ssl, app_readbuf, sizeof(app_readbuf));
  while (readsize < sizeof(app_readbuf)
    && wolfSSL_read(ssl, app_readbuf + readsize, sizeof(app_readbuf) - readsize) > 0);
  printf("%s\n", app_readbuf);

  // Clean up
  wolfSSL_shutdown(ssl);
  net_cleanup(sockfd);
  wolfSSL_free(ssl);
  wolfSSL_CTX_free(ctx);
  wolfSSL_Cleanup();

  return 0;
}

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "wolfssl/ssl.h"

#define SLEEP_MS 100
#define TEST_ROUNDS 5
#define PATH_MAX_SIZE 1024
#define HOSTNAME_MAX_SIZE 128
#define HELP_DOC                                                               \
  "Usage: tls13client [--cafile root.crt] [--certs client-chain.crt] "         \
  "[--key client.key] <hostname> <port>"

static int kex_groups_pqonly[] = {
    PQCLEAN_ML_KEM_512, PQCLEAN_ML_KEM_768, PQCLEAN_ML_KEM_1024,
    PQCLEAN_HQC_128,    PQCLEAN_HQC_192,    PQCLEAN_HQC_256,
    OT_ML_KEM_512,      OT_ML_KEM_768,      OT_ML_KEM_1024,
};
static int kex_groups_nelems = sizeof(kex_groups_pqonly) / sizeof(int);

typedef struct cli_args {
  // if --help is provided then print help string
  bool help;
  // --debug will turn on wolfssl debugging
  bool debug;
  // optional, --cafile <path> should point to a file that contains PEM-encoded
  // CA certificate. If --cafile is provided, then client will perform server
  // authentication, else it will skip server authentication
  char cafile[PATH_MAX_SIZE];
  // optional, --certs <path> should point to the file that contains PEM-encoded
  // client certificate chain
  char certs[PATH_MAX_SIZE];
  // optional, --key <path> should point to the file that contains PEM-encoded
  // client private key
  char keyfile[PATH_MAX_SIZE];
  // first positional argument, required
  char hostname[HOSTNAME_MAX_SIZE];
  // second positional argument, required
  int port;
} cli_args_t;

/**
 * Set all strings components to the empty string
 */
void cli_args_init(cli_args_t *args) {
  if (args) {
    memset(args, 0, sizeof(cli_args_t));
  }
}

// Helper function to check if a string is a number
bool is_number(const char *s) {
  if (*s == '\0')
    return false;
  while (*s) {
    if (!isdigit(*s++))
      return false;
  }
  return true;
}

int parse_args(int argc, char *argv[], cli_args_t *args) {
  if (argc < 2) {
    fprintf(stderr, "Not enough arguments.\n");
    return -1;
  }

  // Initialize args with default values
  memset(args, 0, sizeof(cli_args_t));

  int positional_count = 0;

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--help") == 0) {
      args->help = true;
      printf("%s\n", HELP_DOC);
      exit(EXIT_SUCCESS);
    } else if (strcmp(argv[i], "--debug") == 0) {
      args->debug = true;
    } else if (strcmp(argv[i], "--cafile") == 0 && i + 1 < argc) {
      strncpy(args->cafile, argv[++i], PATH_MAX_SIZE - 1);
    } else if (strcmp(argv[i], "--certs") == 0 && i + 1 < argc) {
      strncpy(args->certs, argv[++i], PATH_MAX_SIZE - 1);
    } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
      strncpy(args->keyfile, argv[++i], PATH_MAX_SIZE - 1);
    } else if (argv[i][0] != '-') {
      // Positional arguments
      if (positional_count == 0) {
        strncpy(args->hostname, argv[i], HOSTNAME_MAX_SIZE - 1);
      } else if (positional_count == 1) {
        if (!is_number(argv[i])) {
          fprintf(stderr, "Invalid port number: %s\n", argv[i]);
          return -1;
        }
        errno = 0;
        long port = strtol(argv[i], NULL, 10);
        if (errno != 0 || port < 1 || port > 65535) {
          fprintf(stderr, "Port out of range: %s\n", argv[i]);
          return -1;
        }
        args->port = (int)port;
      } else {
        fprintf(stderr, "Unexpected extra positional argument: %s\n", argv[i]);
        return -1;
      }
      positional_count++;
    } else {
      fprintf(stderr, "Unknown argument: %s\n", argv[i]);
      return -1;
    }
  }

  if (!args->help && positional_count < 2) {
    fprintf(stderr,
            "Missing required positional arguments: hostname and port\n");
    return -1;
  }

  return 0;
}

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

int main(int argc, char *argv[]) {
  cli_args_t args;
  cli_args_init(&args);
  if (parse_args(argc, argv, &args)) {
    fprintf(stderr, "Failed to parse CLI args\n");
    exit(EXIT_FAILURE);
  }

  int sockfd, ssl_err;
  WOLFSSL *ssl;
  WOLFSSL_CTX *ctx;
  args.debug ? wolfSSL_Debugging_ON() : wolfSSL_Debugging_OFF();
  wolfSSL_Init();

  for (int round = 0; round < TEST_ROUNDS; round++) {
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) {
      fprintf(stderr, "Failed to create WolfSSL ctx\n");
      exit(EXIT_FAILURE);
    }

    // if cafile is provided then verify peer
    if (strlen(args.cafile) > 0) {
      wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
      ssl_err = wolfSSL_CTX_load_verify_locations(ctx, args.cafile, NULL);
      if (ssl_err != SSL_SUCCESS) {
        fprintf(stderr, "Error loading root certificates (err %d).\n", ssl_err);
        wolfSSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
      }
    } else {
      wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }

    // if certs an keyfile are both provided then load them
    if (strlen(args.certs) > 0 && strlen(args.keyfile) > 0) {
      ssl_err = wolfSSL_CTX_use_certificate_chain_file_format(ctx, args.certs,
                                                              SSL_FILETYPE_PEM);
      if (ssl_err != SSL_SUCCESS) {
        fprintf(stderr, "Failed to load certificate chain (err %d)\n", ssl_err);
        wolfSSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
      }
      // TODO: openssl's private keys work, maybe I should export ML-DSA private
      // key instead of the whole key?
      ssl_err =
          wolfSSL_CTX_use_PrivateKey_file(ctx, args.keyfile, SSL_FILETYPE_PEM);
      if (ssl_err != SSL_SUCCESS) {
        fprintf(stderr, "Failed to load private key (err %d)\n", ssl_err);
        wolfSSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
      }
    }
    // ssl_err = wolfSSL_CTX_set_groups(ctx, kex_groups_pqonly, kex_groups_nelems);
    // if (ssl_err != WOLFSSL_SUCCESS) {
    //   fprintf(stderr, "Failed to set key exchange groups (err %d)\n", ssl_err);
    //   wolfSSL_CTX_free(ctx);
    //   exit(EXIT_FAILURE);
    // }

    ssl = wolfSSL_new(ctx);
    if (!ssl) {
      printf("Failed to create WolfSSL object\n");
      wolfSSL_CTX_free(ctx);
      return -1;
    }

    if ((sockfd = tcp_connect(args.hostname, args.port)) < 0) {
      printf("Failed to connect to server\n");
      wolfSSL_free(ssl);
      wolfSSL_CTX_free(ctx);
      return -1;
    }
    printf("Connected to %s:%d\n", args.hostname, args.port);
    wolfSSL_set_fd(ssl, sockfd);

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
    printf("Handshake succeeded %s\n", args.hostname);

    // Clean up
    wolfSSL_shutdown(ssl);
    tcp_close(sockfd);
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
    usleep(SLEEP_MS * 1000);
  }

  wolfSSL_Cleanup();
  return 0;
}

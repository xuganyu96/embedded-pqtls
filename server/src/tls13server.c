/**
 * TLS 1.3 server
 *
 * Server authentication is mandatory: --certs and --key must be supplied.
 * Mutual authentication is optional, but if --cafile is supplied, then server
 * will request client authentication and abort handshake if client
 * authentication fails
 *
 * GYX: can somewhat verify using OpenSSL but OpenSSL will reject the cert chain
 * openssl s_client -CAfile root.crt -verify_return_error -connect \
 *     localhost:8000 < /dev/null
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <wolfssl/ssl.h>

#define PATH_MAX_SIZE 1024
#define HELP_DOC                                                               \
    "Usage: tls13server --certs <server-chain.crt> --key <leaf.key> "          \
    "[--cafile <root.crt>] port"

typedef struct cli_args {
    // --help should print the help string
    bool help;
    // --certs <file> is required. <file> should point to a file that contains
    // PEM-encoded certificate chain, with leaf certificate on top and root
    // certificate at bottom
    char certs[PATH_MAX_SIZE];
    // --key <file> is required. <file> should point to a PEM-encoded private
    // key
    char keyfile[PATH_MAX_SIZE];
    // --cafile <file> is optional. <file> should point to PEM-encoded root
    // certificate for authenticating the client. If --cafile is provided, then
    // client authentication will be required
    char cafile[PATH_MAX_SIZE];
    // --debug will turn on wolfssl debugging
    bool debug;
    // Port is required
    int port;
} cli_args_t;

void cli_args_init(cli_args_t *args) {
    if (args) {
        memset(args, 0, sizeof(cli_args_t));
        args->debug = false;
    }
}

/**
 * Debug networking peer
 *
 * Retrieve and display the host name and port of the peer
 */
void debug_network_peer(int stream) {
    // get and display peer's address
    struct sockaddr_in peer_addr;
    size_t peer_addr_len = sizeof(peer_addr);
    char peer_addr_str[INET_ADDRSTRLEN];
    getpeername(stream, (struct sockaddr *)&peer_addr,
                (socklen_t *)&peer_addr_len);
    inet_ntop(AF_INET, &(peer_addr.sin_addr), peer_addr_str, INET_ADDRSTRLEN);
    int peer_port = ntohs(peer_addr.sin_port);
    printf("Connected to %s:%d\n", peer_addr_str, peer_port);
}

/**
 * Parse command line argument. Return 0 on success.
 */
int parse_args(cli_args_t *args, int argc, char *argv[]) {
    if (!args || argc < 2) {
        fprintf(stderr, "%s\n", HELP_DOC);
        return -1;
    }

    cli_args_init(args);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            args->help = true;
            printf("%s\n", HELP_DOC);
            return 0;
        } else if (strcmp(argv[i], "--debug") == 0) {
            args->debug = true;
        } else if (strcmp(argv[i], "--certs") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing value for --certs\n");
                return -1;
            }
            strncpy(args->certs, argv[++i], PATH_MAX_SIZE - 1);
        } else if (strcmp(argv[i], "--key") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing value for --key\n");
                return -1;
            }
            strncpy(args->keyfile, argv[++i], PATH_MAX_SIZE - 1);
        } else if (strcmp(argv[i], "--cafile") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing value for --cafile\n");
                return -1;
            }
            strncpy(args->cafile, argv[++i], PATH_MAX_SIZE - 1);
        } else {
            // This must be the port
            char *endptr = NULL;
            long port = strtol(argv[i], &endptr, 10);
            if (*endptr != '\0' || port < 1 || port > 65535) {
                fprintf(stderr, "Error: Invalid port number\n");
                return -1;
            }
            args->port = (int)port;
        }
    }

    // Validation: certs, keyfile, and port are required
    if (args->certs[0] == '\0') {
        fprintf(stderr, "Error: --certs is required\n");
        return -1;
    }
    if (args->keyfile[0] == '\0') {
        fprintf(stderr, "Error: --key is required\n");
        return -1;
    }
    if (args->port == 0) {
        fprintf(stderr, "Error: port is required\n");
        return -1;
    }

    return 0;
}

/* block until having received something, then write it back and exit
 */
int echo_server(WOLFSSL *ssl) {
    int ret = 0;
    uint8_t buf[80];
    size_t buflen = 0;

    /* for testing purpose only */
    while (buflen <= 0) {
        ret = wolfSSL_read(ssl, buf, sizeof(buf));
        if (ret <= 0) {
            fprintf(stderr, "read (err=%d)\n", ret);
            return -1;
        }
        fprintf(stderr, "received %d bytes\n", ret);
        buflen += (size_t)ret;
    }

    ret = wolfSSL_write(ssl, buf, buflen);
    if (ret <= 0) {
        fprintf(stderr, "failed to write %zu bytes\n", buflen);
        return ret;
    }
    fprintf(stderr, "wrote %zu bytes\n", buflen);
    return 0;
}

// static int kex_groups_pqonly[] = {
//     WOLFSSL_ML_KEM_512,
// };
// static int kex_groups_nelems = 1;

int main(int argc, char *argv[]) {
    int err;
    int ret = 0;
    cli_args_t args;
    struct timespec accept_finish_ts, accept_start_ts;

    cli_args_init(&args);
    if ((err = parse_args(&args, argc, argv)) != 0) {
        exit(err);
    }
    if (args.help) {
        exit(EXIT_SUCCESS);
    }

    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;

    int listener, stream = 0;
    struct sockaddr_in addr;
    size_t addr_size = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(args.port);

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (!listener) {
        fprintf(stderr, "Failed to create socket\n");
        ret = -1;
        goto shutdown;
    }
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) <
        0) {
        fprintf(stderr, "Failed to set listener to re-use port\n");
        exit(EXIT_FAILURE);
    }
    err = bind(listener, (struct sockaddr *)&addr, addr_size);
    if (err < 0) {
        fprintf(stderr, "Failed to bind socket to port %d\n", args.port);
        ret = -1;
        goto shutdown;
    }
    err = listen(listener, 5);
    if (err < 0) {
        fprintf(stderr, "Failed to listen on port %d\n", args.port);
        ret = -1;
        goto shutdown;
    } else {
        printf("Listening on port %d\n", args.port);
    }

    args.debug ? wolfSSL_Debugging_ON() : wolfSSL_Debugging_OFF();
    err = wolfSSL_Init();
    if (err != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to initialize WolfSSL\n");
        ret = -1;
        goto shutdown;
    }
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method())) == NULL) {
        fprintf(stderr, "Failed to create TLSv1.3 context\n");
        ret = -1;
        goto shutdown;
    }
    err = wolfSSL_CTX_use_PrivateKey_file(ctx, args.keyfile, SSL_FILETYPE_PEM);
    if (err != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to load private key (err %d)\n", err);
        ret = -1;
        goto shutdown;
    }
    err = wolfSSL_CTX_use_certificate_chain_file_format(ctx, args.certs,
                                                        SSL_FILETYPE_PEM);
    if (err != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to load certificate chain\n");
        ret = -1;
        goto shutdown;
    }
    if (strlen(args.cafile) > 0) {
        err = wolfSSL_CTX_load_verify_locations(ctx, args.cafile, NULL);
        if (err != WOLFSSL_SUCCESS) {
            fprintf(stderr, "Failed to load client CA\n");
            ret = -1;
            goto shutdown;
        }
        wolfSSL_CTX_set_verify(
            ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            NULL);
    } else {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }

    int rounds = 0;
    while (1) {
        stream =
            accept(listener, (struct sockaddr *)&addr, (socklen_t *)&addr_size);
        if (stream < 0) {
            fprintf(stderr, "Failed to accept incoming connection\n");
            goto shutdown;
        }
        debug_network_peer(stream);

        ssl = wolfSSL_new(ctx);

        if (!ssl) {
            fprintf(stderr, "Failed to create new SSL\n");
            ret = -1;
            goto shutdown;
        }
        wolfSSL_set_fd(ssl, stream);
        clock_gettime(CLOCK_MONOTONIC, &accept_start_ts);
        err = wolfSSL_accept(ssl);
        if (err != WOLFSSL_SUCCESS) {
            char errmsg[80];
            fprintf(stderr, "TLS handshake failed: %d\n", err);
            wolfSSL_ERR_error_string(wolfSSL_get_error(ssl, err), errmsg);
            fprintf(stderr, "Error string: %s\n", errmsg);
        } else {
            clock_gettime(CLOCK_MONOTONIC, &accept_finish_ts);
            int64_t interval =
                (accept_finish_ts.tv_sec - accept_start_ts.tv_sec) * 1000000 +
                (accept_finish_ts.tv_nsec - accept_start_ts.tv_nsec) / 1000;
            printf("Successful handshake %04d (dur=%9"PRIi64")\n", rounds++, interval);
        }

        err = echo_server(ssl);
        if (err) {
            fprintf(stderr, "echo_server returned %d\n", err);
        } else {
            printf("Ok.\n");
        }

        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        ssl = NULL;
        close(stream);
    }

shutdown:
    if (listener) {
        close(listener);
    }
    if (stream) {
        close(stream);
    }
    if (ctx) {
        wolfSSL_CTX_free(ctx);
    }
    if (ssl) {
        wolfSSL_free(ssl);
    }
    return ret;
}

/* tlsserver.c
 *
 * Handshake only: terminates connection as soon as the connection is
 * established
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "wolfssl/ssl.h"

#define REUSE_ADDR 1
#define ACCEPT_QUEUE_N 5
#define INVALID_FD -1
#define HELP                                                                   \
    "Usage: tlsserver [--debug] --certs <certfile> --key <keyfile> [--cafile " \
    "<cafile>] <port>\n"                                                       \
    "\n"                                                                       \
    "Arguments:\n"                                                             \
    "  --debug                Enable debug mode by activating "                \
    "wolfSSL_Debugging_ON. This provides detailed logging for debugging "      \
    "purposes. "                                                               \
    "Note that this option requires the compilation flag DEBUG_WOLFSSL to be " \
    "set during the build process.\n"                                          \
    "\n"                                                                       \
    "  --certs <certfile>     Specify the path to the certificate file. This " \
    "file should contain the server's public certificate in PEM format. It "   \
    "is "                                                                      \
    "required for establishing a secure TLS connection.\n"                     \
    "\n"                                                                       \
    "  --key <keyfile>        Specify the path to the private key file. This " \
    "file should contain the server's private key in DER format. It is "       \
    "required "                                                                \
    "for decrypting incoming messages and establishing secure connections.\n"  \
    "\n"                                                                       \
    "  --cafile <cafile>      (Optional) Specify the path to the Certificate " \
    "Authority (CA) file. This file should contain the CA certificates in "    \
    "PEM "                                                                     \
    "format that the server trusts. It is used to verify the client "          \
    "certificates "                                                            \
    "if client authentication is enabled.\n"                                   \
    "\n"                                                                       \
    "  <port>                 Specify the port number on which the server "    \
    "will "                                                                    \
    "listen for incoming TLS connections. This is a required argument and "    \
    "must "                                                                    \
    "be a valid integer between 1 and 65535.\n"

/* Return true if path points to a regular file */
static int is_file(const char *path) {
    struct stat target;
    int err;
    if ((err = stat(path, &target)) != 0) {
        fprintf(stderr, "Cannot read from %s\n", path);
        return 0;
    }
    return S_ISREG(target.st_mode);
}

struct CliArgs {
    char *cafile;
    char *keyfile;
    char *certfile;
    int debug;
    uint16_t port;
};

static int CliArgs_check(struct CliArgs *args) {
    if (args->certfile == NULL) {
        fprintf(stderr, "--certfile is required\n");
        return -1;
    } else if (!is_file(args->certfile)) {
        fprintf(stderr, "%s is not valid file\n", args->certfile);
        return -1;
    }
    if (args->keyfile == NULL) {
        fprintf(stderr, "--keyfile is required\n");
        return -1;
    } else if (!is_file(args->keyfile)) {
        fprintf(stderr, "%s is not valid file\n", args->keyfile);
        return -1;
    }
    if ((args->port < 1024) || (args->port > 65535)) {
        fprintf(stderr,
                "port must be between 1024 and 65535, got %" PRIu16 "\n",
                args->port);
        return -1;
    }

    /* If cafile is not NULL, then it must be regular file */
    if (args->cafile) {
        if (!is_file(args->cafile)) {
            fprintf(stderr, "%s is not valid file\n", args->cafile);
            return -1;
        }
    }

    return 0;
}

int CliArgs_init(struct CliArgs *args) {
    if (args == NULL) {
        return BAD_FUNC_ARG;
    }
    memset(args, 0, sizeof(struct CliArgs));
    return 0;
}

int CliArgs_parse(struct CliArgs *args, int argc, char *argv[]) {
    int err = -1;
    (void)args;
    (void)argc;
    (void)argv;

    int argi = 1; /* argv[0] is the program name */

    int expect_kwargs = argi < argc;
    while (expect_kwargs) {
        if (strncmp(argv[argi], "--debug", sizeof("--debug")) == 0) {
            args->debug = 1;
            argi++;
        } else if (strncmp(argv[argi], "--certs", sizeof("--certs")) == 0) {
            if (argi + 1 < argc) {
                args->certfile = argv[argi + 1];
                argi += 2;
            } else {
                fprintf(stderr, "Missing value for --certs\n");
                return -1;
            }
        } else if (strncmp(argv[argi], "--key", sizeof("--key")) == 0) {
            if (argi + 1 < argc) {
                args->keyfile = argv[argi + 1];
                argi += 2;
            } else {
                fprintf(stderr, "Missing value for --certs\n");
                return -1;
            }
        } else if (strncmp(argv[argi], "--cafile", sizeof("--cafile")) == 0) {
            if (argi + 1 < argc) {
                args->cafile = argv[argi + 1];
                argi += 2;
            } else {
                fprintf(stderr, "Missing value for --certs\n");
                return -1;
            }
        } else {
            expect_kwargs = 0;
        }
    }

    if (argi < argc) {
        args->port = atoi(argv[argi]);
    }

    err = CliArgs_check(args);

    return err;
}

/* Print values of args struct for debugging purpose */
void CliArgs_debug(struct CliArgs *args) {
    if (args->keyfile) {
        fprintf(stderr, "%12s: %s\n", "keyfile", args->keyfile);
    }
    if (args->certfile) {
        fprintf(stderr, "%12s: %s\n", "certfile", args->certfile);
    }
    if (args->cafile) {
        fprintf(stderr, "%12s: %s\n", "cafile", args->cafile);
    }
    fprintf(stderr, "%12s: %d\n", "debug", args->debug);
    fprintf(stderr, "%12s: %d\n", "port", args->port);
}

/* Encapsulate the socket and address info
 * Currently only supports IPv4 address
 */
struct TcpListener {
    struct sockaddr_in addr;
    size_t addr_sz;
    int sock;
    /* TODO: this means it can only handle one connection at a time, how can I
     * make it handle multiple connections at a time */
    int stream;
};

/* Create an IPv4 socket, binds it to the specified port, then start listening
 */
int TcpListener_init(struct TcpListener *listener, uint16_t port, int reuse) {
    if (listener == NULL) {
        return BAD_FUNC_ARG;
    }
    memset(&listener->addr, 0, sizeof(struct sockaddr_in));
    listener->stream = INVALID_FD;
    listener->sock = INVALID_FD;
    listener->addr.sin_family = AF_INET;
    listener->addr.sin_addr.s_addr = INADDR_ANY;
    listener->addr.sin_port = port;
    listener->addr_sz = sizeof(struct sockaddr_in);
    listener->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listener->sock < 0) {
        perror("Failed to create a socket");
        return -1;
    }
    if (reuse) {
        if (setsockopt(listener->sock, SOL_SOCKET, SO_REUSEADDR, &(int){1},
                       sizeof(int)) < 0) {
            perror("Failed to set reusable address");
            close(listener->sock);
            return -1;
        }
    }
    if (bind(listener->sock, (struct sockaddr *)&listener->addr,
             listener->addr_sz) < 0) {
        perror("Failed to bind listener to address");
        close(listener->sock);
        listener->sock = INVALID_FD;
        return -1;
    }
    if (listen(listener->sock, 5) < 0) {
        perror("Failed to listen");
        close(listener->sock);
        listener->sock = INVALID_FD;
        return -1;
    }
    return 0;
}

/* If it fails to accept a connection, will not automatically close the socket
 */
int TcpListener_accept(struct TcpListener *listener) {
    if (listener == NULL) {
        return BAD_FUNC_ARG;
    }
    if (listener->stream != INVALID_FD) {
        fprintf(stderr, "Connection is busy\n");
        return -1;
    }
    listener->stream =
        accept(listener->sock, (struct sockaddr *)&listener->addr,
               (socklen_t *)&listener->addr_sz);
    if (listener->stream < 0) {
        perror("Failed to accept connection");
        listener->stream = INVALID_FD;
        return -1;
    }
    return 0;
}

int TcpListener_close(struct TcpListener *listener) {
    if (listener == NULL) {
        return BAD_FUNC_ARG;
    }
    if (listener->sock != INVALID_FD) {
        if (close(listener->sock) < 0) {
            perror("Ignoring `close` error: ");
        }
    }
    if (listener->stream != INVALID_FD) {
        if (close(listener->stream) < 0) {
            perror("Ignoring `close` error: ");
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int err, ec = 0;
    struct CliArgs args;
    CliArgs_init(&args);
    if ((err = CliArgs_parse(&args, argc, argv)) < 0) {
        printf("%s\n", HELP);
        exit(EXIT_FAILURE);
    }
    CliArgs_debug(&args);

    wolfSSL_Init();
    if (args.debug) {
        wolfSSL_Debugging_ON();
    } else {
        wolfSSL_Debugging_OFF();
    }
    WOLFSSL_CTX *ctx;

    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method())) == NULL) {
        fprintf(stderr, "Failed to create WOLFSSL_CTX\n");
        ec = 1;
        goto cleanup;
    }
    if ((err = wolfSSL_CTX_use_PrivateKey_file(
             ctx, args.keyfile, SSL_FILETYPE_DEFAULT)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to load private key file %s\n", args.keyfile);
        ec = 1;
        goto cleanup;
    }
    if ((err = wolfSSL_CTX_use_certificate_chain_file_format(
             ctx, args.certfile, SSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to load certificates %s\n", args.certfile);
        ec = 1;
        goto cleanup;
    }
    if (args.cafile) {
        if ((err = wolfSSL_CTX_load_verify_locations(ctx, args.cafile, NULL)) !=
            WOLFSSL_SUCCESS) {
            fprintf(stderr, "Failed to load CA file %s\n", args.cafile);
            ec = 1;
            goto cleanup;
        }
        wolfSSL_CTX_set_verify(
            ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            NULL);
    } else {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }

    struct TcpListener listener;
    if ((err = TcpListener_init(&listener, args.port, REUSE_ADDR)) < 0) {
        fprintf(stderr, "Failed to listen to port %d\n", args.port);
        goto cleanup;
    }
    printf("Listening to port %d\n", args.port);

    for (int i = 0; i < 2; i++) {
        if (TcpListener_accept(&listener) < 0) {
            fprintf(stderr, "Failed to accept\n");
            goto cleanup;
        }

        printf("Accepted connection\n");
        close(listener.stream);
        listener.stream = INVALID_FD;
    }

cleanup:
    if (ctx) {
        wolfSSL_CTX_free(ctx);
    }
    wolfSSL_Cleanup();
    TcpListener_close(&listener);

    return ec;
}

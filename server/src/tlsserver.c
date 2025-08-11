/* tlsserver.c
 *
 * Handshake only: terminates connection as soon as the connection is
 * established
 *
 * Test with Openssl:
 *  openssl s_client \
 *      -cert <cert> \
 *      -key <key> \
 *      -CAfile <root> \
 *      -verify_return_error \
 *      -connect \
 *      localhost:8000
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "wolfssl/ssl.h"

#define REUSE_ADDR 1
#define ACCEPT_QUEUE_N 5
#define INVALID_FD -1
#define APP_BUF_SZ 256
#define HELP                                                                   \
    "Usage: tlsserver [--debug] --certs <certfile> --key <keyfile> [--cafile " \
    "<cafile>] <port>\n"                                                       \
    "\n"                                                                       \
    "Arguments:\n"                                                             \
    "  --debug              Enable wolfSSL_Debugging_ON. Requires the macro "  \
    "DEBUG_WOLFSSL to be set at compile time\n"                                \
    "  --certs <certfile>   Required. Loads PEM-encoded certificate chain at " \
    "the specified location. Leaf certificate must be on top\n"                \
    "  --key <keyfile>      Required. Loads DER-encoded private key for "      \
    "server authentication\n"                                                  \
    "  --cafile <cafile>    Optional. Loads PEM-encoded root certificate at "  \
    "the specified path. If cafile is specified, then server "                 \
    "will request client authentication\n"                                     \
    "  <port>               Required. The server will listen for incoming "    \
    "TCP connection on this port\n"

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
};

/* Create an IPv4 socket, binds it to the specified port, then start listening
 */
int TcpListener_init(struct TcpListener *listener, uint16_t port, int reuse) {
    if (listener == NULL) {
        return BAD_FUNC_ARG;
    }
    memset(&listener->addr, 0, sizeof(struct sockaddr_in));
    listener->sock = INVALID_FD;
    listener->addr.sin_family = AF_INET;
    listener->addr.sin_addr.s_addr = INADDR_ANY;
    listener->addr.sin_port = htons(port);
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

int TcpListener_accept(struct TcpListener *listener) {
    int stream = INVALID_FD;
    if (listener == NULL) {
        return BAD_FUNC_ARG;
    }
    stream = accept(listener->sock, (struct sockaddr *)&listener->addr,
                    (socklen_t *)&listener->addr_sz);
    if (stream < 0) {
        perror("Failed to accept connection");
        return -1;
    } else {
        struct sockaddr_in peer_addr;
        size_t peer_addr_len = sizeof(peer_addr);
        char peer_addr_str[INET_ADDRSTRLEN];
        getpeername(stream, (struct sockaddr *)&peer_addr,
                    (socklen_t *)&peer_addr_len);
        inet_ntop(AF_INET, &(peer_addr.sin_addr), peer_addr_str,
                  INET_ADDRSTRLEN);
        int peer_port = ntohs(peer_addr.sin_port);
        fprintf(stderr, "Connected to %s:%d\n", peer_addr_str, peer_port);
    }
    return stream;
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
    return 0;
}

/* Echo client's application data until client hangs up */
void echo_server(WOLFSSL *ssl) {
    char buf[APP_BUF_SZ];
    size_t buflen = 0;
    int ret = 0, err = 0;

    while (1) {
        ret = wolfSSL_read(ssl, buf, sizeof(buf));
        if (ret <= 0) {
            err = wolfSSL_get_error(ssl, err);
            fprintf(stderr, "SSL has nothing to read (err=%d)\n", err);
            return;
        }
        buflen = ret;
        ret = wolfSSL_write(ssl, buf, buflen);
        if (ret <= 0) {
            err = wolfSSL_get_error(ssl, err);
            fprintf(stderr, "SSL failed to write %zu bytes (err=%d)\n", buflen,
                    err);
            return;
        }
        fprintf(stderr, "SSL wrote %zu bytes\n", buflen);
        buflen = 0;
    }
}

int main(int argc, char *argv[]) {
    int err, ec = 0, stream = INVALID_FD;
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
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;

    /* TODO: simplify this */
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

    while (1) {
        if ((stream = TcpListener_accept(&listener)) < 0) {
            fprintf(stderr, "Failed to accept\n");
            goto cleanup;
        }

        if ((ssl = wolfSSL_new(ctx)) == NULL) {
            fprintf(stderr, "Failed to allocate WOLFSSL\n");
            goto cleanup;
        }
        if ((err = wolfSSL_set_fd(ssl, stream)) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "Failed to bind WOLFSSL to TCP stream\n");
            goto cleanup;
        }
        if ((err = wolfSSL_accept(ssl)) != WOLFSSL_SUCCESS) {
            int wolfssl_e = wolfSSL_get_error(ssl, err);
            fprintf(stderr, "wolfSSL_accept failed (err=%d)\n", wolfssl_e);
        } else {
            fprintf(stderr, "Successful handshake\n");
            echo_server(ssl);
            /* TODO: shutdown might fail; need to handle shutdown's error */
            wolfSSL_shutdown(ssl);
        }

        if (close(stream) == 0) {
            fprintf(stderr, "Gracefully shutdown connection\n");
        } else {
            perror("Failed to gracefully shutdown connection\n");
        }
        stream = INVALID_FD;
    }

cleanup:
    if (ctx) {
        wolfSSL_CTX_free(ctx);
    }
    if (ssl) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }
    wolfSSL_Cleanup();
    TcpListener_close(&listener);

    return ec;
}

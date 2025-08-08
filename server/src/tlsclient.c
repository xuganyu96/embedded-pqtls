/* tlsclient.c
 *
 * A simple TLS client that performs a handshake then immediately hang up
 *
 * Command line options:
 *  --debug             enables wolfssl_debugging_on, requires DEBUG_WOLFSSL at
 *                      compile time
 *  --cafile <path>     load PEM-encoded root certificate. If supplied, then
 *                      server authentication is required, else it is disabled
 *  --certs <path>      load certificate chain.
 *  --key <path>        load private key
 *  --namedgroup <name> force key exchange to use this group
 *  <host>              remote host to connect to
 *  <port>              remote port to connect to
 */
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#include "wolfssl/ssl.h"

#define INVALID_FD -1
#define HELP                                                                   \
    "Usage: tlsclient [--debug] [--cafile <path>] [--certs <path>] [--key "    \
    "<path>] [--namedgroup <x25519|secp256r1|mlkem512>] <host> <port>"

static int default_kex_groups[] = {
    WOLFSSL_ECC_X25519,    WOLFSSL_ECC_SECP256R1, WOLFSSL_ECC_SECP384R1,
    WOLFSSL_ECC_SECP521R1, WOLFSSL_ECC_X448,      WOLFSSL_ML_KEM_512,
    WOLFSSL_ML_KEM_768,    WOLFSSL_ML_KEM_1024,
};
static int default_kex_n = sizeof(default_kex_groups) / sizeof(int);

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

static int get_namedgroup_from_name(const char *name) {
    if (strncmp(name, "x25519", sizeof("x25519")) == 0) {
        return WOLFSSL_ECC_X25519;
    } else if (strncmp(name, "secp256r1", sizeof("secp256r1")) == 0) {
        return WOLFSSL_ECC_SECP256R1;
    } else if (strncmp(name, "secp384r1", sizeof("secp384r1")) == 0) {
        return WOLFSSL_ECC_SECP384R1;
    } else if (strncmp(name, "secp521r1", sizeof("secp521r1")) == 0) {
        return WOLFSSL_ECC_SECP521R1;
    } else if (strncmp(name, "x448", sizeof("x448")) == 0) {
        return WOLFSSL_ECC_X448;
    } else if (strncmp(name, "mlkem512", sizeof("mlkem512")) == 0) {
        return WOLFSSL_ML_KEM_512;
    } else if (strncmp(name, "mlkem768", sizeof("mlkem768")) == 0) {
        return WOLFSSL_ML_KEM_768;
    } else if (strncmp(name, "mlkem1024", sizeof("mlkem1024")) == 0) {
        return WOLFSSL_ML_KEM_1024;
    }
    return NOT_COMPILED_IN;
}

struct CliArgs {
    int debug;
    char *cafile;
    char *certfile;
    char *keyfile;
    char *host;
    char *namedgroup;
    uint16_t port;
};

int CliArgs_init(struct CliArgs *args) {
    if (args == NULL) {
        return BAD_FUNC_ARG;
    }
    memset(args, 0, sizeof(struct CliArgs));
    return 0;
}

int CliArgs_check(struct CliArgs *args) {
    if (args->cafile != NULL && !is_file(args->cafile)) {
        fprintf(stderr, "%s is not valid file\n", args->cafile);
        return -1;
    }
    if (args->certfile != NULL && !is_file(args->certfile)) {
        fprintf(stderr, "%s is not valid file\n", args->certfile);
        return -1;
    }
    if (args->keyfile != NULL && !is_file(args->keyfile)) {
        fprintf(stderr, "%s is not valid file\n", args->keyfile);
        return -1;
    }
    if ((args->port < 1024) || (args->port > 65535)) {
        fprintf(stderr,
                "port must be between 1024 and 65535, got %" PRIu16 "\n",
                args->port);
        return -1;
    }
    if (get_namedgroup_from_name(args->namedgroup) < 0) {
        fprintf(stderr, "%s is not supported named group\n", args->namedgroup);
        return -1;
    }

    return 0;
}

int CliArgs_parse(struct CliArgs *args, int argc, char **argv) {
    int argi = 1; /* argv[0] is program name */
    int expect_kwargs = argi < argc;

    while (expect_kwargs && argi < argc) {
        if (strncmp(argv[argi], "--debug", sizeof("--debug")) == 0) {
            args->debug = 1;
            argi++;
        } else if (strncmp(argv[argi], "--cafile", sizeof("--cafile")) == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "Missing value for --cafile\n");
                return -1;
            }
            args->cafile = argv[argi + 1];
            argi += 2;
        } else if (strncmp(argv[argi], "--namedgroup",
                           sizeof("--namedgroup")) == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "Missing value for --namedgroup\n");
                return -1;
            }
            args->namedgroup = argv[argi + 1];
            argi += 2;
        } else if (strncmp(argv[argi], "--certs", sizeof("--certs")) == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "Missing value for --certs\n");
                return -1;
            }
            args->certfile = argv[argi + 1];
            argi += 2;
        } else if (strncmp(argv[argi], "--key", sizeof("--key")) == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "Missing value for --key\n");
                return -1;
            }
            args->keyfile = argv[argi + 1];
            argi += 2;
        } else {
            expect_kwargs = 0;
        }
    }

    if (argi < argc) {
        args->host = argv[argi++];
    }
    if (argi < argc) {
        args->port = atoi(argv[argi]);
    }

    return CliArgs_check(args);
}

int CliArgs_debug(struct CliArgs *args) {
    if (args->debug) {
        printf("%12s: %d\n", "debug", args->debug);
    }
    if (args->cafile) {
        printf("%12s: %s\n", "cafile", args->cafile);
    }
    if (args->certfile) {
        printf("%12s: %s\n", "certs", args->certfile);
    }
    if (args->keyfile) {
        printf("%12s: %s\n", "keyfile", args->keyfile);
    }
    if (args->host) {
        printf("%12s: %s\n", "host", args->host);
    }
    if (args->port) {
        printf("%12s: %d\n", "port", args->port);
    }
    if (args->namedgroup) {
        printf("%12s: %s\n", "namedgroup", args->namedgroup);
    }
    return 0;
}

static int set_wolfssl_ctx(WOLFSSL_CTX *ctx, const char *cafile,
                           const char *certfile, const char *keyfile,
                           const char *namedgroup) {
    int err = 0;

    if (cafile) {
        if ((err = wolfSSL_CTX_load_verify_locations(ctx, cafile, NULL)) !=
            WOLFSSL_SUCCESS) {
            fprintf(stderr, "Failed to load CA certificate (err=%d)\n", err);
            return err;
        }
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    } else {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }

    if (certfile != NULL && keyfile != NULL) {
        if ((err = wolfSSL_CTX_use_certificate_chain_file_format(
                 ctx, certfile, SSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "Failed to load certificate chain (err=%d)\n", err);
            return err;
        }
        if ((err = wolfSSL_CTX_use_PrivateKey_file(
                 ctx, keyfile, SSL_FILETYPE_DEFAULT)) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "Failed to load private key (err=%d)\n", err);
            return err;
        }
    }

    if (namedgroup) {
        int namedgroups[1] = {0};
        int namedgroups_n = 1;
        namedgroups[0] = get_namedgroup_from_name(namedgroup);
        err = wolfSSL_CTX_set_groups(ctx, namedgroups, namedgroups_n);
    } else {
        err = wolfSSL_CTX_set_groups(ctx, default_kex_groups, default_kex_n);
    }
    if (err != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to set named groups\n");
        return err;
    }

    return 0;
}

static int TcpStream_connect(const char *host, uint16_t port) {
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

int main(int argc, char *argv[]) {
    int err = 0, ret = 0, stream = INVALID_FD;

    struct CliArgs args;
    CliArgs_init(&args);
    if (CliArgs_parse(&args, argc, argv) < 0) {
        fprintf(stderr, "%s\n", HELP);
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

    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method())) == NULL) {
        fprintf(stderr, "Failed to create WOLFSSL_CTX\n");
        ret = 1;
        goto cleanup;
    }
    if ((err = set_wolfssl_ctx(ctx, args.cafile, args.certfile, args.keyfile,
                               args.namedgroup)) < 0) {
        fprintf(stderr, "Failed to configure WOLFSSL_CTX\n");
        ret = 1;
        goto cleanup;
    }

    if ((stream = TcpStream_connect(args.host, args.port)) < 0) {
        fprintf(stderr, "Failed to connect to %s:%d\n", args.host, args.port);
        ret = 1;
        goto cleanup;
    }

    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "Failed to create WOLFSSL struct\n");
        ret = 1;
        goto cleanup;
    }

    wolfSSL_set_fd(ssl, stream);

    if ((err = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
        int wolfssl_err = wolfSSL_get_error(ssl, err);
        fprintf(stderr, "TLS connection failed (err=%d)\n", wolfssl_err);
    } else {
        fprintf(stderr, "Successful handshake\n");
        wolfSSL_shutdown(ssl);
    }

cleanup:
    if (ctx) {
        wolfSSL_CTX_free(ctx);
    }
    if (ssl) {
        wolfSSL_free(ssl);
    }
    if (stream >= 0) {
        if (close(stream) == 0) {
            fprintf(stderr, "Gracefully shutdown connection\n");
        } else {
            perror("Failed to gracefully shutdown connection\n");
        }
        stream = INVALID_FD;
    }
    wolfSSL_Cleanup();

    return ret;
}

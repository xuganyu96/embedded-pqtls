/* tlsserver.c
 *
 * Handshake only: terminates connection as soon as the connection is
 * established
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "wolfssl/ssl.h"

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

int main(int argc, char *argv[]) {
    int err = 0;
    struct CliArgs args;
    CliArgs_init(&args);
    if ((err = CliArgs_parse(&args, argc, argv)) < 0) {
        printf("%s\n", HELP);
        exit(EXIT_FAILURE);
    }

    CliArgs_debug(&args);

    wolfSSL_Init();

    return err;
}

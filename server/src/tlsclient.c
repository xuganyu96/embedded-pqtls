/* tlsclient.c
 *
 * A simple TLS client that performs a handshake then immediately hang up
 *
 * Command line options:
 *  --debug         enables wolfssl_debugging_on, requires DEBUG_WOLFSSL at
 *                  compile time
 *  --cafile <path> load PEM-encoded root certificate. If supplied, then server
 *                  authentication is required, else it is disabled
 *  --certs <path>  load certificate chain.
 *  --key <path>    load private key
 *  <host>          remote host to connect to
 *  <port>          remote port to connect to
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "wolfssl/ssl.h"

#define HELP                                                                   \
    "Usage: tlsclient [--debug] [--cafile <path>] [--certs <path>] [--key "    \
    "<path>] <host> <port>"

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
    int debug;
    char *cafile;
    char *certfile;
    char *keyfile;
    char *host;
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
    return 0;
}

int main(int argc, char *argv[]) {
    int err = 0;

    struct CliArgs args;
    CliArgs_init(&args);
    if (CliArgs_parse(&args, argc, argv) < 0) {
        fprintf(stderr, "%s\n", HELP);
        exit(EXIT_FAILURE);
    }
    CliArgs_debug(&args);

    wolfSSL_Init();

    return err;
}

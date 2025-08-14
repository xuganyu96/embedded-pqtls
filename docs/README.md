# Basic usage
## Compile the first program
Set up the server project, containing programs that run on MacOS and/or Ubuntu Linux:

```
server/
    src/
    config/
    include/
    CMakeLists.txt
```

`src/` contains `.c` source files. `config/` contains `user_settings.h`, a header file containing build-time configuration for WolfSSL. `include/` contains `.h` header files. We also need a `build/` directory to host the build artifacts specified in `CMakeLists.txt`.

Build a first program.
The source code will exist at `src/client.c`; we call it client because we will later fill it in as a TLS client.

```c
#include <stdio.h>

int main(void) {
  printf("你好，🌍!\n");
  return 0;
}
```

Fill in the boilerplate for `CMakeLists.txt`, then add the program as compilation target.

```cmake
cmake_minimum_required(VERSION 3.13)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    # -DCMAKE_BUILD_TYPE=<RelWithDebInfo|Debug>
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

project(server C CXX ASM)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/config
)

add_compile_options(-Wall -Wextra)

add_executable(tlsclient src/tlsclient.c)
```

Build for the first time:

```bash
# from server/
mkdir build
cd build
cmake .. && make
./tlsclient  # should print "Hello, world"
```

## Simple TLS client
### Build WolfSSL from source
Next we will write a simple TLS client in `tlsclient.c`.
First we need to pull in [WolfSSL](https://github.com/wolfssl/wolfssl).
We will clone a fork of it as a submodule so we can modify it and compile the library from source.

```bash
# from project root
git submodule add git@github.com:xuganyu96/wolfssl.git
```

Some helpful commands with git submodules:
- When cloning `git clone --recurse-submodules` will recursively clone submodules, including submodules within submodules; this will be helpful later when `pico-sdk` is a submodule that contains sub-modules like `lwip`
- `git submodule update --init --recursive` will initialize uninitialized sub-modules, then update them recursively

At the time of this write-up, WolfSSL's head is at commit `2db1669`.
However, it might be a good idea to also set up the original repository as a remote source so we can pull updates from the original repository, as well:

```bash
# From the wolfssl submodule
git remote add wolfssl https://github.com/wolfssl/wolfssl.git
git pull wolfssl master
```

We will configure WolfSSL using `config/user_settings.h`.
A [template](https://github.com/wolfSSL/wolfssl/tree/master/examples/configs) provided by WolfSSL serves as a good starting point:

```bash
# from server/
curl https://raw.githubusercontent.com/wolfSSL/wolfssl/refs/heads/master/examples/configs/user_settings_template.h > config/user_settings.h
```

> The template enables single-precision math by default, but my compiler `Apple clang 17.0.0` will not compile with this configuration, and I have to turn it off.

Then we need to add WolfSSL's source code to `CMakeLists.txt` and tell CMake how to generate compile commands:

```cmake
# Compile WolfSSL into a static library
set(WOLFSSL_ROOT "${CMAKE_CURRENT_LIST_DIR}/../wolfssl" CACHE PATH "Path to WolfSSL")
get_filename_component(WOLFSSL_ROOT "${WOLFSSL_ROOT}" ABSOLUTE)
if(NOT IS_DIRECTORY "${WOLFSSL_ROOT}")
    message(FATAL_ERROR "'${WOLFSSL_ROOT}' is not a valid directory.")
endif()
message(STATUS "Using wolfSSL from ${WOLFSSL_ROOT}")
include_directories(${WOLFSSL_ROOT})
file(GLOB WOLFSSL_SRC 
    "${WOLFSSL_ROOT}/src/*.c" 
    "${WOLFSSL_ROOT}/wolfcrypt/src/*.c"
)
add_library(wolfssl STATIC ${WOLFSSL_SRC})
target_compile_definitions(wolfssl PUBLIC WOLFSSL_USER_SETTINGS)
target_compile_options(wolfssl PRIVATE -Wno-deprecated-declarations)

# Compile tlsclient and link wolfssl against it
add_executable(tlsclient src/tlsclient.c)
target_link_libraries(tlsclient wolfssl)
```

Before we introduce any WolfSSL library components into `tlsclient.c`, build the project once just to make sure that WolfSSL can compile correctly.
This test build will also export compile commands under `build/compile_commands.json`, which the LSP needs to function correctly.

### Establish TCP connection
After a successful build, we will move on to establishing a TCP connection.
On a desktop environment, TCP functionalities will almost entirely be handled by the operating system.
We simply make the write API calls to the methods provided in standard library.

```c
#include <netdb.h>
#include <unistd.h>

/**
 * Establishes a TCP connection to a specified hostname and port.
 *
 * Creates a socket, resolves the hostname to an IP address,
 * and attempts to connect to the specified port on the resolved address.
 *
 * @param hostname The hostname to connect to (e.g., "example.com").
 * @param port The port number to connect to (e.g., 80 for HTTP).
 * @return int Returns the socket file descriptor on success, or -1 on failure.
 */
static int tcp_connect(const char *hostname, int port) {
    struct sockaddr_in server_addr; /* netinet/in.h */
    struct hostent *server;         /* netdb.h */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    server = gethostbyname(hostname);
    if (!server) {
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
        0) {
        close(sockfd); /* unistd.h */
        return -1;
    }
    return sockfd;
}
```

Test that we can connect to some TCP server:

```c
int conn = tcp_connect("www.github.com", 443);
if (conn <= 0) {
    printf("failed to connect\n");
    close(conn);
} else {
    printf("你好，GitHub!\n");
    close(conn);
}
```

### Make a TLS connection
When using WolfSSL to make a TLS connection, we first need to set up a runtime configuration using the struct `WOLFSSL_CTX`, which will specify how the connection will behave:
what protocol version (TLS 1.3 or 1.2?), what peer authentication policy (no auth or server auth), where to find certificate authority, and where to find private keys, etc.

From the context struct, we make a `ssl` struct, then bind the TCP socket to the struct.
From here, WolfSSL's code will take care of I/O operations with the socket, and we just need to call the "connect" method and handle the cleanup.
Here is a minimal example.

```c
int main(void) {
    wolfSSL_Init();

    int ssl_ret, sockfd;
    WOLFSSL *ssl;
    WOLFSSL_CTX *ctx;

    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method())) == NULL) {
        fprintf(stderr, "Failed to create WolfSSL context\n");
        exit(EXIT_FAILURE);
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "Failed to create SSL struct\n");
        wolfSSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    if ((sockfd = tcp_connect("api.github.com", 443)) < 0) {
        fprintf(stderr, "Failed to establish TCP connection\n");
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    wolfSSL_set_fd(ssl, sockfd);
    if ((ssl_ret = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
        close(sockfd);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    printf("Connected to github.com:443\n");
    wolfSSL_shutdown(ssl);
    close(sockfd);
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
    wolfSSL_Cleanup();

    return 0;
}
```

We can further verify that the TLS connection really works by sending an HTTPS request and reading its response:

```c
#define HTTP_REQUEST                                                           \
    "GET /octocat HTTP/1.1\r\n"                                                \
    "Host: api.github.com\r\n"                                                 \
    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) "     \
    "Gecko/20100101 Firefox/136.0\r\n"                                         \
    "Accept: application/json\r\n"                                             \
    "Connection: close\r\n\r\n"

int main(void) {
    /* connect to github.com:443 */
    wolfSSL_write(ssl, HTTP_REQUEST, strlen(HTTP_REQUEST));
    while ((readlen = wolfSSL_read(ssl, http_rx_buf + rx_buf_len,
                                   sizeof(http_rx_buf) - rx_buf_len)) > 0) {
        rx_buf_len += readlen;
    }
    http_rx_buf[rx_buf_len] = '\0';
    printf("%s\n", http_rx_buf);
    /* clean-up */
}
```

## Generate certificates and private keys
At a minimum, TLS 1.3 requires server authentication in all handshakes,
so before writing a TLS server, we first need to write a program for generating public-key certificates and private keys, which we will call `certgen`.

### Private key
For a first example, we will create a self-signed certificate (a chain of length 1) with some minimal information.
The program will output a `ecdsa256.key` file that contains an ECDSA (P-256) private key encoded under DER, 
and a `root.crt` file encoding an X.509 certificate UNDER PEM.
The certificate will contain the corresponding public key.

First we need to generate the ECDSA key pair.

```c
if ((err = wc_ecc_init(&key)) < 0) {
    fprintf(stderr, "Failed to init ECC key (err=%d)\n", err);
    exit(EXIT_FAILURE);
}
if ((err = wc_ecc_make_key(&rng, curve_size, &key)) < 0) {
    fprintf(stderr, "Failed to make ECC key (err=%d)\n", err);
    exit(EXIT_FAILURE);
}
if ((err = wc_ecc_check_key(&key)) < 0) {
    fprintf(stderr, "ECC key check failed (err=%d)\n", err);
    exit(EXIT_FAILURE);
}
if ((err = wc_EccKeyToDer(&key, der, sizeof(der))) <= 0) {
    fprintf(stderr, "Failed to DER-encode ECC key (err=%d)\n", err);
    exit(EXIT_FAILURE);
}
printf("ECC key DER size %d\n", err);

/* fopen a file and write it */
```

The output file `root.key` can be inspected using OpenSSL:

```bash
openssl asn1parse -inform DER -in root.key
```

### Certificate
The body of the certificate contains the identity of the subject/issuer, the subject's public key, and a slew of other information.
We begin with a `Cert` struct:

```c
#include "wolfssl/wolfcrypt/asn_public.h"

Cert cert;
wc_InitCert(&cert);
```

Identity information about the subject and the issuer is encoded using UTF-8 strings, which is filled in to the appropriate fields with `strncpy`:

```c
strncpy(cert.subject.country, "CA", CTC_NAME_SIZE);
strncpy(cert.subject.state, "ON", CTC_NAME_SIZE);
strncpy(cert.subject.locality, "Waterloo", CTC_NAME_SIZE);
strncpy(cert.subject.org, "University of Waterloo", CTC_NAME_SIZE);
strncpy(cert.subject.commonName, "*.uwaterloo.ca", CTC_NAME_SIZE);
```

Since we need to copy information for both subject and issuer, and later we will need to do this for four certificates (root CA, intermediate CA, server, client),
it helps to have a function that hides away the repetition:

```c
static void set_certname(CertName *id, const char *country, const char *state,
                         const char *locality, const char *org,
                         const char *common_name) {
    if (id == NULL) {
        return;
    }
    if (country != NULL) {
        strncpy(id->country, country, CTC_NAME_SIZE);
    }
    if (state != NULL) {
        strncpy(id->state, state, CTC_NAME_SIZE);
    }
    if (locality != NULL) {
        strncpy(id->locality, locality, CTC_NAME_SIZE);
    }
    if (org != NULL) {
        strncpy(id->org, org, CTC_NAME_SIZE);
    }
    if (common_name != NULL) {
        strncpy(id->commonName, common_name, CTC_NAME_SIZE);
    }
}
```

Another piece of non-cryptographic information we are interested in is the date range for which the certificate is valid.
One way to express such date range is with a pair of dates "not before" and "not after".
In X.509 certificates, dates are formatted according to the UTC time format `YYMMDDHHMMSSZ` (see [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)).
Here is how we work with date range:

```c
static void set_utctime(byte *dst, int *dst_sz, const char *datestr) {
    dst[0] = ASN_UTC_TIME;
    dst[1] = ASN_UTC_TIME_SIZE - 1;
    memcpy(dst + 2, datestr, strlen(datestr));
    *dst_sz = 2 + strlen(datestr);
}
set_utctime(cert.beforeDate, &cert.beforeDateSz, NOT_BEFORE_DATE);
set_utctime(cert.afterDate, &cert.afterDateSz, NOT_AFTER_DATE);
```

There are a few other relevant but optional attributes to play with, such as `cert.isCA`, which corresponds to a X.509v3 extension, but we will ignore them for now.

WolfCrypt's `MakeCert` and `SignCert` API's are used to serialize the certificate, then sign the certificate body.
We will convert the DER-encoded certificate to PEM format because `openssl s_client`'s `-CAfile` argument only accepts PEM format.

```c
int key_keytype = ECC_TYPE;
int key_sigtype = CTC_SHA256wECDSA;
if ((err = wc_MakeCert_ex(&cert, der, sizeof(der), key_keytype, &key,
                            &rng)) <= 0) {
    fprintf(stderr, "Failed to encode certificate body (err=%d)\n", err);
    exit(EXIT_FAILURE);
}
der_len = err;
if ((err = wc_SignCert_ex(cert.bodySz, key_sigtype, der, sizeof(der),
                            key_keytype, &key, &rng)) <= 0) {
    fprintf(stderr, "Failed to sign certificate (err=%d)\n", err);
    exit(EXIT_FAILURE);
}
der_len = err;
if ((err = wc_DerToPem(der, der_len, pem, sizeof(pem), CERT_TYPE)) <= 0) {
    fprintf(stderr, "Failed to convert DER to PEM (err=%d)\n", err);
    exit(EXIT_FAILURE);
}
pem_len = err;
```

We can output the certificate to the filesystem and inspect it with OpenSSL's `openssl x509 -noout -text -in root.crt` command, which should output something that looks like this:

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            55:c3:06:41:c7:d2:bd:cc:88:52:fe:91:20:ed:14:4d
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=CA, ST=ON, L=Waterloo, O=University of Waterloo, CN=*.eng.uwaterloo.ca
        Validity
            Not Before: Jan  1 00:00:00 2025 GMT
            Not After : Jan  1 00:00:00 2035 GMT
        Subject: C=CA, ST=ON, L=Waterloo, O=University of Waterloo, CN=*.eng.uwaterloo.ca
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:05:ca:d0:8b:1a:ab:28:4b:43:f1:12:d2:37:00:
                    f3:04:06:1b:0a:66:65:91:ed:92:c4:d9:ea:45:54:
                    0a:99:41:57:e0:48:14:37:8e:bf:ac:05:b9:21:ed:
                    1e:c6:dc:09:c0:52:c9:8c:81:52:73:42:c3:c8:e3:
                    48:f9:60:68:3d
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:TRUE
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:6c:aa:19:0a:10:fb:af:68:2f:6d:f7:b3:6e:de:
        d3:5c:11:c8:ab:ec:66:df:11:7e:75:05:20:de:db:55:38:03:
        02:20:34:64:ec:d5:ca:6c:03:61:2e:d4:51:87:35:e0:e7:4e:
        92:51:03:3f:33:97:8a:94:e6:d1:ec:29:5f:2c:b0:00
```

We can further check the validity of the certificate and the key using `openssl s_server` and `openssl s_client`:

```bash
openssl s_server -cert root.crt -key root.key -port 8000
openssl s_client -CAfile root.crt -verify_return_error -connect localhost:8000 < /dev/null
```

The client should report `Verify report code: 0 (ok)`.

### Certificate chain
Today on the real Internet we usually work with a chain of multiple certificates.
Each certificate is issued by a different person or institute, and with varying expiration date ranges, public keys, and signature types.
Certificate Authorities are institutes that can issue other certificates, and the leaf certificates are owned by individual domains, and are what was sent to the client during the TLS handshake.

The complete `certgen` program will generate the following certificate chain:

```
root   -->   intermediate   -->   server
  |
client
```

With `root` and `intermediate` being CAs and server/client being end entities.
When authenticating the server, client holds the root certificate, and server sends a chain that contains server and intermediate CA in this order.
When authenticating the client, server holds the root certificate, and client sends its own certificate.

## Implementing a server
The test server listens to a user-specified port and accepts TLS handshakes.
Users can specify certificate chain, private key, and certificate authority (for requesting client authentication) from the command line.
Upon a successful handshake, the server will echo client's data until client hangs up.

## Implementing a client
The test client connects to a user-specified remote host and initiate a TLS handshake.
Users can specify certificate authority, client certificate chain, client key, and key exchange group from the command line.
After the handshake, client should send some random bytes and verify that the data are correct.

# Implementing PQC with PQClean
[PQClean](https://github.com/PQClean/PQClean/) is a curated collection of post-quantum cryptography implementations.
We can use their ML-KEM and HQC impls for ephemeral key exchange and their ML-DSA/Falcon/SPHINCS+ impls for certificates.

## Compiling with PQClean
We recommend forking the original repository since we will make some modifications.

```bash
# From project root
git submodule add git@github.com:xuganyu96/PQClean.git
git remote add pqclean git@github.com:PQClean/PQClean.git
git pull pqclean master
```

PQClean comes with its own implementation of AES, SHA-2, SHA-3, and random number generator.
These implementations duplicate the functionalities of WolfCrypt and are actually slower.
The random number generator is going to be problematic because it depends on the presence of some operating system, whereas this project will later move to a bare metal platform.
My workaround is to substitute PQClean's implementation with WolfCrypt's `WC_RNG`.

```bash
# From PQClean/
git checkout -b wolfcrypt-integration
```

`WC_RNG` is stateful and cannot directly plug into the `int randombytes()` function.
Instead `PQClean/common/randombytes.c` will have a static pointer to a `WC_RNG` object,
which can be set to a user-specified instance using a public API, 
then the stateless `int randombytes()` can behave statelessly by hiding the `WC_RNG`.
Of course the user is responsible for making sure that `WC_RNG` is properly initialized and cleaned up afterwards, but that should not be a problem since we can piggyback off the RNG in `WOLFSSL` struct.

Need to add a `.clangd` at PQClean root so the language server can find WolfSSL.
Also define a macro so that WolfCrypt integration is only enabled if `USE_WC_RNG` is defined.

```yaml
# PQClean/.clang
CompileFlags:
  Add: [
    "-I/path/to/embedded-pqtls/wolfssl",
    "-DUSE_WC_RNG",
  ]
```

Modification to `randombytes.c`:

```c
#ifdef USE_WC_RNG
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

/* GYX: maybe not the best way to approach this:
 * if USE_WC_RNG, then turn off all other entropy sources
 */
#undef _WIN32
#undef __wasi__
#undef __linux__
#undef BSD
#undef __APPLE__
#undef __MACH__
#undef __EMSCRIPTEN__

static WC_RNG *_wc_rng = NULL;

/* Set the internal WC_RNG pointer to the input pointer
 *
 * Return 0 on success.
 * Return BAD_FUNC_ARG if input pointer is NULL
 */
int set_wc_rng(WC_RNG *rng) {
    if (rng == NULL) {
        return BAD_FUNC_ARG;
    }
    _wc_rng = rng;
    return 0;
}
// TODO: maybe also do a free_wc_rng, which set _wc_rng to NULL?
#endif

int randombytes(uint8_t *output, size_t n) {
    #if defined(USE_WC_RNG)
    (void) buf;
    if (_wc_rng == NULL) {
        return BAD_FUNC_ARG;
    }
    return wc_RNG_GenerateBlock(_wc_rng, output, n);
    #endif
}
```

Add PQClean's source code and headers to `server/CMakeLists.txt`, 
first define PQClean's root directory.
Need to add `PQClean/common` to `include_directories` so implementations can find `randombytes`.
Need to add `PQClean` to `include_directories` so we can find the individual `api.h` files.

```cmake
set(PQCLEAN_ROOT "${CMAKE_CURRENT_LIST_DIR}/../PQClean" CACHE PATH "Path to PQClean")
get_filename_component(PQCLEAN_ROOT ${PQCLEAN_ROOT} ABSOLUTE)
if(NOT IS_DIRECTORY ${PQCLEAN_ROOT}) 
    message(FATAL_ERROR "'${PQCLEAN_ROOT}' is not a valid directory")
endif()
message(STATUS "Using PQClean from ${PQCLEAN_ROOT}")
include_directories(
    ${PQCLEAN_ROOT}/common
    ${PQCLEAN_ROOT}
)
file(GLOB PQCLEAN_SRC
    "${PQCLEAN_ROOT}/common/*.c"
    "${PQCLEAN_ROOT}/crypto_kem/ml-kem-512/clean/*.c"
)
```

Add PQClean to the `libwolfssl.a` target, remember to define `USE_WC_RNG`:

```cmake
add_library(wolfssl STATIC ${WOLFSSL_SRC} ${PQCLEAN_SRC})
target_compile_options(wolfssl PRIVATE -Wno-deprecated-declarations -DUSE_WC_RNG)
```

We can write a quick test program:

```c
#include "crypto_kem/ml-kem-512/clean/api.h"

int main(void) {
    uint8_t pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES],
        sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES],
        ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES],
        ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES],
        sscmp[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(sscmp, ct, sk);
    if (memcmp(ss, sscmp, sizeof(sscmp)) == 0) {
        printf("ML-KEM-512 Ok.\n");
    }
    return 0;
}
```

Before we modify WolfSSL, need to add PQClean to the include directories:

```c
CompileFlags:
    Add: [
        "-DWOLFSSL_USER_SETTINGS",
        "-I/path/to/embedded-pqtls/wolfssl",
        "-I/path/to/embedded-pqtls/server/config",
        "-I/path/to/embedded-pqtls/pqclean",
        "-DUSE_WC_RNG",
    ]
```

## Adding HQC for ephemeral key exchange
### Adding named group variant to the enumerated type
HQC was [selected by NIST](https://www.nist.gov/publications/status-report-fourth-round-nist-post-quantum-cryptography-standardization-process) as an alternative KEM to ML-KEM.

The entrypoint would be `wolfSSL_CTX_set_groups`.
The enum variants are located in `internal.h`, though the type does not have a name.
Find the type definition by looking up the definition of something like `WOLFSSL_ECC_X25519`.

```c
int groups[] = {WOLFSSL_HQC_128, WOLFSSL_HQC_192, WOLFSSL_HQC_256}
wolfSSL_CTX_set_groups(ctx, groups, 3);
```

`wolfSSL_CTX_set_groups` calls `wolfSSL_CTX_UseSupportedCurve` to check if the named group is valid.
`wolfSSL_CTX_UseSupportedCurve` calls `isValidCurveGroup` and `TLSX_UseSupportedCurve`.
`TLSX_UseSupportedCurve` calls `TLSX_IsGroupSupported`.
`isValidCurveGroup` and `TLSX_IsGroupSupported` need to be modified so the added named group variants are recognized.
The group is assigned to `ctx->group[i]`.
The function `InitSSL` copies `ctx->group` to `ssl->group`.
`InitSSL` is called by `wolfSSL_new`.

```c
if (ctx->numGroups > 0) {
    XMEMCPY(ssl->group, ctx->group, sizeof(*ctx->group) * ctx->numGroups);
    ssl->numGroups = ctx->numGroups;
}
```

After modifying `isValidCurveGroup` and `TLSX_IsGroupSupported`, `wolfSSL_CTX_set_groups` returns success.
Client can construct `ClientHello` and send to server, but server complains that `ClientHello` is missing the `key_share` extension and sends back an alert instead of `ServerHello`.
Client fails upon receiving server's alert.

Client might omit the `key_share` extension because of the following snippet in `tls.c`:

```c
extension = TLSX_Find(ssl->extensions, TLSX_KEY_SHARE);
if (extension == NULL) {
    if (ssl->numGroups > 0) {
        int set = 0;
        int i, j;

        /* try to find the highest element in ssl->group[]
            * that is contained in preferredGroup[].
            */
        namedGroup = preferredGroup[0];
        for (i = 0; i < ssl->numGroups && !set; i++) {
            for (j = 0; preferredGroup[j] != WOLFSSL_NAMED_GROUP_INVALID; j++) {
                if (preferredGroup[j] == ssl->group[i]
                    && TLSX_IsGroupSupported(preferredGroup[j])) {
                    namedGroup = ssl->group[i];
                    set = 1;
                    break;
                }
            }
        }
        if (!set)
            namedGroup = WOLFSSL_NAMED_GROUP_INVALID;
    }
    else {
        /* Choose the most preferred group. */
        namedGroup = preferredGroup[0];
        if (!TLSX_IsGroupSupported(namedGroup)) {
            int i = 1;
            for (;preferredGroup[i] != WOLFSSL_NAMED_GROUP_INVALID;
                    i++) {
                if (TLSX_IsGroupSupported(preferredGroup[i]))
                    break;
            }
            namedGroup = preferredGroup[i];
        }
    }
}
else {
    KeyShareEntry* kse = (KeyShareEntry*)extension->data;
    if (kse)
        namedGroup = kse->group;
}
if (namedGroup != WOLFSSL_NAMED_GROUP_INVALID) {
    ret = TLSX_KeyShare_Use(ssl, namedGroup, 0, NULL, NULL,
            &ssl->extensions);
    if (ret != 0)
        return ret;
}
```

There is a static list of `int preferredGroup[]` at the top of `tls.c`.
When populating the extensions in `ClientHello`, 
if the `key_share` extension is not already populated,
then `ssl->group` is compared with `preferredGroup`.
If the two lists do not agree, then client will not call `TLSX_KeyShare_Use` to populate the `key_share` extension.
I guess this is so server will could send back its preferred list of named group in `HelloRetryRequest`.

After adding the HQC variants to `preferredGroup`, 
client fails at constructing `ClientHello` because `TLSX_KeyShare_GenKey` does not know how to handle `WOLFSSL_HQC_128/192/256`.

### Generate HQC keypair in ClientHello
When using a KEM for TLS ephemeral key exchange, 
the `key_share` extension in `ClientHello` contains the public key of a freshly generated keypair.
Need to modify `NamedGroupIsPqc` so `WOLFSSL_HQC_XXX` is identified as PQC KEM.
Then modify `TLSX_KeyShare_GenPqcKeyClient`.
At [65e7f2](https://github.com/wolfSSL/wolfssl/tree/65e7f2c40f51e4cb7c9594873c0afd1e38c85912),
`TLSX_KeyShare_GenPqcKeyClient` assumes that the only PQC KEM is ML-KEM and/or Kyber,
so the first modification is to add a layer of abstraction and make `GenPqcKeyClient` call `GenMlKemKeyClient` if `kse->group` represents ML-KEM/Kyber and `GenHqcKeyClient` if `kse->group` represents HQC.

Need to implement `TLSX_KeyShare_GenHqcKeyClient`, but first look at `GenMlKemKeyClient`:

```c
static int TLSX_KeyShare_GenMlKemKeyClient(WOLFSSL *ssl, KeyShareEntry *kse) {
    WOLFSSL_ENTER("TLSX_KeyShare_GenMlKemKeyClient");
    int ret = 0;
    int type = 0;
    KyberKey kem[1];
    if (kse->pubKey != NULL) {
        return ret;
    }

    ret = mlkem_id2type(kse->group, &type);
    if (ret == WC_NO_ERR_TRACE(NOT_COMPILED_IN)) {
        WOLFSSL_MSG("Invalid Kyber algorithm specified.");
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = wc_KyberKey_Init(type, kem, ssl->heap, ssl->devId);
        if (ret != 0) {
            WOLFSSL_MSG("Failed to initialize Kyber Key.");
        }
    }

    if (ret == 0) {
        ret = wc_KyberKey_PrivateKeySize(kem, &privSz);
    }
    if (ret == 0) {
        ret = wc_KyberKey_PublicKeySize(kem, &kse->pubKeyLen);
    }

    if (ret == 0) {
        privKey = (byte*)XMALLOC(privSz, ssl->heap, DYNAMIC_TYPE_PRIVATE_KEY);
        if (privKey == NULL) {
            WOLFSSL_MSG("privkey memory allocation failure");
            ret = MEMORY_ERROR;
        }
    }

    if (ret == 0) {
        kse->pubKey = (byte*)XMALLOC(kse->pubKeyLen, ssl->heap,
                                     DYNAMIC_TYPE_PUBLIC_KEY);
        if (kse->pubKey == NULL) {
            WOLFSSL_MSG("pubkey memory allocation failure");
            ret = MEMORY_ERROR;
        }
    }

    if (ret == 0) {
        ret = wc_KyberKey_MakeKey(kem, ssl->rng);
        if (ret != 0) {
            WOLFSSL_MSG("Kyber keygen failure");
        }
    }
    if (ret == 0) {
        ret = wc_KyberKey_EncodePublicKey(kem, kse->pubKey,
                                          kse->pubKeyLen);
    }

    if (ret == 0) {
        ret = wc_KyberKey_EncodePrivateKey(kem, privKey, privSz);
    }

    if (ret != 0) {
        wc_KyberKey_Free(kem);
        XFREE(kse->pubKey, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        kse->pubKey = NULL;
        if (privKey) {
            ForceZero(privKey, privSz);
            XFREE(privKey, ssl->heap, DYNAMIC_TYPE_PRIVATE_KEY);
            privKey = NULL;
        }
    } else {
        wc_KyberKey_Free(kem);
        kse->privKey = (byte*)privKey;
        kse->privKeyLen = privSz;
    }

    return ret;
}
```

- key struct `KyberKey` is allocated on the stack and needs to be cleaned-up (i.e. zero'd out) at before the function exits
- `kse->privKey` and `kse->pubKey` are allocated on the heap; if anything goes wrong, they need to be freed, and `kse->privKey` needs to be additionally zero'd out
- `EncodePublicKey` and `EncodePrivateKey` act more like "export", compared to `PublicKeyToDer` and `PrivateKeyToDer`, which encode bytes using ASN.1 and DER.

WolfSSL used a clever trick to abstract over the difference between stack-allocated and heap-allocated key struct:

```c
#ifdef WOLFSSL_SMALL_STACK
    KyberKey *key;
    /* Allocate from heap */
#else
    KyberKey key[1];
#endif
/* In either case, key behaves like a pointer to a KyberKey struct */
```

Maybe the "array as pointer" trick is unnecessary:

```c
#ifdef WOLFSSL_SMALL_STACK
    KyberKey *key;
#else
    KyberKey _key;
    KbyerKey *key = &_key;
#endif
```

Also, something I initially did not understand is why we need a `wc_MlKemKey_Free` if we are going to `XFREE` the pointer anyways.
Now I think `wc_MlKemKey_Free` is for cleaning up, and for **when the key struct itself has heap-allocated pointers**, which did not happen with `KyberKey`/`MlKemKey`, so it seems redundant.

Here is my implementation:

```c
static int TLSX_KeyShare_GenHqcKeyClient(WOLFSSL *ssl, KeyShareEntry *kse) {
    WOLFSSL_ENTER("TLSX_KeyShare_GenHqcKeyClient");
    int ret = 0;

    HqcKey key;
    int level;

    if ((ret = wc_HqcKey_GetLevelFromNamedGroup(kse->group, &level)) < 0) {
        WOLFSSL_MSG_EX("Invalid named group %d", kse->group);
        goto cleanup;
    }
    if ((ret = wc_HqcKey_Init(&key)) < 0) {
        WOLFSSL_MSG_EX("Failed to initialize HQC key (err=%d)", ret);
        goto cleanup;
    }
    if ((ret = wc_HqcKey_SetLevel(&key, level)) < 0) {
        WOLFSSL_MSG_EX("Failed to set HQC level to %d (err=%d)", level, ret);
        goto cleanup;
    }
    if ((ret = wc_HqcKey_PrivateKeySize(&key, &kse->privKeyLen)) < 0) {
        WOLFSSL_MSG_EX("Failed to get private key size (err=%d)", ret);
        goto cleanup;
    }
    if ((kse->privKey = XMALLOC(kse->privKeyLen, ssl->heap,
                                DYNAMIC_TYPE_PRIVATE_KEY)) == NULL) {
        WOLFSSL_MSG_EX("Failed to allocate %d bytes kse->privKey",
                       kse->privKeyLen);
        ret = MEMORY_ERROR;
        goto cleanup;
    }
    if ((ret = wc_HqcKey_PublicKeySize(&key, &kse->pubKeyLen)) < 0) {
        WOLFSSL_MSG_EX("Failed to get public key size (err=%d)", ret);
        goto cleanup;
    }
    if ((kse->pubKey = XMALLOC(kse->pubKeyLen, ssl->heap,
                               DYNAMIC_TYPE_PUBLIC_KEY)) == NULL) {
        WOLFSSL_MSG_EX("Failed to allocate %d bytes kse->pubKey",
                       kse->pubKeyLen);
        ret = MEMORY_ERROR;
        goto cleanup;
    }
    if ((ret = wc_HqcKey_MakeKey(&key, ssl->rng)) < 0) {
        WOLFSSL_MSG_EX("Failed to generate HQC key (err=%d)", ret);
        goto cleanup;
    }
    if ((ret = wc_HqcKey_ExportPublicKey(&key, kse->pubKey,
                                         kse->pubKeyLen)) < 0) {
        WOLFSSL_MSG_EX("Failed to export HQC public key (err=%d)", ret);
        goto cleanup;
    }
    if ((ret = wc_HqcKey_ExportPrivateKey(&key, kse->privKey,
                                          kse->privKeyLen)) < 0) {
        WOLFSSL_MSG_EX("Failed to export HQC private key (err=%d)", ret);
        goto cleanup;
    }

cleanup:
    wc_HqcKey_Free(&key);
    if (ret != 0) {
        if (kse->pubKey) {
            XFREE(kse->pubKey, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
            kse->pubKey = NULL;
        }
        if (kse->privKey) {
            ForceZero(kse->privKey, kse->privKeyLen);
            XFREE(kse->privKey, ssl->heap, DYNAMIC_TYPE_PRIVATE_KEY);
            kse->privKey = NULL;
        }
    }

    WOLFSSL_LEAVE("TLSX_KeyShare_GenHqcKeyClient", ret);
    return ret;
}
```

This impl makes reference to APIs that need to be implemented in `hqc.h` and `hqc.c`:

```c
typedef struct HqcKey {
} HqcKey;

int wc_HqcKey_Init(HqcKey *key);
int wc_HqcKey_Free(HqcKey *key);
int wc_HqcKey_SetLevel(HqcKey *key, int level);
int wc_HqcKey_GetLevel(HqcKey *key, int *level);
int wc_HqcKey_PublicKeySize(HqcKey *key, word32 *len);
int wc_HqcKey_PrivateKeySize(HqcKey *key, word32 *len);
int wc_HqcKey_CiphertextSize(HqcKey *key, word32 *len);
int wc_HqcKey_SharedSecretSize(HqcKey *key, word32 *len);
int wc_HqcKey_MakeKey(HqcKey *key, WC_RNG *rng);
int wc_HqcKey_ExportPublicKey(HqcKey *key, byte *buf, word32 len);
int wc_HqcKey_ExportPrivateKey(HqcKey *key, byte *buf, word32 len);
int wc_HqcKey_GetLevelFromNamedGroup(word16 namedgroup, int *level);
```

`GetLevelFromNamedGroup` was removed because it requires a WolfCrypt module to know values found in the WolfSSL module.
Other APIs are relatively easy to implement.
`PQCLEAN_SRC` in the CMake list file in the `server` project needs to include the source files under `crypto_kem/hqc-xxx/clean/*.c`
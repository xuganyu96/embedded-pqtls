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

For a first example, we will create a self-signed certificate (a chain of length 1) with some minimal information.
We begin with generating an ECDSA keypair using the NIST curve P-256.
WolfCrypt also supports RSA, Ed25519, and Ed448.

```c
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"

int err;
ecc_key root_key;
enum ecc_curve_ids curve_id = ECC_SECP256R1;
WC_RNG rng;
wc_InitRng(&rng);

if ((err = wc_ecc_init(&root_key)) < 0) {
    fprintf(stderr, "Failed to init ECC key (%d)\n", err);
    return -1;
}
if ((err = wc_ecc_make_key(&rng, wc_ecc_get_curve_size_from_id(curve_id),
                            &root_key)) < 0) {
    fprintf(stderr, "Failed to make ECC key (%d)\n", err);
    return -1;
}
if ((err = wc_ecc_check_key(&root_key)) < 0) {
    fprintf(stderr, "ECC key check failed (%d)\n", err);
    return -1;
}
```

WolfCrypt includes an ASN.1 module (`asn_public.h`) with which one can build a certificate.
The core data structure is the `Cert` struct, and the workflow goes:
1. Fill in the identity section of the certificate
1. Call `wc_MakeCert` with the keypair, which will DER serialize the unsigned certificate, including identity and public key, to a buffer
1. Call `wc_SignCert` with the DER buffer to produce the signed DER buffer

Note that `WOLFSSL_CERT_GEN` must be defined in `user_settings.h`, or functions like `wc_MakeCert` will not be compiled.

```c
Cert cert;
uint8_t der[512], pem[512];
int der_sz, pem_sz;

wc_InitCert(&cert);
cert.sigType = key_sigtype;
cert.isCA = 1;
// TODO: fill in subject, issuer, dates
if ((der_sz = wc_MakeCert_ex(&cert, der, sizeof(der), key_type, &key,
                                &rng)) <= 0) {
    fprintf(stderr, "Failed to make cert (%d)\n", der_sz);
    exit(-1);
}
if ((der_sz = wc_SignCert_ex(cert.bodySz, cert.sigType, der, sizeof(der),
                                key_type, &key, &rng)) < 0) {
    fprintf(stderr, "Failed to sign cert (%d)\n", der_sz);
    exit(-1);
}

/* Convert to PEM and write to file */
if ((pem_sz = wc_DerToPem(der, der_sz, pem, sizeof(pem), CERT_TYPE)) <= 0) {
    fprintf(stderr, "Failed to make PEM (%d)\n", pem_sz);
    exit(-1);
}
pem[pem_sz] = '\0';
```

You can then print `pem` with `printf("%s\n", pem)`, pipe the output to a file, and inspect the content using `openssl x509`:

```bash
# from project_root/server/
cd build && cmake .. && make
./certgen > root.crt
openssl x509 -text -noout -in root.crt
```

Since we used ECDSA with P-256, the public key and signature algorithm fields of OpenSSL's output should show the appropriate value:

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            0d:6b:63:0c:9a:a1:83:cd:d2:85:ed:0e:7b:2d:5b:13
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: 
        Validity
            Not Before: Jul 25 00:29:16 2025 GMT
            Not After : Dec  8 00:29:16 2026 GMT
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:5d:c4:64:42:4a:ba:81:1a:68:24:36:d7:82:fa:
                    b4:a4:11:73:ff:ab:29:72:d1:c5:15:b8:e3:fb:9c:
                    2e:f7:50:fb:4d:c4:71:53:f4:15:f8:41:7d:dc:0a:
                    0c:86:6f:6c:7e:e8:f9:60:55:d6:f9:fb:13:01:fd:
                    d1:ce:da:09:c1
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:TRUE
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:d2:37:93:64:6c:be:8e:68:21:34:ac:35:fa:
        b3:d5:6e:2c:3a:fe:cc:0b:9f:00:eb:0c:1f:39:7d:cd:fa:44:
        b9:02:21:00:cb:a7:f8:8b:30:0f:9d:e1:10:69:84:83:de:63:
        97:be:d4:2e:48:94:7b:04:d5:d5:b9:eb:36:12:0c:36:ce:db
```
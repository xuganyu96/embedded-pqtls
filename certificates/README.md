# Post-quantum certificates

## Server and client with classic handshake
The `certgen-openssl.sh` script will generate a set of certificates and keys using classic cryptographic primitives (ed25519 if it is available and 2048-bit RSA as a fallback):
- `root.crt` and `root.key` belong to the root certificate authority: self-signed and with `X509v3 basic constraint CA: TRUE`
- `int.crt` and `int.key` are intermediate certificate authority: it is signed by the root CA but is itself also a CA
- `leaf.crt` and `leaf.key` describe the server certificate, signed by the intermediate CA but are not CA itself
- `client.crt` and `client.key` are for client authentication, signed by the root CA
- `server-chain.crt` concatenates `leaf.crt`, `int.crt`, and `root.crt`. `client-chain.crt` concatenates `client.crt` and `root.crt`.

Certificates can be inspected using OpenSSL, or with the `asn1` program

```bash
openssl x509 -text -noout -in <file>
./asn1 --pem --indent --no-dump-text --branch certs/root.key
```

OpenSSL also comes with basic TLS server/client, though they do no support certificate chain:

```bash
# TODO: right now this won't work fully, because the certgen-openssl script generates root
#   certificate to not be used for server authentication, while s_server does not seem to support
#   certificate chain
openssl s_server -cert classic-certs/root.crt -key classic-certs/root.key -port 8000
# "< /dev/null" will feed an EOF that terminates the connection after the handshake
openssl s_client -CAfile classic-certs/root.crt -verify_return_error -connect localhost:8000 < /dev/null
```

The `tls13server` and `tls13client` programs can also be used to test:

```bash
./tls13server --certs classic-certs/server-chain.crt --key classic-certs/leaf.key --cafile classic-certs/root.crt 8000
./tls13client --cafile classic-certs/root.crt --certs classic-certs/client-chain.crt --key classic-certs/client.key 127.0.0.1 8000
```

## Compile WolfSSL from source
Instead of using `autogen`, `configure`, and `make` to install WolfSSL into system path, use `user_settings.h` to control the compilation options, then compile WolfSSL into a static library.

```cmake
# Compile WolfSSL into static library
# Instead of using autogen and configure, use header file `user_settings.h`
set(WOLFSSL_ROOT "" CACHE PATH "Path to WolfSSL installation")
if(NOT WOLFSSL_ROOT)
    message(FATAL_ERROR "WOLFSSL_ROOT not set. Please specify -DWOLFSSL_ROOT=/path/to/wolfssl")
endif()
include_directories(${WOLFSSL_ROOT})
file(GLOB WOLFSSL_SRC "${WOLFSSL_ROOT}/src/*.c" "${WOLFSSL_ROOT}/wolfcrypt/src/*.c")
add_library(wolfssl STATIC ${WOLFSSL_SRC})
target_compile_definitions(wolfssl PUBLIC WOLFSSL_USER_SETTINGS)
target_compile_options(wolfssl PRIVATE -Wno-deprecated-declarations)
```

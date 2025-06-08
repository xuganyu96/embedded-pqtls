# Thesis write-up
A peer's Master's thesis has 50 pages of main content. For a first draft I want to have at least 60 pages of stuff, then trim down as needed.

- Post-quntum TLS in embedded systems
    - What is TLS, main features, overview of the handshake protocols
    - TLS in embedded/constrained systems
    - (post-quantum) cryptography in embedded systems
- Improvement: use IND-1CCA KEM for ephemeral key exchange
- Improvement: use KEMTLS
- Improvement: embed trusted public key (i.e. `cache_info`)
- Implementation and results
- Conclusion and future works

## Implementation
In Thom Wiggers' thesis, *"Implementing and measuring post-quantum TLS in Rust"* is a section that spans 15 pages! I should document my implementation, as well.

# Implementation with [WolfSSL@7898823](https://github.com/wolfssl/wolfssl/tree/7898823)
[WolfSSL](https://github.com/wolfSSL/wolfssl) is a small, fast, and portable implementation of TLS/SSL for embedded devices. It optimizes for code size and memory footprint. WolfSSL also has its own cryptography library called WolfCrypt, which provides symemtric and asymmetric cryptographic primitives used throughout the TLS implementation.

## Compiling WolfSSL
The repository starts out being empty with a single README file:

```
root
- README.md
```

We will start with forking WolfSSL, which we will then add to our repository as a submodule.
As of the day of writing this document, I am using [WolfSSL@7898823](https://github.com/wolfssl/wolfssl/tree/7898823).

```bash
git submodule add git@github.com:xuganyu96/wolfssl.git
```

On a desktop environment, WolfSSL recommends building (and installing) the library using `autoconf`. However, I took a different approach and compiled using CMake. This is because `autoconf` will generate a header file at `wolfssl/config.h`, which will hardcode build flags that interfere with other projects that depend on the same codebase. This is important because later we will also compile Pico's firmware against the same codebase, and Pico will definitely configure the build flags different from desktop.

The desktop project will be organized as follows:

```
project root/
- README
- wolfssl/
  - ....
- server/
    - CMakeLists.txt
    - config/ 
      - user_settings.h
    - src/
      source files
    - include/
      header files
    - build/
      build artifacts, to be ignored by git
```

Let's compile something against WolfSSL to verify that the toolchain is set up correctly. 
First we need a `user_settings.h` file: WolfSSL provides a good [template](https://github.com/wolfSSL/wolfssl/blob/master/examples/configs/user_settings_template.h) to start with. 
Second, we need a list file, so here is one to get started with:

```cmake
cmake_minimum_required(VERSION 3.13)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# set to RelWithDebInfo in optimized build
set(CMAKE_BUILD_TYPE Debug)

project(server C CXX ASM)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/config
)

# Compile WolfSSL into a static library
set(WOLFSSL_ROOT "${CMAKE_CURRENT_LIST_DIR}/../wolfssl" CACHE PATH "Path to WolfSSL installation")
get_filename_component(WOLFSSL_ROOT "${WOLFSSL_ROOT}" ABSOLUTE)
if(NOT IS_DIRECTORY "${WOLFSSL_ROOT}")
    message(FATAL_ERROR "WOLFSSL_ROOT is set to '${WOLFSSL_ROOT}', but this is not a valid directory.")
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

# Global compilation flags
add_compile_options(-Wall -Wextra)

# Compiling individual binaries
add_executable(certgen src/certgen.c)
target_link_libraries(certgen wolfssl)
```

Finally, add `src/certgen.c` as specified in `CMakeLists.txt`.
Eventually this will compile into a progrm that generates X509 certificate chains, but for now it's just an empty program that immediately exits.

```c
/* src/certgen.c */
int main(void) {
    return 0;
}
```

Now we are ready to build:

```bash
# from root/server
mkdir build
cd build
cmake ..
make
./certgen
```

## Generate certificate chain
A certificate contains three main components: identity, some public key, and a digital signature over the identity and the public key to bind these two components together. 
A certificate chain contains multiple certificates where the signature on one certificate is to be verified by the public key in another certificate, up to the root, where we typically have a self-signed certificate.
In this project we will emulate a 3-certificate chain setup typically found on the Internet: server's identity (e.g. www.github.com) is bound to the leaf key in the leaf certificate, which is signed by an intermediate certificate authority (CA), which is then signed by a root CA.
I also want to experiment with the uncommon use case of client authentication, so a fourth certificate will be directly signed by the root CA.
Last but not least I need to retain the corresponding private keys.

```
root  ---signs--->  intermediate ---signs---> leaf
  |
  |-- signs ---> client
```

There are many ways to accomplish this, including using OpenSSL and Python's `asn1` package. 
To reduce dependencies and to later better accommodate non-standard certificate chain (i.e. KEM certificates), I will use WolfSSL. 
Here is sample code for generating a self-signed certificate

```c
/* need to enable the following in user_settings.h
 * #define WOLFSSL_SHA3
 * #define WOLFSSL_SHAKE128
 * #define WOLFSSL_SHAKE256
 * #define HAVE_DILITHIUM
 * #define WOLFSSL_WC_DILITHIUM
 * #define WOLFSSL_CERT_GEN
 * also set "Wolf Single Precision Math" to 0
 */
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/dilithium.h>

#define LEAF_COUNTRY "CA"
#define LEAF_STATE "ON"
#define LEAF_LOCALITY "Waterloo"
#define LEAF_ORG "Communication Security Lab"
#define LEAF_COMMONNAME "*.eng.uwaterloo.ca"
#define ROOT_COUNTRY LEAF_COUNTRY
#define ROOT_STATE LEAF_STATE
#define ROOT_LOCALITY LEAF_LOCALITY
#define ROOT_ORG LEAF_ORG
#define ROOT_COMMONNAME "*.eng.uwaterloo.ca"
#define NOT_BEFORE_DATE "250101000000Z"
#define NOT_AFTER_DATE "350101000000Z"
#define DER_MAX_SIZE 1000000

static void set_certname(CertName *cert_name, const char *country,
                         const char *state, const char *locality,
                         const char *org, const char *common_name) {
    strncpy(cert_name->country, country, CTC_NAME_SIZE);
    strncpy(cert_name->state, state, CTC_NAME_SIZE);
    strncpy(cert_name->locality, locality, CTC_NAME_SIZE);
    strncpy(cert_name->org, org, CTC_NAME_SIZE);
    strncpy(cert_name->commonName, common_name, CTC_NAME_SIZE);
}

// https://obj-sys.com/asn1tutorial/node15.html
// datestr must follow the UTCTime formatting
static void set_before_date_utctime(Cert *cert, const char *datestr) {
    cert->beforeDate[0] = ASN_UTC_TIME;
    cert->beforeDate[1] = ASN_UTC_TIME_SIZE - 1;
    memcpy(cert->beforeDate + 2, datestr, strlen(datestr));
    cert->beforeDateSz = 2 + strlen(datestr);
}

// https://obj-sys.com/asn1tutorial/node15.html
// datestr must follow the UTCTime formatting
static void set_after_date_utctime(Cert *cert, const char *datestr) {
    cert->afterDate[0] = ASN_UTC_TIME;
    cert->afterDate[1] = ASN_UTC_TIME_SIZE - 1;
    memcpy(cert->afterDate + 2, datestr, strlen(datestr));
    cert->afterDateSz = 2 + strlen(datestr);
}

/* Generate a self-signed certificate. Write the certificate and the private key
 * in PEM format to the input buffers.
 *
 * On input, *cert_len and *key_len encode the capacity of the buffers; on
 * output, they contain the actual length of data.
 *
 * Return 0 on success.
 */
int certgen(uint8_t *cert_pem, size_t *cert_len, uint8_t *key_pem,
            size_t *key_len, WC_RNG *rng) {
    int ret = 0;
    int level = WC_ML_DSA_44;
    uint8_t der[DER_MAX_SIZE];
    enum Ctc_SigType sig_type = CTC_ML_DSA_LEVEL2;
    enum CertType key_type = ML_DSA_LEVEL2_TYPE;

    /* Generate keypair */
    dilithium_key key;
    if ((ret = wc_dilithium_init(&key)) < 0)
        return ret;
    if ((ret = wc_dilithium_set_level(&key, level)) < 0)
        return ret;
    if ((ret = wc_dilithium_make_key(&key, rng)) < 0)
        return ret;
    if ((ret = wc_Dilithium_PrivateKeyToDer(&key, der, sizeof(der))) < 0)
        return ret;
    if ((ret = wc_DerToPem(der, ret, key_pem, *key_len,
                           PKCS8_PRIVATEKEY_TYPE)) < 0)
        return ret;
    *key_len = ret;

    /* Generate certificate */
    Cert cert;
    if ((ret = wc_InitCert(&cert)) < 0)
        return ret;
    cert.sigType = sig_type;
    cert.isCA = 1;
    set_certname(&cert.subject, ROOT_COUNTRY, ROOT_STATE, ROOT_LOCALITY,
                 ROOT_ORG, ROOT_COMMONNAME);
    set_certname(&cert.issuer, ROOT_COUNTRY, ROOT_STATE, ROOT_LOCALITY,
                 ROOT_ORG, ROOT_COMMONNAME);
    set_before_date_utctime(&cert, NOT_BEFORE_DATE);
    set_after_date_utctime(&cert, NOT_AFTER_DATE);
    ret = wc_MakeCert_ex(&cert, der, sizeof(der), key_type, &key, rng);
    if ((ret = wc_SignCert_ex(cert.bodySz, cert.sigType, der, sizeof(der),
                              key_type, &key, rng)) < 0)
        return ret;

    if ((ret = wc_DerToPem(der, ret, cert_pem, *cert_len, CERT_TYPE)) < 0)
        return ret;
    *cert_len = ret;

    return 0;
}

int main(void) {
    int ret = 0;
    WC_RNG rng;
    wc_InitRng(&rng);
    uint8_t cert_pem[DER_MAX_SIZE], key_pem[DER_MAX_SIZE];
    size_t cert_len = sizeof(cert_pem), key_len = sizeof(key_pem);
    ret = certgen(cert_pem, &cert_len, key_pem, &key_len, &rng);
    if (ret == 0) {
        printf("Cert PEM %zu, key PEM %zu\n", cert_len, key_len);
    }
    return ret;
}
```

This can then be expanded to a full program to generate the entire chain.
See `src/certgen.c` in the source code for details.
You can use the [example asn1 program](https://github.com/wolfSSL/wolfssl/blob/master/examples/asn1/asn1.c) to inspect certificates and private keys. `openssl x509 -text -noout -in <certificate>` can also be used to inspect certificates (but not private keys).
We will talk more about ASN1, DER, and how WolfSSL works with them in later section.
Finally, with a full set of certificate chain and key, you can test a complete TLS handshake using the example client and server [here](https://github.com/wolfSSL/wolfssl/tree/master/examples/).

## Integration with PQClean
WolfSSL comes with full support for ML-KEM and ML-DSA, and although it has the scaffolding for SPHINCS and Falcon, the implementation relies on `liboqs`. I've decided for no particular reason to NOT use `liboqs`; instead I will use `PQClean`. Similar to WolfSSL, I will compile PQClean into a static library, then use the public API to modify WolfSSL.

PQClean (and for that matter `liboqs`) comes with its own implementation of `randombytes` and Keccak API. I did some preliminary benchmarking and found PQClean's Keccak API to be marginally slower than WolfCrypt's implementation, so I will keep Keccak as it is. On the other hand, the "randombytes" API must be replaced with the `WC_RNG` API because later when we move to an embedded platform there will not be a `/dev/urandom` for a source of entropy.

I chose to add `WC_RNG` as a backend to PQClean's `randombytes` API. This requires the `randombytes` implementation to hold a static reference to some RNG instace, and a function for pointing that reference to a user-supplied `WC_RNG`. It is safe to assume that we will not use PQClean API calls outside WolfSSL, so there will not be use-after-free after WolfSSL cleans up the RNG.

```cmake
# Compile PQClean, on MacOS desktop I will do only the clean impls
set(PQCLEAN_ROOT "${CMAKE_CURRENT_LIST_DIR}/../PQClean" CACHE PATH "Path to PQCleang")
get_filename_component(PQCLEAN_ROOT "${PQCLEAN_ROOT}" ABSOLUTE)
if(NOT IS_DIRECTORY "${PQCLEAN_ROOT}")
    message(FATAL_ERROR "'${PQCLEAN_ROOT}' is not a valid directory.")
endif()
message(STATUS "Using PQClean from ${PQCLEAN_ROOT}")
    include_directories(${PQCLEAN_ROOT})
    include_directories(${PQCLEAN_ROOT}/common)
    file(GLOB_RECURSE PQCLEAN_SRC 
        "${PQCLEAN_ROOT}/common/fips202.c"
        "${PQCLEAN_ROOT}/common/randombytes.c"
        "${PQCLEAN_ROOT}/crypto_kem/ml-kem-512/clean/*.c"
        # ...
    )
add_library(pqclean STATIC ${PQCLEAN_SRC})
target_compile_definitions(pqclean PUBLIC HAVE_WC_RNG)
```

## Adding SPHINCS+ and Falcon
Now we have PQClean, we can instantiate the SPHINCS+ and Falcon scaffolding with actual implementations.
There is a bug where SPHINCS+ and Falcon private keys cannot be loaded, but I currently do not care for the situation where SPHINCS+ and/or Falcon is a leaf/client key.

For fairness of comparison I want to use PQClean's ML-DSA as well, which can be integrated in similar fashion.

## Adding ML-KEM and HQC for key exchange
WolfSSL has its in-house implementation of ML-KEM and ML-DSA. 
They were mysteriously optimized. 
The WolfCrypt ML-KEM implementation is somehow twice as fast as the reference implementation. 
While the performance is great for production system, it is not great when I need a fair comparison across different post-quantum cryptography schemes.
I also need to add HQC and one-time ML-KEM.

While the WolfCrypt ML-KEM is not suitable for comparison, it does pave the way for straightforward addition of other KEM schemes with similar `keygen`, `encap`, and `decap` API. Here are the steps for adding them.
- In `wolfssl/ssl.h` there is an enum that defines the various "named groups". ML-KEM is already added, so HQC can be added to the enum as well. Later we will feed these enum variants to `wolfSSL_CTX_set_groups` to fix the KEM used in `ClientHello`.
- There are a few validation tests to modify so the added named groups are accepted: `TLSX_IsGroupSupported`, `isValidCurveGroup`, `NamedGroupIsPqc`.
- The added named groups also need to be added to the list of `int preferredGroup[]` in `tls.c`. Apparently WolfSSL will match the groups set in `wolfSSL_CTX_set_groups` with `preferredGroup`, and if there is no match, then it will send `ClientHello` with no `key_share`. This is allowed by RFC 8446: client can ask server to send server's list of supported key exchange groups using `HelloRetryRequest`. However, this is not what we want, so we will add the new groups to `preferredGroup` and ensure that the first `ClientHello` contains the correct key share.
- Add new schemes to the handshake control flow. Note that these functions were originally hard-coded with WolfCrypt ML-KEM, so it is necessary to move the abstraction down by one function call (e.g. `TLSX_KeyShare_GenPqcKeyClient` originally directly calls `wc_MlKemKey_MakeKey`, but now calls `TLSX_KeyShare_GenMlKemKeyClient` or `TLSX_KeyShare_GenHqcKeyClient`).
    - `TLSX_KeyShare_GenPqcKeyClient`, called by `SendTls13ClientHello` when client is generating `ClientHello`.
    - `TLSX_KeyShare_HandlePqcKeyServer`, called by `DoTls13ClientHello` when server is processing client's key share.
    - `TLSX_KeyShare_ProcessPqcClient`, called by `DoTls13ServerHello` when client is processing server's key share.

For key exchange, each KEM needs to implement the following API
- A `XXXKey` struct, which usually includes the level of the scheme, some byte arrays for public key and secret key, and some flags for whether these keys are present.
- KeyGen, Encap, and Decap
- export/import public key and secret key: for black-box KEM schemes it is sufficient to dump the bytes
- Setting level and getting level, getting public key, secret key, ciphertext, and shared secret sizes

Later when we add KEM for authentication we will need to implement encoding to and decoding according to DER.

## Generating ML-KEM and HQC certificate
Before implementing KEMTLS handshake, we first need to have KEM-based certificate. Since KEM-based certificate cannot be self-signed, they must be the leaf certificate of a non-trivial certificate chain. We will add ML-KEM and HQC. IND-1CCA KEMs are not suitable because certificate keys are necessarily long-term key. Classic McEliece keys are not suitable because the public key (>250kB) is too large.

Here are the modifications to WolfSSL:
- Add ML-KEM and HQC to `enum CertType` under `asn_public.h` and `enum cert_enums` under `asn.h`. Also add the DER-encoded sequence to `asn.c`
- Add OIDs for ML-KEM and HQC. OIDs are variable-length sequence of integers, which is hard to work with using C; WolfSSL simplifies working with OIDs by summing the integers. The sums are aggregated in the header `oid_sum.h`, which is generated by a Perl script `scripts/asn1_oid_sum.pl`. Need to add ML-KEM and HQC to the script and run it.
- Modify `wc_MakeCert_ex` so that ML-KEM and HQC keys are accepted
    - Function signature of `MakeCert` needs to change
    - Implemented `EncodePublicKey_ex` to accept ML-KEM and HQC keys
- Need to implement `PublicKeyToDer`, `PrivateKeyToDer`, and `DerToPrivateKey`, although the last one is not immediately used in certificate generation.
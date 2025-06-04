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

# Implementation with WolfSSL
[WolfSSL](https://github.com/wolfSSL/wolfssl) is a small, fast, and portable implementation of TLS/SSL for embedded devices. It optimizes for code size and memory footprint. WolfSSL also has its own cryptography library called WolfCrypt, which provides symemtric and asymmetric cryptographic primitives used throughout the TLS implementation.

## Getting started
WolfSSL's source code is available on Github. I start forking from [WolfSSL@7898823](https://github.com/wolfssl/wolfssl/tree/7898823). I use CMake to generate the Makefiles so that integrating WolfSSL on desktop environment is highly similar to integrating WolfSSL into Pi Pico's firmware:

```cmake
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

# Link against WolfSSL
add_executable(client src/client.c)
target_link_libraries(client wolfssl)
```

## Supporting custom KEM in key exchange
As of May 2025, WolfSSL already supports TLS 1.3 key exchange using post-quantum and hybrid KEM using an in-house implementation of ML-KEM and various elliptic curves. However, for comparison purposes I also need to add some optimized implementation of ML-KEM, as well as other KEM algorithms including IND-1CCA KEM (One-time ML-KEM) and HQC.


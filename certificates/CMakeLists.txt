cmake_minimum_required(VERSION 3.13)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(tls13server C CXX ASM)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/config
    ${CMAKE_CURRENT_LIST_DIR}/include
)

# Compile WolfSSL into a static library
set(WOLFSSL_ROOT "" CACHE PATH "Path to WolfSSL installation")
if(NOT WOLFSSL_ROOT)
    message(FATAL_ERROR "WOLFSSL_ROOT not set. Please specify -DWOLFSSL_ROOT=/path/to/wolfssl")
endif()
include_directories(${WOLFSSL_ROOT})
file(GLOB WOLFSSL_SRC
    "${WOLFSSL_ROOT}/src/*.c"
    "${WOLFSSL_ROOT}/wolfcrypt/src/*.c"
)
list(REMOVE_ITEM WOLFSSL_SRC EXCLUDE REGEX
    # TODO: enable everything on desktop
    # "${WOLFSSL_ROOT}/src/bio.c"
    # "${WOLFSSL_ROOT}/src/conf.c"
    # "${WOLFSSL_ROOT}/src/pk.c"
    # "${WOLFSSL_ROOT}/src/ssl_asn1.c"
    # "${WOLFSSL_ROOT}/src/ssl_bn.c"
    # "${WOLFSSL_ROOT}/src/ssl_misc.c"
    # "${WOLFSSL_ROOT}/src/x509.c"
    # "${WOLFSSL_ROOT}/src/x509_str.c"
    # "${WOLFSSL_ROOT}/wolfcrypt/src/evp.c"
    # "${WOLFSSL_ROOT}/wolfcrypt/src/misc.c"
)
add_library(wolfssl STATIC
    ${WOLFSSL_SRC}
)
# User settings are specified in config/user_settings.h
target_compile_definitions(wolfssl PUBLIC
    WOLFSSL_USER_SETTINGS
)
# TODO: ignoring deprecation is not ideal
target_compile_options(wolfssl PRIVATE -Wno-deprecated-declarations)

add_compile_options(-O3 -Wall -Wextra)

add_executable(certgen src/certgen.c)
target_link_libraries(certgen wolfssl)

add_executable(asn1 src/asn1.c)
target_link_libraries(asn1 wolfssl)

add_executable(pq-certgen src/pq-certgen.c)
target_link_libraries(pq-certgen wolfssl)

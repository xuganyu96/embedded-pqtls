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
        "${PQCLEAN_ROOT}/crypto_kem/ml-kem-768/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/ml-kem-1024/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/hqc-128/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/hqc-192/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/hqc-256/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/mceliece348864/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/mceliece348864f/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/mceliece460896/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/mceliece460896f/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/mceliece6688128/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/mceliece6688128f/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/mceliece6960119/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/mceliece6960119f/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/mceliece8192128/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/mceliece8192128f/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_sign/ml-dsa-44/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_sign/ml-dsa-65/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_sign/ml-dsa-87/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_sign/falcon-512/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_sign/falcon-1024/clean/*.c"
        # "${PQCLEAN_ROOT}/crypto_sign/sphincs-sha2-128f-simple/clean/*.c"
        # "${PQCLEAN_ROOT}/crypto_sign/sphincs-sha2-128s-simple/clean/*.c"
        # "${PQCLEAN_ROOT}/crypto_sign/sphincs-sha2-192f-simple/clean/*.c"
        # "${PQCLEAN_ROOT}/crypto_sign/sphincs-sha2-192s-simple/clean/*.c"
        # "${PQCLEAN_ROOT}/crypto_sign/sphincs-sha2-256f-simple/clean/*.c"
        # "${PQCLEAN_ROOT}/crypto_sign/sphincs-sha2-256s-simple/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_sign/sphincs-shake-128f-simple/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_sign/sphincs-shake-128s-simple/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_sign/sphincs-shake-192f-simple/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_sign/sphincs-shake-192s-simple/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_sign/sphincs-shake-256f-simple/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_sign/sphincs-shake-256s-simple/clean/*.c"
    )
add_library(pqclean STATIC ${PQCLEAN_SRC})
# message(STATUS "Using PQCLEAN_SRC from ${PQCLEAN_SRC}")
target_compile_definitions(pqclean PUBLIC HAVE_WC_RNG WOLFSSL_USER_SETTINGS)

# Compile WolfSSL into a static library
set(WOLFSSL_ROOT "${CMAKE_CURRENT_LIST_DIR}/../wolfssl" CACHE PATH "Path to WolfSSLg")
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
add_library(wolfssl STATIC ${WOLFSSL_SRC} ${PQCLEAN_SRC})
target_compile_definitions(wolfssl PUBLIC WOLFSSL_USER_SETTINGS)
target_compile_options(wolfssl PRIVATE -Wno-deprecated-declarations)

# Global compilation flags
add_compile_options(-Wall -Wextra)

# Compiling individual binaries
add_executable(certgen src/certgen.c)
target_link_libraries(certgen wolfssl)

add_executable(asn1 src/asn1.c)
target_link_libraries(asn1 wolfssl)

add_executable(tls13server src/tls13server.c)
target_link_libraries(tls13server wolfssl)

add_executable(tls13client src/tls13client.c)
target_link_libraries(tls13client wolfssl)

add_executable(test src/test.c)
target_link_libraries(test wolfssl pqclean)


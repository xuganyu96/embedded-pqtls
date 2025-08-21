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

# PQClean
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
    "${PQCLEAN_ROOT}/crypto_kem/hqc-128/clean/*.c"
    "${PQCLEAN_ROOT}/crypto_kem/hqc-192/clean/*.c"
    "${PQCLEAN_ROOT}/crypto_kem/hqc-256/clean/*.c"
    "${PQCLEAN_ROOT}/crypto_sign/falcon-512/clean/*.c"
    "${PQCLEAN_ROOT}/crypto_sign/falcon-1024/clean/*.c"
    "${PQCLEAN_ROOT}/crypto_sign/sphincs-shake-128f-simple/clean/*.c"
    "${PQCLEAN_ROOT}/crypto_sign/sphincs-shake-128s-simple/clean/*.c"
    "${PQCLEAN_ROOT}/crypto_sign/sphincs-shake-192f-simple/clean/*.c"
    "${PQCLEAN_ROOT}/crypto_sign/sphincs-shake-192s-simple/clean/*.c"
    "${PQCLEAN_ROOT}/crypto_sign/sphincs-shake-256f-simple/clean/*.c"
    "${PQCLEAN_ROOT}/crypto_sign/sphincs-shake-256s-simple/clean/*.c"
)

# WolfSSL
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
add_library(wolfssl STATIC ${WOLFSSL_SRC} ${PQCLEAN_SRC})
target_compile_definitions(wolfssl PUBLIC WOLFSSL_USER_SETTINGS)
target_compile_options(wolfssl PRIVATE -Wno-deprecated-declarations -DUSE_WC_RNG)


add_compile_options(-Wall -Wextra)

add_executable(https_example src/https_example.c)
target_link_libraries(https_example wolfssl)

add_executable(tlsserver src/tlsserver.c)
target_link_libraries(tlsserver wolfssl)

add_executable(certgen src/certgen.c)
target_link_libraries(certgen wolfssl)

add_executable(tlsclient src/tlsclient.c)
target_link_libraries(tlsclient wolfssl)

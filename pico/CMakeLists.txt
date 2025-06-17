cmake_minimum_required(VERSION 3.13)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BUILD_TYPE)
    # -DCMAKE_BUILD_TYPE=<RelWithDebInfo|Debug>
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()
set(PICO_BOARD pico2_w CACHE STRING "Board type")

# Define a helper macro
macro(require_env_var VAR_NAME)
    if(DEFINED ENV{${VAR_NAME}})
        set(${VAR_NAME} $ENV{${VAR_NAME}})
        message(STATUS "${VAR_NAME} set to ${${VAR_NAME}}")
    else()
        message(FATAL_ERROR "Error: environment variable ${VAR_NAME} is not set."
            " Did you source ${CMAKE_CURRENT_LIST_DIR}/.env?")
    endif()
endmacro()

# Use it for required variables
require_env_var(WIFI_SSID)
require_env_var(WIFI_PASSWORD)
require_env_var(TEST_TCP_SERVER_IP)
require_env_var(TEST_TCP_SERVER_HOSTNAME)
require_env_var(TEST_TCP_SERVER_PORT)

include(pico_sdk_import.cmake)
project(pico-pqtls C CXX ASM)
pico_sdk_init()

include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/config)
include_directories(${CMAKE_CURRENT_LIST_DIR}/include)

# >>>>>>> PQClean
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
        "${PQCLEAN_ROOT}/crypto_kem/ot-ml-kem-512/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/ot-ml-kem-768/clean/*.c"
        "${PQCLEAN_ROOT}/crypto_kem/ot-ml-kem-1024/clean/*.c"
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
target_compile_definitions(pqclean PUBLIC HAVE_WC_RNG WOLFSSL_USER_SETTINGS)
# message(STATUS "Using PQCLEAN_SRC from ${PQCLEAN_SRC}")

# >>>>>>> WolfSSL 
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
    "${WOLFSSL_ROOT}/wolfcrypt/src/port/rpi_pico/*"
)
list(REMOVE_ITEM WOLFSSL_SRC EXCLUDE REGEX
    "${WOLFSSL_ROOT}/src/bio.c"
    "${WOLFSSL_ROOT}/src/conf.c"
    "${WOLFSSL_ROOT}/src/pk.c"
    "${WOLFSSL_ROOT}/src/ssl_asn1.c"
    "${WOLFSSL_ROOT}/src/ssl_bn.c"
    "${WOLFSSL_ROOT}/src/ssl_misc.c"
    "${WOLFSSL_ROOT}/src/x509.c"
    "${WOLFSSL_ROOT}/src/x509_str.c"
    "${WOLFSSL_ROOT}/wolfcrypt/src/evp.c"
    "${WOLFSSL_ROOT}/wolfcrypt/src/misc.c"
)
add_library(wolfssl STATIC
    ${WOLFSSL_SRC}
)
target_compile_definitions(wolfssl PUBLIC
    WOLFSSL_USER_SETTINGS
)
target_compile_options(wolfssl PRIVATE -Wno-deprecated-declarations)
if (${PICO_PLATFORM} STREQUAL "rp2350")
    add_compile_definitions(wolfssl WOLFSSL_SP_ARM_CORTEX_M_ASM)
elseif (${PICO_PLATFORM} STREQUAL "rp2350-riscv")
    add_compile_definitions(wolfSSL WOLFSSL_SP_RISCV32)
else()
    add_compile_definitions(wolfssl WOLFSSL_SP_ARM_THUMB_ASM)
endif()
target_link_libraries(wolfssl
    pqclean
    pico_stdlib
    pico_rand
)



# comment out to get plain logging, good for logging to file
# add_compile_definitions(USE_COLORED_LOGGING)

file(GLOB COMMON_SRC src/common/*.c)

add_executable(bench_wolfcrypt
    src/bench_wolfcrypt.c
    ${COMMON_SRC}
)
pico_enable_stdio_uart(bench_wolfcrypt 0)
pico_enable_stdio_usb(bench_wolfcrypt 1)
target_link_libraries(bench_wolfcrypt
    wolfssl
    pico_stdlib
    pico_rand
    pico_cyw43_arch_lwip_poll
)
pico_add_extra_outputs(bench_wolfcrypt)

add_executable(test_tcp_stream src/test_tcp_stream.c ${COMMON_SRC})
pico_enable_stdio_uart(test_tcp_stream 0)
pico_enable_stdio_usb(test_tcp_stream 1)
target_link_libraries(test_tcp_stream pico_stdlib pico_cyw43_arch_lwip_poll)
target_compile_definitions(test_tcp_stream PRIVATE
    WIFI_SSID=\"${WIFI_SSID}\"
    WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
    TEST_TCP_SERVER_IP=\"${TEST_TCP_SERVER_IP}\"
    TEST_TCP_SERVER_PORT=${TEST_TCP_SERVER_PORT}
)
pico_add_extra_outputs(test_tcp_stream)

add_executable(tls_client src/tls_client.c ${COMMON_SRC})
pico_enable_stdio_uart(tls_client 0)
pico_enable_stdio_usb(tls_client 1)
target_link_libraries(tls_client
    wolfssl
    pico_stdlib
    pico_rand
    pico_cyw43_arch_lwip_poll
)
target_compile_definitions(tls_client PRIVATE
    WIFI_SSID=\"${WIFI_SSID}\"
    WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
    TEST_TCP_SERVER_IP=\"${TEST_TCP_SERVER_IP}\"
    TEST_TCP_SERVER_HOSTNAME=\"${TEST_TCP_SERVER_HOSTNAME}\"
    TEST_TCP_SERVER_PORT=${TEST_TCP_SERVER_PORT}
)
pico_add_extra_outputs(tls_client)

add_executable(https_client src/https_client.c ${COMMON_SRC})
pico_enable_stdio_uart(https_client 0)
pico_enable_stdio_usb(https_client 1)
target_link_libraries(https_client
    wolfssl
    pico_stdlib
    pico_rand
    pico_cyw43_arch_lwip_poll
)
target_compile_definitions(https_client PRIVATE
    WIFI_SSID=\"${WIFI_SSID}\"
    WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
    TEST_TCP_SERVER_IP=\"${TEST_TCP_SERVER_IP}\"
    TEST_TCP_SERVER_PORT=${TEST_TCP_SERVER_PORT}
)
pico_add_extra_outputs(https_client)

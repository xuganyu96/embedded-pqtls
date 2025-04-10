cmake_minimum_required(VERSION 3.13)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
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
require_env_var(TEST_TCP_SERVER_PORT)
require_env_var(WOLFSSL_ROOT)

include(pico_sdk_import.cmake)
project(pico-pqtls C CXX ASM)
pico_sdk_init()

include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/config)
include_directories(${CMAKE_CURRENT_LIST_DIR}/include)

# WolfSSL source
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
if (${PICO_PLATFORM} STREQUAL "rp2350")
    add_compile_definitions(wolfssl WOLFSSL_SP_ARM_CORTEX_M_ASM)
elseif (${PICO_PLATFORM} STREQUAL "rp2350-riscv")
    add_compile_definitions(wolfSSL WOLFSSL_SP_RISCV32)
else()
    add_compile_definitions(wolfssl WOLFSSL_SP_ARM_THUMB_ASM)
endif()
target_link_libraries(wolfssl
    pico_stdlib
    pico_rand
)


# comment out to get plain logging, good for logging to file
add_compile_definitions(USE_COLORED_LOGGING)

file(GLOB COMMON_SRC src/common/*.c)

add_executable(colors src/colors.c ${COMMON_SRC})
pico_enable_stdio_uart(colors 0)
pico_enable_stdio_usb(colors 1)
target_link_libraries(colors pico_stdlib pico_cyw43_arch_lwip_poll)
pico_add_extra_outputs(colors)


add_executable(connect_wifi src/connect_wifi.c ${COMMON_SRC})
pico_enable_stdio_uart(connect_wifi 0)
pico_enable_stdio_usb(connect_wifi 1)
target_link_libraries(connect_wifi pico_stdlib pico_cyw43_arch_lwip_poll)
target_compile_definitions(connect_wifi  PRIVATE
    WIFI_SSID=\"${WIFI_SSID}\"
    WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
)
pico_add_extra_outputs(connect_wifi)

add_executable(tcp_stream src/tcp_stream.c ${COMMON_SRC})
pico_enable_stdio_uart(tcp_stream 0)
pico_enable_stdio_usb(tcp_stream 1)
target_link_libraries(tcp_stream pico_stdlib pico_cyw43_arch_lwip_poll)
target_compile_definitions(tcp_stream PRIVATE
    WIFI_SSID=\"${WIFI_SSID}\"
    WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
    TEST_TCP_SERVER_IP=\"${TEST_TCP_SERVER_IP}\"
    TEST_TCP_SERVER_PORT=${TEST_TCP_SERVER_PORT}
)
pico_add_extra_outputs(tcp_stream)

add_executable(bench_wolfcrypt
    src/bench_wolfcrypt.c
    ${COMMON_SRC}
    ${WOLFSSL_ROOT}/wolfcrypt/benchmark/benchmark.c
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

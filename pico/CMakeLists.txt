cmake_minimum_required(VERSION 3.13)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(PICO_BOARD pico2_w CACHE STRING "Board type")

# Use environment variables WIFI_SSID and WIFI_PASSWORD to set wifi parameters
if(DEFINED ENV{WIFI_SSID})
    set(WIFI_SSID $ENV{WIFI_SSID})
    message("Wifi SSID set to ${WIFI_SSID}")
else()
    message(FATAL_ERROR "Error: environment variable WIFI_SSID is not set."
    "Did you source ${CMAKE_CURRENT_LIST_DIR}/.env?")
endif()
if(DEFINED ENV{WIFI_PASSWORD})
    set(WIFI_PASSWORD $ENV{WIFI_PASSWORD})
    message("Wifi PASSWORD set to ${WIFI_PASSWORD}")
else()
    message(FATAL_ERROR "Error: environment variable WIFI_PASSWORD is not set."
    "Did you source ${CMAKE_CURRENT_LIST_DIR}/.env?")
endif()
if(DEFINED ENV{TEST_TCP_SERVER_IP})
    set(TEST_TCP_SERVER_IP $ENV{TEST_TCP_SERVER_IP})
    message("Wifi PASSWORD set to ${TEST_TCP_SERVER_IP}")
else()
    message(FATAL_ERROR "Error: environment variable TEST_TCP_SERVER_IP is not set."
    "Did you source ${CMAKE_CURRENT_LIST_DIR}/.env?")
endif()

include(pico_sdk_import.cmake)
project(pico-pqtls C CXX ASM)
pico_sdk_init()
include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/src)

file(GLOB COMMON_SRC src/common/*.c)

add_executable(connect_wifi src/connect_wifi.c ${COMMON_SRC})
pico_enable_stdio_uart(connect_wifi 0)
pico_enable_stdio_usb(connect_wifi 1)
target_link_libraries(connect_wifi pico_stdlib pico_cyw43_arch_lwip_poll)
target_compile_definitions(connect_wifi  PRIVATE
    WIFI_SSID=\"${WIFI_SSID}\"
    WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
)
pico_add_extra_outputs(connect_wifi)

add_executable(tcp_client src/tcp_client.c ${COMMON_SRC})
pico_enable_stdio_uart(tcp_client 0)
pico_enable_stdio_usb(tcp_client 1)
target_link_libraries(tcp_client pico_stdlib pico_cyw43_arch_lwip_poll)
target_compile_definitions(tcp_client PRIVATE
    WIFI_SSID=\"${WIFI_SSID}\"
    WIFI_PASSWORD=\"${WIFI_PASSWORD}\"
    TEST_TCP_SERVER_IP=\"${TEST_TCP_SERVER_IP}\"
)
pico_add_extra_outputs(tcp_client)


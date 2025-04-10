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

include(pico_sdk_import.cmake)
project(pico-pqtls C CXX ASM)
pico_sdk_init()

include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/config)
include_directories(${CMAKE_CURRENT_LIST_DIR}/include)

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

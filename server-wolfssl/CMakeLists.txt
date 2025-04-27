cmake_minimum_required(VERSION 3.13)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# set(CMAKE_BUILD_TYPE RelWithDebInfo)
set(CMAKE_BUILD_TYPE Debug)

project(pq-certgen C CXX ASM)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/config
)

# Compile WolfSSL into static library
# Instead of using autogen and configure, use header file `user_settings.h`
set(WOLFSSL_ROOT "${CMAKE_CURRENT_LIST_DIR}/../wolfssl" CACHE PATH "Path to WolfSSL installation")
get_filename_component(WOLFSSL_ROOT "${WOLFSSL_ROOT}" ABSOLUTE)
if(NOT IS_DIRECTORY "${WOLFSSL_ROOT}")
    message(FATAL_ERROR "WOLFSSL_ROOT is set to '${WOLFSSL_ROOT}', but this is not a valid directory.")
endif()
message(STATUS "Using wolfSSL from ${WOLFSSL_ROOT}")
include_directories(${WOLFSSL_ROOT})
file(GLOB WOLFSSL_SRC "${WOLFSSL_ROOT}/src/*.c" "${WOLFSSL_ROOT}/wolfcrypt/src/*.c")
add_library(wolfssl STATIC ${WOLFSSL_SRC})
target_compile_definitions(wolfssl PUBLIC WOLFSSL_USER_SETTINGS)
target_compile_options(wolfssl PRIVATE -Wno-deprecated-declarations)


add_compile_options(-Wall -Wextra)

add_executable(certgen src/certgen.c)
target_link_libraries(certgen wolfssl)

add_executable(asn1 src/asn1.c)
target_link_libraries(asn1 wolfssl)

add_executable(echoserver src/echoserver.c)
add_executable(tcp_bench_client src/tcp_bench_client.c)

add_executable(tls13client src/tls13client.c)
target_link_libraries(tls13client wolfssl)

add_executable(tls13server src/tls13server.c)
target_link_libraries(tls13server wolfssl)

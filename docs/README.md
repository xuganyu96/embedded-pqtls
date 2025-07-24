# July 24, 2025
## Compile the first program
Set up the server project, containing programs that run on MacOS and/or Ubuntu Linux:

```
server/
    src/
    config/
    include/
    CMakeLists.txt
```

`src/` contains `.c` source files. `config/` contains `user_settings.h`, a header file containing build-time configuration for WolfSSL. `include/` contains `.h` header files. We also need a `build/` directory to host the build artifacts specified in `CMakeLists.txt`.

Build a first program.
The source code will exist at `src/client.c`; we call it client because we will later fill it in as a TLS client.

```c
#include <stdio.h>

int main(void) {
  printf("你好，🌍!\n");
  return 0;
}
```

Fill in the boilerplate for `CMakeLists.txt`, then add the program as compilation target.

```cmake
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

add_compile_options(-Wall -Wextra)

add_executable(tlsclient src/tlsclient.c)
```

Build for the first time:

```bash
# from server/
mkdir build
cd build
cmake .. && make
./tlsclient  # should print "Hello, world"
```

## Simple TLS client
Next we will write a simple TLS client in `tlsclient.c`.
First we need to pull in [WolfSSL](https://github.com/wolfssl/wolfssl).
We will clone a fork of it as a submodule so we can modify it and compile the library from source.

```bash
# from project root
git submodule add git@github.com:xuganyu96/wolfssl.git
```

Some helpful commands with git submodules:
- When cloning `git clone --recurse-submodules` will recursively clone submodules, including submodules within submodules; this will be helpful later when `pico-sdk` is a submodule that contains sub-modules like `lwip`
- `git submodule update --init --recursive` will initialize uninitialized sub-modules, then update them recursively

At the time of this write-up, WolfSSL's head is at commit `2db1669`.

We will configure WolfSSL using `config/user_settings.h`.
A [template](https://github.com/wolfSSL/wolfssl/tree/master/examples/configs) provided by WolfSSL serves as a good starting point:

```bash
# from server/
curl https://raw.githubusercontent.com/wolfSSL/wolfssl/refs/heads/master/examples/configs/user_settings_template.h > config/user_settings.h
```

> The template enables single-precision math by default, but my compiler `Apple clang 17.0.0` will not compile with this configuration, and I have to turn it off.

Then we need to add WolfSSL's source code to `CMakeLists.txt` and tell CMake how to generate compile commands:

```cmake
# Compile WolfSSL into a static library
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
add_library(wolfssl STATIC ${WOLFSSL_SRC})
target_compile_definitions(wolfssl PUBLIC WOLFSSL_USER_SETTINGS)
target_compile_options(wolfssl PRIVATE -Wno-deprecated-declarations)

# Compile tlsclient and link wolfssl against it
add_executable(tlsclient src/tlsclient.c)
target_link_libraries(tlsclient wolfssl)
```

Before we introduce any WolfSSL library components into `tlsclient.c`, build the project once just to make sure that WolfSSL can compile correctly.
This test build will also export compile commands under `build/compile_commands.json`, which the LSP needs to function correctly.
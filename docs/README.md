# July 24, 2025
Git sub-module status:

```
2cc64716044832eea747234ddbffc06746ab815d PQClean (heads/master)
2db16697137628d9653cacb3534212823433aa88 wolfssl (heads/master)
```

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

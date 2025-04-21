# Post-quantum certificates

## Compile WolfSSL from source
Instead of using `autogen`, `configure`, and `make` to install WolfSSL into system path, use `user_settings.h` to control the compilation options, then compile WolfSSL into a static library.

```cmake
# Compile WolfSSL into static library
# Instead of using autogen and configure, use header file `user_settings.h`
set(WOLFSSL_ROOT "" CACHE PATH "Path to WolfSSL installation")
if(NOT WOLFSSL_ROOT)
    message(FATAL_ERROR "WOLFSSL_ROOT not set. Please specify -DWOLFSSL_ROOT=/path/to/wolfssl")
endif()
include_directories(${WOLFSSL_ROOT})
file(GLOB WOLFSSL_SRC "${WOLFSSL_ROOT}/src/*.c" "${WOLFSSL_ROOT}/wolfcrypt/src/*.c")
add_library(wolfssl STATIC ${WOLFSSL_SRC})
target_compile_definitions(wolfssl PUBLIC WOLFSSL_USER_SETTINGS)
target_compile_options(wolfssl PRIVATE -Wno-deprecated-declarations)
```

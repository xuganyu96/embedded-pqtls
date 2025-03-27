# Blinking Pico
The blink binary from [here](http://rptl.io/pico-w-blink) is built for the Pico W (RP2040), not Pico W 2 (RP2350). Here is the instruction on how to do it for Pico W 2 (note that the LED on the wireless-capable boards are wired differently from the LED on the non-wireless boards, so this guide does not apply to Pico 2.

First install CMake and cross compilers, then clone the Pico SDK:

```bash
sudo apt install -y cmake gcc-arm-none-eabi libnewlib-arm-none-eabi libstdc++-arm-none-eabi-newlib
# --recurse-submodules is needed since we need to use the submodules for controlling the wireless
# chip, which controls the LED
git clone git@github.com/raspberrypi/pico-sdk --recurse-submodules

# The environment variable PICO_SDK_PATH is required later
cd pico-sdk
export PICO_SDK_PATH="$(pwd)"
```

Under the project root, copy `pico_sdk_import.cmake` from the SDK root directory, then create the project `CMakeLists.txt`

```cmake
cmake_minimum_required(VERSION 3.13)
include(pico_sdk_import.cmake)
project(myproject)
pico_sdk_init()
add_executable(blink_pico2w blink_pico2w.c)
target_link_libraries(blink_pico2w pico_stdlib pico_cyw43_arch_none)
pico_add_extra_outputs(blink_pico2w)
```

Under project root, add the source file `blink_pico2w.c`:

```c
/**
 * Copyright (c) 2022 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"

int main() {
    stdio_init_all();
    if (cyw43_arch_init()) {
        printf("Wi-Fi init failed");
        return -1;
    }
    while (true) {
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
        sleep_ms(250);
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
        sleep_ms(250);
    }
}
```

From project root, create the build directory, then build the project. Here we need `PICO_SDK_PATH` to point to the `pico-sdk` directory set earlier. Alternatively you can pass the argument `-DPICO_SDK_PATH=<...>` to the cmake command.

```cmake
mkdir build
cd build
cmake .. -DPICO_BOARD=pico2_w  # This generates the build system
make blink_pico2w  # This builds the executables
```

Press the `BOOTSEL` button on the Pico 2 W and plug it into the computer. The Pico 2 W should show up as a USB storage device, to which you can copy the built `blink_pico2w.uf2` file. The board should shortly disconnect itself from the computer, then start blinking.

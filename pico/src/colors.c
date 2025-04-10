#include <pico/stdio.h>
#include <pico/time.h>
#include <stdio.h>

#include "pico-pqtls/utils.h"

int main(void) {
  stdio_init_all();

  while (1) {
    CRITICAL_printf("This is an critical message: %s\n", "File not found");
    WARNING_printf("This is a warning message: %s\n", "Low disk space");
    INFO_printf("This is an info message: %s\n",
                "Operation completed successfully");
    DEBUG_printf("This is a debug message: %s\n", "Variable x = 42");

    sleep_ms(1000);
  }
}

#include <pico/stdlib.h>
#include <stdio.h>
#include "utils.h"

void countdown_s(int dur) {
  for (int i = dur; i > 0; i--) {
    printf("Main loop begins in %d seconds\n", i);
    sleep_ms(1000);
  }
}


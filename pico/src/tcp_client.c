#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>
#include <stdio.h>

#include "common/utils.h"

int main(void) {
  stdio_init_all();
  countdown_s(10);

  if (cyw43_arch_init()) {
    printf("cyw43_arch_init failed\n");
    return -1;
  }
  cyw43_arch_enable_sta_mode();

  printf("Connecting to Wi-Fi: %s...\n", WIFI_SSID);
  int result = cyw43_arch_wifi_connect_timeout_ms(
      WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 10000);
  if (result != 0) {
    printf("Wi-Fi connect failed (error %d)\n", result);
  } else {
    printf("Connected!\n");
  }

  while (1) {
  }
}

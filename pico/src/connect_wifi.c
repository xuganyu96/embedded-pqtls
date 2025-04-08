#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>
#include <stdio.h>

#include "pico-pqtls/utils.h"

int main() {
  stdio_init_all();
  countdown_s(10);
  printf("Starting Wi-Fi status monitor...\n");

  if (cyw43_arch_init()) {
    printf("cyw43_arch_init failed\n");
    return -1;
  }

  cyw43_arch_enable_sta_mode();

  while (true) {
    ensure_wifi_connection_blocking(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK);

    sleep_ms(2000);
  }

  return 0;
}

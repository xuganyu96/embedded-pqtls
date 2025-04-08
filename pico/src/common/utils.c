#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>
#include <stdio.h>

#include "pico-pqtls/utils.h"

void countdown_s(int dur) {
  for (int i = dur; i > 0; i--) {
    printf("Main loop begins in %d seconds\n", i);
    sleep_ms(1000);
  }
}

static bool wifi_connected() {
  int status = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
  return (status == CYW43_LINK_UP) || (status == CYW43_LINK_JOIN);
}

void ensure_wifi_connection_blocking(const char *ssid, const char *pw,
                                     uint32_t auth) {
  int result;
  while (!wifi_connected()) {
    printf("Wifi is down\n");
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
    result = cyw43_arch_wifi_connect_timeout_ms(ssid, pw, auth, 10000);

    if (result != 0) {
      printf("Wi-Fi re-connect failed (error %d)\n", result);
    } else {
      printf("Connected!\n");
    }
  }
  printf("WiFi is up\n");
  cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
  cyw43_arch_poll();
}

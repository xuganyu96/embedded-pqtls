#ifndef PICO_PQTLS_UTILS_H
#define PICO_PQTLS_UTILS_H

#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>

#include "include/pico-pqtls/utils.h"

#define WIFI_CONNECT_TIMEOUT_MS 30000

/**
 * Countdown from specified number of seconds. Useful for giving the human time to do setup
 */
void countdown_s(int dur) {
  for (int i = dur; i > 0; i--) {
    DEBUG_printf("Main loop begins in %d seconds\n", i);
    sleep_ms(1000);
  }
}

/**
 * Return true if the board is connected to a WiFi network
 * WiFi link status is documented here:
 * https://www.raspberrypi.com/documentation/pico-sdk/networking.html
 */
static bool wifi_connected() {
  int status = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
  return (status == CYW43_LINK_UP) || (status == CYW43_LINK_JOIN);
}

void ensure_wifi_connection_blocking(const char *ssid, const char *pw,
                                     uint32_t auth) {
  while (!wifi_connected()) {
    WARNING_printf("Wifi is down\n");
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);

    DEBUG_printf("Attempting re-connect\n");
    if (cyw43_arch_wifi_connect_timeout_ms(ssid, pw, auth,
                                           WIFI_CONNECT_TIMEOUT_MS) != 0) {
      WARNING_printf("Wi-Fi re-connect failed\n");
    } else {
      // INFO_printf("Connected!\n");
    }
  }
  // printf("WiFi is up\n");
  cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
  cyw43_arch_poll();
}
#endif

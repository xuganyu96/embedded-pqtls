#include "common/utils.h"
#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>
#include <stdio.h>

int main() {
  stdio_init_all();
  countdown_s(10);
  printf("Starting Wi-Fi status monitor...\n");

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

  while (true) {
    cyw43_arch_poll();
    int status = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);

    if (status == CYW43_LINK_UP || status == CYW43_LINK_JOIN) {
      cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1); // LED ON
      printf("Wi-Fi UP\n");
    } else {
      cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0); // LED OFF
      printf("Wi-Fi DOWN (status = %d)\n", status);
      result = cyw43_arch_wifi_connect_timeout_ms(
          WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 10000);

      if (result != 0) {
        printf("Wi-Fi re-connect failed (error %d)\n", result);
      } else {
        printf("Connected!\n");
      }
    }

    sleep_ms(2000);
  }

  return 0;
}

#include <cyw43_ll.h>
#include <pico/cyw43_arch.h>
#include <pico/cyw43_arch/arch_poll.h>
#include <pico/stdlib.h>

#define WIFI_CONNECT_TIMEOUT_MS 30000

int main(void) {
  stdio_init_all();

  if (cyw43_arch_init()) {
    printf("ERROR: cyw43 failed to initialize\n");
    return -1;
  }
  // station mode. The counter part is access point mode (ap_mode)
  // For now this pico is connecting to another network, so we use station mode
  cyw43_arch_enable_sta_mode();

  if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD,
                                         CYW43_AUTH_WPA2_AES_PSK,
                                         WIFI_CONNECT_TIMEOUT_MS)) {
    printf("ERROR: wifi connection timed out after %d ms",
           WIFI_CONNECT_TIMEOUT_MS);
    return -1;
  }

  while(1) {
    printf("Connected to %s\n", WIFI_SSID);
    sleep_ms(1000);
  }
}

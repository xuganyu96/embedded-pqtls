#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>
#include <stdio.h>

#include "pico-pqtls/tcp.h"
#include "pico-pqtls/utils.h"

// This is a safe choice; 700 will fail sometimes
#define TCP_CONNECT_TIMEOUT_MS 1000

int main(void) {
  stdio_init_all();
  // countdown_s(10);

  if (cyw43_arch_init()) {
    printf("cyw43_arch_init failed\n");
    return -1;
  }

  cyw43_arch_enable_sta_mode();

  err_t err;

  while (1) {
    ensure_wifi_connection_blocking(WIFI_SSID, WIFI_PASSWORD,
                                    CYW43_AUTH_WPA2_AES_PSK);

    PICO_PQTLS_tcp_stream_t *stream = PICO_PQTLS_tcp_stream_new();
    if (!stream) {
      DEBUG_printf("FATAL: fail to instantiate TCP stream\n");
      return -1;
    }

    err = PICO_PQTLS_tcp_stream_connect_timeout_ms(stream, TEST_TCP_SERVER_IP,
                                                   TEST_TCP_SERVER_PORT,
                                                   TCP_CONNECT_TIMEOUT_MS);
    if (err == ERR_OK) {
      DEBUG_printf("Connected to %s:%d\n", TEST_TCP_SERVER_IP,
                   TEST_TCP_SERVER_PORT);
    } else {
      DEBUG_printf("Failed to establish connection within %d ms (err=%d)\n",
                   TCP_CONNECT_TIMEOUT_MS, err);
      PICO_PQTLS_tcp_stream_close(stream);
      sleep_ms(2000);
      continue;
    }

    err = PICO_PQTLS_tcp_stream_close(stream);
    if (err == ERR_OK) {
      DEBUG_printf("Gracefully terminated connection\n");
    } else if (err == ERR_ABRT) {
      DEBUG_printf("Aborted connection\n");
    } else {
      DEBUG_printf("FATAL: UNREACHABLE!\n");
      return -1;
    }
    sleep_ms(2000);
  }
}

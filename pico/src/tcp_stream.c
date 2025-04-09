/**
 * Example TCP client
 *
 * NOTE: April 9, 2025
 * There is an interesting panic that I ran into. The server uses `nc -lv 8000`
 * to listen for incoming TCP connection. First run the server, then start the
 * Pico, at which time the Pico will repeatedly establish connection, then
 * gracefully terminate it. The second step is to stop the server, at which
 * point the Pico should start reporting "failing to connect", which is still
 * ok. For the third time, start the server again, then **the Pico will make one
 * successful connection before panic**: Connecting to 129.97.229.167:8000
 * tcp_connect returned 0
 * *** PANIC ***
 * tcp_input: TIME-WAIT pcb->state == TIME-WAIT
 */
#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>
#include <stdio.h>

#include "pico-pqtls/tcp.h"
#include "pico-pqtls/utils.h"

#define TCP_CONNECT_TIMEOUT_MS 1000
#define TCP_READ_TIMEOUT_MS 10000

int main(void) {
  uint8_t app_buf[512];
  stdio_init_all();
  countdown_s(10);

  if (cyw43_arch_init()) {
    printf("cyw43_arch_init failed\n");
    return -1;
  }

  cyw43_arch_enable_sta_mode();

  err_t err;
  size_t outlen;
  PICO_PQTLS_tcp_err_t tcp_err;

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
      goto sleep;
    }

    tcp_err = PICO_PQTLS_tcp_stream_read(stream, app_buf, sizeof(app_buf),
                                         &outlen, TCP_READ_TIMEOUT_MS);
    if (tcp_err == TCP_RESULT_OK) {
      app_buf[outlen] = 0; // Null-terminate the received string
      printf("Received %d bytes: %s\n", outlen, app_buf);
    } else {
      printf("Read error: %d\n", tcp_err);
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

  sleep:
    sleep_ms(2000);
  }
}

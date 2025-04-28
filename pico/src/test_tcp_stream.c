/**
 * BUG: there must be some memory leaks; after a few reflection tests there will
 * be a "Failed to allocate for tcp_pcb"
 */
#include <lwip/err.h>
#include <lwip/ip4_addr.h>
#include <lwip/ip_addr.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <lwip/tcpbase.h>
#include <malloc.h>
#include <pico/cyw43_arch.h>
#include <pico/stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include "pico-pqtls/tcp.h"
#include "pico-pqtls/utils.h"

#define TCP_TEST_ROUNDS 20
#define TEST_MSG_MAX_SIZE (1 << 14)
#define TEST_MSG_MIN_SIZE 1024

static int test_tcp_stream(tcp_stream_t *stream) {
  if (!stream || !stream->pcb || !stream->connected) {
    return 1;
  }
  uint8_t app_rx_buf[TEST_MSG_MAX_SIZE];
  uint8_t app_tx_buf[TEST_MSG_MAX_SIZE];
  size_t msglen = sizeof(app_rx_buf);
  err_t send_err = ERR_OK, recv_err = ERR_OK;
  size_t send_tot_len, send_len, recv_tot_len, recv_len;

  for (int round = 0; round < TCP_TEST_ROUNDS; round++) {
    DEBUG_printf("Test rounds %d, msglen=%zu\n", round, msglen);
    send_tot_len = 0;
    recv_tot_len = 0;
    // DEBUG_printf("testing read/write size %zu bytes\n", msglen);
    memset(app_rx_buf, 0x00, sizeof(app_rx_buf));
    memset(app_tx_buf, 0xFF, sizeof(app_rx_buf));

    // assume that the peer is an echo server, send messages of increasing
    // sizes, then check if the same message was sent back
    while (send_err == ERR_OK && send_tot_len < msglen) {
      send_err = tcp_stream_write(stream, app_tx_buf + send_tot_len,
                                  msglen - send_tot_len, &send_len, 0);
      tcp_stream_flush(stream);
      if (send_err == ERR_OK) {
        send_tot_len += send_len;
      }
    }
    if (send_err == ERR_OK) {
      // DEBUG_printf("Successfully sent %zu bytes\n", send_tot_len);
    } else {
      WARNING_printf("Failed to send %zu bytes (err %d)\n", msglen, send_err);
    }

    while (recv_err == ERR_OK && recv_tot_len < msglen) {
      recv_err = tcp_stream_read(stream, app_rx_buf + recv_tot_len,
                                 msglen - recv_tot_len, &recv_len);
      if (recv_err == ERR_OK) {
        recv_tot_len += recv_len;
      }
    }

    uint8_t diff = 0;
    for (size_t i = 0; i < msglen; i++) {
      diff |= app_rx_buf[i] ^ app_tx_buf[i];
    }
    if (diff) {
      WARNING_printf("Reflection failed at msglen=%zu\n", msglen);
      return 1;
    }
    INFO_printf("Reflection(msglen=%zu) succeeded\n", msglen);
  }

  return 0;
}

int main(void) {
  stdio_init_all();

  countdown_s(10);
  if (cyw43_arch_init()) {
    printf("cyw43_arch_init failed\n");
    return -1;
  }
  cyw43_arch_enable_sta_mode();

  ensure_wifi_connection_blocking(WIFI_SSID, WIFI_PASSWORD,
                                  CYW43_AUTH_WPA2_AES_PSK);

  tcp_stream_t stream;
  err_t lwip_err;
  // struct mallinfo mi;
  // mi = mallinfo();
  // DEBUG_printf("arena: %d, non-inuse: %d\n", mi.arena, mi.fordblks);

  while (1) {
    ensure_wifi_connection_blocking(WIFI_SSID, WIFI_PASSWORD,
                                    CYW43_AUTH_WPA2_AES_PSK);

    tcp_stream_init(&stream);
    lwip_err =
        tcp_stream_connect_ipv4(&stream, TEST_TCP_SERVER_IP,
                                TEST_TCP_SERVER_PORT, TCP_CONNECT_TIMEOUT_MS);
    if (lwip_err == ERR_OK) {
      INFO_printf("Connected to %s:%d\n", TEST_TCP_SERVER_IP,
                  TEST_TCP_SERVER_PORT);
    } else {
      WARNING_printf("Failed to connect to %s:%d\n", TEST_TCP_SERVER_IP,
                     TEST_TCP_SERVER_PORT);
    }

    int tcp_test_fail = test_tcp_stream(&stream);
    if (tcp_test_fail) {
      WARNING_printf("TCP stream test failed\n");
    } else {
      INFO_printf("TCP stream test succeeded\n");
    }

    if ((lwip_err = tcp_stream_close(&stream)) == ERR_OK) {
      INFO_printf("Gracefully closed connection\n");
    } else {
      WARNING_printf("Failed to gracefully close connection (err %d)\n",
                     lwip_err);
    }
    // mi = mallinfo();
    // DEBUG_printf("arena: %d, non-inuse: %d\n", mi.arena, mi.fordblks);

    sleep_ms(1000);
  }
}

#include <lwip/err.h>
#include <lwip/ip4_addr.h>
#include <lwip/ip_addr.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <lwip/tcpbase.h>
#include <pico/cyw43_arch.h>
#include <pico/stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include "pico-pqtls/utils.h"

#define CYW43_LWIP_TCP_TICK 1
#define TCP_CONNECT_TIMEOUT_MS (1000 * 10)
#define TEST_MSG_MAX_SIZE 8192
#define TEST_MSG_MIN_SIZE 1024

typedef struct tcp_stream {
  struct tcp_pcb *pcb;
  ip_addr_t peer_addr;
  struct pbuf *rx_pbuf;
  uint16_t rx_offset;
  bool connected;
} tcp_stream_t;

static err_t recv_handler(void *arg, struct tcp_pcb *tpcb, struct pbuf *p,
                          err_t err) {
  tcp_stream_t *stream = (tcp_stream_t *)arg;
  err_t lwip_err = ERR_OK;

  cyw43_arch_lwip_begin();
  if (stream == NULL) {
    tcp_abort(tpcb);
    lwip_err = ERR_ABRT;
  } else if (tpcb == NULL || err != ERR_OK) {
    // something went wrong, free resources and abort
    if (stream->rx_pbuf) {
      pbuf_free(stream->rx_pbuf);
    }
    if (p) {
      pbuf_free(p);
    }
    stream->rx_pbuf = NULL;
    stream->pcb = NULL;
    tcp_abort(tpcb);
    lwip_err = ERR_ABRT;
  } else if (p) {
    if (stream->rx_pbuf) {
      uint32_t remaining_cap = 0xFFFF - stream->rx_pbuf->tot_len;
      if (remaining_cap > p->tot_len) {
        lwip_err = ERR_WOULDBLOCK;
      } else {
        pbuf_cat(stream->rx_pbuf, p);
      }
    } else {
      stream->rx_pbuf = p;
    }
  }
  cyw43_arch_lwip_end();
  return lwip_err;
}

static err_t sent_handler(void *arg, struct tcp_pcb *tpcb, u16_t len) {
  return ERR_OK;
}

static err_t poll_handler(void *arg, struct tcp_pcb *tpcb) {
  tcp_stream_t *stream = (tcp_stream_t *)arg;
  err_t lwip_err = ERR_OK;

  // flush unprocessed output
  cyw43_arch_lwip_begin();
  if (stream != NULL && tpcb != NULL) {
    lwip_err = tcp_output(tpcb);
  }
  cyw43_arch_lwip_end();

  return lwip_err;
}

static void err_handler(void *arg, err_t err) {
  tcp_stream_t *stream = (tcp_stream_t *)arg;

  cyw43_arch_lwip_begin();
  if (stream) {
    struct tcp_pcb *pcb = stream->pcb;
    struct pbuf *rx_pbuf = stream->rx_pbuf;
    memset(stream, 0, sizeof(tcp_stream_t));
    if (pcb && err != ERR_ABRT) {
      tcp_close(pcb);
    }
    if (rx_pbuf) {
      pbuf_free(rx_pbuf);
    }
  }
  cyw43_arch_lwip_end();
}

static err_t connected_handler(void *arg, struct tcp_pcb *tpcb, err_t err) {
  tcp_stream_t *stream = (tcp_stream_t *)arg;
  if (err != ERR_OK) {
    return err;
  }
  stream->connected = true;
  return ERR_OK;
}

void tcp_stream_init(tcp_stream_t *stream) {
  if (stream) {
    memset(stream, 0, sizeof(tcp_stream_t));
  }
}

err_t tcp_stream_connect_ipv4(tcp_stream_t *stream, const char *peer_ipv4,
                              uint16_t port, uint32_t timeout_ms) {
  stream->pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
  if (!stream->pcb) {
    DEBUG_printf("Failed to allocate for tcp_pcb\n");
    return ERR_MEM;
  }
  stream->connected = false;

  // set the callbacks
  tcp_arg(stream->pcb, stream);
  tcp_poll(stream->pcb, poll_handler, CYW43_LWIP_TCP_TICK);
  tcp_sent(stream->pcb, sent_handler);
  tcp_recv(stream->pcb, recv_handler);
  tcp_err(stream->pcb, err_handler);

  // convert address
  if (ip4addr_aton(peer_ipv4, &stream->peer_addr) != 1) {
    WARNING_printf("%s is not a valid IPv4 address\n", peer_ipv4);
    return ERR_ARG;
  }
  DEBUG_printf("Connecting to %s:%d\n", ip4addr_ntoa(&stream->peer_addr), port);

  // connect!
  err_t lwip_err =
      tcp_connect(stream->pcb, &stream->peer_addr, port, connected_handler);
  if (lwip_err != ERR_OK) {
    return lwip_err;
  }
  uint32_t elapsed = 0;
  while (!stream->connected && elapsed < timeout_ms) {
    cyw43_arch_poll();
    sleep_ms(10);
    elapsed += 10;
  }
  cyw43_arch_lwip_end();
  if (!stream->connected) {
    return ERR_TIMEOUT;
  }
  return ERR_OK;
}

/**
 * Return true if there is data to read
 */
bool tcp_stream_can_read(tcp_stream_t *stream) {
  if (!stream || !stream->pcb) {
    return false;
  }
  return (stream->rx_pbuf != NULL);
}

err_t tcp_stream_read(tcp_stream_t *stream, uint8_t *buf, size_t bufcap,
                      size_t *outlen, uint32_t timeout_ms) {
  err_t lwip_err = ERR_OK;
  cyw43_arch_lwip_begin();
  if (stream == NULL || buf == NULL || bufcap == 0) {
    lwip_err = ERR_ARG;
  } else if (stream->pcb == NULL) {
    // TODO: how to distinguish between "connection closed" and "waiting"
    lwip_err = ERR_CLSD;
  } else if (stream->rx_pbuf != NULL) {
    // there is data to read, so read and exit
    uint16_t remaining_len = stream->rx_pbuf->tot_len - stream->rx_offset;
    size_t copylen = MIN(remaining_len, bufcap);
    *outlen =
        pbuf_copy_partial(stream->rx_pbuf, buf, copylen, stream->rx_offset);
    tcp_recved(stream->pcb, *outlen);
    if (stream->rx_pbuf->tot_len == *outlen + stream->rx_offset) {
      pbuf_free(stream->rx_pbuf);
      stream->rx_pbuf = NULL;
      stream->rx_offset = 0;
    } else {
      stream->rx_offset += *outlen;
    }
  } else {
    // there is no data to read
    // TODO: for now, just exit, but later we should implement timeout
    *outlen = 0;
  }
  cyw43_arch_lwip_end();
  return lwip_err;
}

err_t tcp_stream_write(tcp_stream_t *stream, const uint8_t *data,
                       size_t data_len, size_t *written_len,
                       uint32_t timeout_ms) {
  err_t lwip_err = ERR_OK;
  cyw43_arch_lwip_begin();
  if (stream == NULL || data == NULL) {
    lwip_err = ERR_ARG;
  } else if (stream->pcb == NULL) {
    lwip_err = ERR_CLSD;
  } else if (data_len == 0) {
    *written_len = 0;
  } else {
    // tcp_sndbuf usage is described here:
    // https://www.nongnu.org/lwip/2_1_x/group__tcp__raw.html#ga6b2aa0efbf10e254930332b7c89cd8c5
    tcpwnd_size_t send_buflen = tcp_sndbuf(stream->pcb);
    if ((int16_t)send_buflen == ERR_MEM || send_buflen == 0) {
      // write buffer is currently full
      *written_len = 0;
    } else {
      size_t write_len = MIN(send_buflen, data_len);
      lwip_err = tcp_write(stream->pcb, data, write_len, TCP_WRITE_FLAG_COPY);
      if (lwip_err == ERR_OK) {
        *written_len = write_len;
      } else if (lwip_err == ERR_MEM) {
        *written_len = 0;
      }
    }
  }
  cyw43_arch_lwip_end();
  return lwip_err;
}

void tcp_stream_flush(tcp_stream_t *stream) {
  cyw43_arch_lwip_begin();
  if (stream != NULL && stream->pcb != NULL) {
    tcp_output(stream->pcb);
  }
  cyw43_arch_lwip_end();
}

err_t tcp_stream_close(tcp_stream_t *stream) {
  err_t err = ERR_OK;

  if (stream->pcb) {
    tcp_arg(stream->pcb, NULL);
    tcp_poll(stream->pcb, NULL, 0);
    tcp_sent(stream->pcb, NULL);
    tcp_recv(stream->pcb, NULL);
    tcp_err(stream->pcb, NULL);
    err = tcp_close(stream->pcb);
    if (err != ERR_OK) {
      WARNING_printf("Failed to close stream pcb (err %d), aborting\n", err);
      tcp_abort(stream->pcb);
      err = ERR_ABRT;
    }
    stream->pcb = NULL;
  }
  if (stream->rx_pbuf) {
    pbuf_free(stream->rx_pbuf);
  }

  memset(stream, 0, sizeof(tcp_stream_t));
  return err;
}

static int test_tcp_stream(tcp_stream_t *stream) {
  if (!stream || !stream->pcb || !stream->connected) {
    return 1;
  }
  uint8_t app_rx_buf[TEST_MSG_MAX_SIZE];
  uint8_t app_tx_buf[TEST_MSG_MAX_SIZE];
  err_t send_err = ERR_OK, recv_err = ERR_OK;
  size_t send_tot_len, send_len, recv_tot_len, recv_len;

  for (size_t msglen = TEST_MSG_MIN_SIZE; msglen <= sizeof(app_rx_buf);
       msglen = msglen << 1) {
    send_tot_len = 0;
    recv_tot_len = 0;
    DEBUG_printf("testing read/write size %zu\n", msglen);
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
      cyw43_arch_poll();
    }
    if (send_err == ERR_OK) {
      DEBUG_printf("Successfully sent %zu bytes\n", send_tot_len);
    } else {
      WARNING_printf("Failed to send %zu bytes (err %d)\n", msglen, send_err);
    }

    while (recv_err == ERR_OK && recv_tot_len < msglen) {
      recv_err = tcp_stream_read(stream, app_rx_buf + recv_tot_len,
                                 msglen - recv_tot_len, &recv_len, 0);
      if (recv_err == ERR_OK) {
        recv_tot_len += recv_len;
      }
      cyw43_arch_poll();
    }

    uint8_t diff = 0;
    for (size_t i = 0; i < msglen; i++) {
      diff |= app_rx_buf[i] ^ app_tx_buf[i];
    }
    if (diff) {
      WARNING_printf("Reflection failed at msglen=%zu\n", msglen);
      return 1;
    }
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

    sleep_ms(10000);
  }
}

#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <pico/cyw43_arch.h>
#include <pico/stdio.h>
#include <stdint.h>

#include "pico-pqtls/utils.h"

typedef struct tcp_stream {
  struct tcp_pcb *pcb;
  struct pbuf *rx_pbuf;
  uint16_t rx_offset;
} tcp_stream_t;

static err_t connected_handler(void *arg, struct tcp_pcb *tpcb, err_t err);

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

  while (1) {
    ensure_wifi_connection_blocking(WIFI_SSID, WIFI_PASSWORD,
                                    CYW43_AUTH_WPA2_AES_PSK);
    sleep_ms(1000);
  }
}

#include "pico-pqtls/colonytcp.h"
#include "pico-pqtls/utils.h"
#include <lwip/err.h>

/**
 * One can tell that peer has hung by if this callback is invoked with a NULL pbuf
 */
static err_t recv_handler(void *arg, struct tcp_pcb *tpcb, struct pbuf *p,
                          err_t err) {
  tcp_stream_t *stream = (tcp_stream_t *)arg;
  err_t lwip_err = ERR_OK;

  cyw43_arch_lwip_begin();
  cyw43_arch_poll();
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
  } else if (!p) {
    // peer hung up
    stream->terminated = true;
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
  cyw43_arch_poll();
  if (stream != NULL && tpcb != NULL) {
    lwip_err = tcp_output(tpcb);
  }
  cyw43_arch_lwip_end();

  return lwip_err;
}

static void err_handler(void *arg, err_t err) {
  tcp_stream_t *stream = (tcp_stream_t *)arg;

  cyw43_arch_lwip_begin();
  cyw43_arch_poll();
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
    WARNING_printf("Failed to allocate for tcp_pcb\n");
    return ERR_MEM;
  }
  stream->connected = false;

  // set the callbacks
  tcp_arg(stream->pcb, stream);
  tcp_poll(stream->pcb, poll_handler, COLONY_TCP_TICK);
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
  cyw43_arch_lwip_begin();
  cyw43_arch_poll();
  if (!stream || !stream->pcb) {
    return false;
  }
  bool ready = (stream->rx_pbuf != NULL);
  cyw43_arch_lwip_end();
  return ready;
}

err_t tcp_stream_read(tcp_stream_t *stream, uint8_t *buf, size_t bufcap,
                      size_t *outlen, uint32_t timeout_ms) {
  err_t lwip_err = ERR_OK;
  cyw43_arch_lwip_begin();
  cyw43_arch_poll();
  if (stream == NULL || buf == NULL || bufcap == 0) {
    lwip_err = ERR_ARG;
  } else if (stream->pcb == NULL) {
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
  } else if (stream->terminated) {
    // there is no data to read, and peer has hung up
    *outlen = 0;
    lwip_err = ERR_CLSD;
  } else {
    // there is no data to read, but peer has not hung up
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
  cyw43_arch_poll();
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
  cyw43_arch_poll();
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
    stream->rx_pbuf = NULL;
  }

  memset(stream, 0, sizeof(tcp_stream_t));
  return err;
}

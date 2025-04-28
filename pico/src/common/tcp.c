#include "pico-pqtls/tcp.h"
#include "pico-pqtls/utils.h"
#include <lwip/dns.h>
#include <lwip/err.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>
#include <pico/time.h>
#include <pico/types.h>
#include <string.h>


/**
 * One can tell that peer has hung by if this callback is invoked with a NULL
 * pbuf
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
  if (!stream || !stream->pcb || stream->terminated) {
    return false;
  }
  bool ready = (stream->rx_pbuf != NULL);
  cyw43_arch_lwip_end();
  return ready;
}

/**
 * Will block if peer does not hang up but no data comes through
 */
err_t tcp_stream_read(tcp_stream_t *stream, uint8_t *buf, size_t bufcap,
                      size_t *outlen) {
  err_t lwip_err = ERR_OK;
  cyw43_arch_lwip_begin();
  cyw43_arch_poll();
  if (stream == NULL || buf == NULL || bufcap == 0) {
    lwip_err = ERR_ARG;
    goto finish_read;
  }
  if (stream->pcb == NULL) {
    lwip_err = ERR_CLSD;
    goto finish_read;
  }
  while (stream->rx_pbuf == NULL && !stream->terminated) {
    // TODO: get rid of this busy waiting
    cyw43_arch_poll();
    // sleep_ms(1);
  }
  if (stream->rx_pbuf != NULL) {
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
    CRITICAL_printf("unreachable!\n");
    exit(-1);
  }

finish_read:
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

static void dns_handler(const char *name, const ip_addr_t *ipaddr, void *arg) {
  dns_result_t *dns_res = (dns_result_t *)arg;
  if (ipaddr) {
    dns_res->addr = *ipaddr;
    dns_res->resolved = true;
  } else {
    dns_res->resolved = false;
  }
  dns_res->complete = true;
}

void dns_result_init(dns_result_t *res) {
  ip_addr_set_zero(&res->addr);
  res->resolved = false;
  res->complete = false;
}

/**
 * Block until callback is called. Check dns_res->resolved for success or not
 */
void dns_gethostbyname_blocking(const char *hostname, dns_result_t *dns_res) {
  err_t err = dns_gethostbyname(hostname, &dns_res->addr, dns_handler, dns_res);
  if (err == ERR_OK) {
    // DNS record has been cached, no need to check callback
    dns_res->complete = true;
    dns_res->resolved = true;
    return;
  } else if (err == ERR_INPROGRESS) {
    // Wait for callback
    while (!dns_res->complete) {
      cyw43_arch_poll();
      sleep_ms(1);
    }
  } else {
    CRITICAL_printf("Unhandled error (err %d)!\n", err);
    exit(-1);
  }
}

static void ntp_resp_handler(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                             const ip_addr_t *peer_addr, u16_t peer_port) {
  ntp_client_t *client = (ntp_client_t *)arg;
  client->processed = true;
  client->abs_time_at_ntp_resp = get_absolute_time();
  if (p->tot_len != NTP_MSG_LEN) {
    WARNING_printf("UDP response length %d, expected %d\n", p->tot_len,
                   NTP_MSG_LEN);
    client->ntp_err = ERR_VAL;
    goto cleanup;
  }
  uint8_t *payload = (uint8_t *)(p->payload);
  uint8_t resp_mode = payload[0] & NTP_MODE_MASK;
  uint8_t resp_stratum = payload[1];

  if (!ip_addr_cmp(&client->ntp_ipaddr, peer_addr)) {
    WARNING_printf("Mismatched IP addr: expect %s found %s\n",
                   ip4addr_ntoa(&client->ntp_ipaddr), ip4addr_ntoa(peer_addr));
    client->ntp_err = ERR_VAL;
    goto cleanup;
  }
  if (peer_port != client->ntp_port) {
    WARNING_printf("Mismatched Port: expect %d found %d\n", client->ntp_port,
                   peer_port);
    client->ntp_err = ERR_VAL;
    goto cleanup;
  }
  if (resp_mode != NTP_MODE_SERVER) {
    WARNING_printf("Unexpected NTP mode: expect %d found %d\n", NTP_MODE_SERVER,
                   resp_mode);
    client->ntp_err = ERR_VAL;
    goto cleanup;
  }
  if (resp_stratum == NTP_STRATUM_INVALID) {
    WARNING_printf("Invalid NTP stratum\n");
    client->ntp_err = ERR_VAL;
    goto cleanup;
  }
  client->ntp_err = ERR_OK;
  uint8_t seconds_buf[4] = {0};
  pbuf_copy_partial(p, seconds_buf, sizeof(seconds_buf), 40);
  uint32_t seconds_since_1900 = seconds_buf[0] << 24 | seconds_buf[1] << 16 |
                                seconds_buf[2] << 8 | seconds_buf[3];
  uint32_t seconds_since_1970 = seconds_since_1900 - NTP_DELTA_SECONDS;
  client->epoch = seconds_since_1970;
  INFO_printf("got ntp response: %llu\n", client->epoch);

cleanup:
  pbuf_free(p);
}

err_t ntp_client_init(ntp_client_t *client, ip_addr_t ntp_ipaddr,
                      uint16_t ntp_port) {
  client->ntp_ipaddr = ntp_ipaddr;
  client->ntp_port = ntp_port;
  client->processed = false;
  client->pcb = udp_new_ip_type(IPADDR_TYPE_V4);
  if (!client->pcb) {
    CRITICAL_printf("Failed to allocate for NTP's UDP control block\n");
    return ERR_MEM;
  }
  udp_recv(client->pcb, ntp_resp_handler, client);
  return ERR_OK;
}

void ntp_client_close(ntp_client_t *client) {
  if (client->pcb) {
    udp_remove(client->pcb);
    client->pcb = NULL;
  }
}

/**
 * This method will handle the UDP PCB
 */
err_t ntp_client_sync_timeout_ms(ntp_client_t *client, uint32_t timeout_ms) {
  cyw43_arch_lwip_begin();
  cyw43_arch_poll();
  struct pbuf *ntp_req = pbuf_alloc(PBUF_TRANSPORT, NTP_MSG_LEN, PBUF_RAM);
  if (!ntp_req) {
    WARNING_printf("Failed to allocate %d pbuf\n", NTP_MSG_LEN);
    return ERR_MEM;
  }
  uint8_t *payload = (uint8_t *)ntp_req->payload;
  memset(payload, 0, NTP_MSG_LEN);
  payload[0] = NTP_LI_NO_WARNING | NTP_VN_VERSION_3 | NTP_MODE_CLIENT;
  udp_sendto(client->pcb, ntp_req, &client->ntp_ipaddr, client->ntp_port);
  pbuf_free(ntp_req);
  cyw43_arch_lwip_end();

  uint32_t timeout_begin = to_ms_since_boot(get_absolute_time());
  while ((to_ms_since_boot(get_absolute_time()) - timeout_begin) < timeout_ms &&
         !client->processed) {
    cyw43_arch_poll();
    sleep_ms(1);
  }

  if (!client->processed) {
    return ERR_TIMEOUT;
  }
  return client->ntp_err;
}

/**
 * Return the current time
 */
time_t get_current_epoch(ntp_client_t *client) {
  uint64_t diff_us =
      absolute_time_diff_us(client->abs_time_at_ntp_resp, get_absolute_time());
  return client->epoch + (us_to_ms(diff_us) / 1000u);
}

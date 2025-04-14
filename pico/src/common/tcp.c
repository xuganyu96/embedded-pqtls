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

static void tcp_stream_flush_send_buffer(PICO_PQTLS_tcp_stream_t *stream) {
  if (!stream || !stream->connected || stream->tx_buflen == 0)
    return;

  while (stream->tx_buf_sent < stream->tx_buflen) {
    size_t unsent = stream->tx_buflen - stream->tx_buf_sent;
    size_t can_send = tcp_sndbuf(stream->tcp_pcb);

    size_t chunk = MIN(unsent, can_send);
    if (chunk == 0)
      break;

    err_t err = tcp_write(stream->tcp_pcb, stream->tx_buf + stream->tx_buf_sent,
                          chunk, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK)
      break;

    stream->tx_buf_sent += chunk;
  }

  tcp_output(stream->tcp_pcb);

  // If all sent, reset buffer
  if (stream->tx_buf_sent == stream->tx_buflen) {
    stream->tx_buf_sent = 0;
    stream->tx_buflen = 0;
  }
}

/**
 * The polling callback in lwIP is your chance to handle periodic tasks for a
 * TCP connection—especially when the connection is idle:
 * - Tries to send unsent data (if any).
 * - Optionally closes the connection if the job is complete.
 * - Uses tcp_output() to push data down the stack.
 */
static err_t tcp_stream_poll(void *arg, struct tcp_pcb *tpcb) {
  // DEBUG_printf("tcp_stream_poll\n");
  cyw43_arch_poll();
  PICO_PQTLS_tcp_stream_t *stream = (PICO_PQTLS_tcp_stream_t *)arg;
  tcp_stream_flush_send_buffer(stream);

  // // If everything has been sent and marked complete, close the connection
  // if (state->complete && state->sent_len >= state->buffer_len) {
  //   tcp_arg(tpcb, NULL);
  //   tcp_sent(tpcb, NULL);
  //   tcp_recv(tpcb, NULL);
  //   tcp_err(tpcb, NULL);
  //   tcp_poll(tpcb, NULL, 0);
  //   tcp_close(tpcb);
  //   return ERR_OK;
  // }
  return ERR_OK;
}

static err_t tcp_stream_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
  PICO_PQTLS_tcp_stream_t *stream = (PICO_PQTLS_tcp_stream_t *)arg;
  tcp_stream_flush_send_buffer(stream);
  return ERR_OK;
}

static err_t tcp_stream_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p,
                             err_t err) {
  PICO_PQTLS_tcp_stream_t *stream = (PICO_PQTLS_tcp_stream_t *)arg;
  cyw43_arch_poll();
  if (!p) { // peer has hung up
    stream->complete = true;
    return ERR_OK;
  }
  size_t to_copy = MIN(TCP_STREAM_BUF_SIZE - stream->rx_buflen, p->tot_len);
  if (to_copy > 0) {
    pbuf_copy_partial(p, stream->rx_buf + stream->rx_buflen, to_copy, 0);
    stream->rx_buflen += to_copy;
    tcp_recved(tpcb, to_copy);
  }
  // TODO: if to_copy is less than p->tot_len, then freeing pbuf_free will cause
  // uncopied data to be lost. Need to find a way to process these data.
  pbuf_free(p);
  return ERR_OK;
}

static void tcp_stream_err(void *arg, err_t err) {
  PICO_PQTLS_tcp_stream_t *stream = (PICO_PQTLS_tcp_stream_t *)arg;
  stream->connected = false;
  stream->complete = true;
  if (err != ERR_ABRT) {
    DEBUG_printf("Non-abort error (err %d)\n", err);
  }
}

static err_t tcp_stream_connected(void *arg, struct tcp_pcb *tpcb, err_t err) {
  // DEBUG_printf("callback: tcp_stream_connected\n");
  PICO_PQTLS_tcp_stream_t *stream = (PICO_PQTLS_tcp_stream_t *)arg;
  if (err != ERR_OK) {
    DEBUG_printf("connect failed %d\n", err);
    return err;
  }
  stream->connected = true;
  cyw43_arch_poll();
  return ERR_OK;
}

PICO_PQTLS_tcp_stream_t *PICO_PQTLS_tcp_stream_new(void) {
  PICO_PQTLS_tcp_stream_t *stream = malloc(sizeof(PICO_PQTLS_tcp_stream_t));
  if (!stream) {
    DEBUG_printf("Failed to allocate for stream\n");
    return NULL;
  }
  // memset(stream, 0, sizeof(PICO_PQTLS_tcp_stream_t));
  // DEBUG_printf("IP address type: %d\n", IPADDR_TYPE_V4);
  stream->tcp_pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
  if (!stream->tcp_pcb) {
    DEBUG_printf("Failed to allocate for tcp_pcb\n");
    free(stream);
    return NULL;
  }
  stream->rx_buflen = 0;
  stream->tx_buflen = 0;
  stream->complete = false;
  stream->connected = false;

  // set the callbacks
  tcp_arg(stream->tcp_pcb, stream);
  tcp_poll(stream->tcp_pcb, tcp_stream_poll, 10);
  tcp_sent(stream->tcp_pcb, tcp_stream_sent);
  tcp_recv(stream->tcp_pcb, tcp_stream_recv);
  tcp_err(stream->tcp_pcb, tcp_stream_err);

  return stream;
}

void PICO_PQTLS_tcp_stream_free(PICO_PQTLS_tcp_stream_t *stream) {
  if (stream) {
    free(stream);
  }
}

/**
 * If fail, caller is responsible for freeing the stream with
 * PICO_PQTLS_tcp_stream_free()
 */
err_t PICO_PQTLS_tcp_stream_connect_timeout_ms(PICO_PQTLS_tcp_stream_t *stream,
                                               const char *server_ipv4,
                                               uint16_t port,
                                               uint32_t timeout_ms) {
  err_t err = ERR_OK;
  if (ip4addr_aton(server_ipv4, &stream->remote_addr) != 1) {
    DEBUG_printf("%s is not valid address\n", server_ipv4);
    return ERR_ARG;
  }
  cyw43_arch_lwip_begin();
  DEBUG_printf("Connecting to %s:%d\n", ip4addr_ntoa(&stream->remote_addr),
               port);
  err = tcp_connect(stream->tcp_pcb, &stream->remote_addr, port,
                    tcp_stream_connected);
  if (err != ERR_OK) {
    // no need to wait for connection callback, but clean up of pcb and stream
    // will be left to the user calling tcp_stream_close(stream)
    return err;
  }
  // continue polling until the callback is executed
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
  return err;
}

PICO_PQTLS_tcp_err_t PICO_PQTLS_tcp_stream_read(PICO_PQTLS_tcp_stream_t *stream,
                                                uint8_t *buf, size_t buflen,
                                                size_t *outlen,
                                                uint32_t timeout) {
  if (!stream || !stream->connected || !buf || buflen == 0 || !outlen)
    return TCP_RESULT_ERROR;

  absolute_time_t start = get_absolute_time();

  while (stream->rx_buflen == 0 && !stream->complete) {
    cyw43_arch_poll();
    if (timeout > 0 &&
        to_ms_since_boot(get_absolute_time()) - to_ms_since_boot(start) >
            timeout) {
      return TCP_RESULT_TIMEOUT;
    }
    sleep_ms(1);
  }

  if (stream->rx_buflen == 0 && stream->complete) {
    return TCP_RESULT_EOF;
  }
  size_t to_copy = MIN(buflen, stream->rx_buflen);
  memcpy(buf, stream->rx_buf, to_copy);
  memmove(stream->rx_buf, stream->rx_buf + to_copy,
          stream->rx_buflen - to_copy);
  stream->rx_buflen -= to_copy;
  *outlen = to_copy;
  return TCP_RESULT_OK;
}

PICO_PQTLS_tcp_err_t
PICO_PQTLS_tcp_stream_read_exact(PICO_PQTLS_tcp_stream_t *stream, uint8_t *dst,
                                 size_t len, uint32_t timeout_ms) {
  size_t total = 0;

  while (total < len) {
    size_t n = 0;
    PICO_PQTLS_tcp_err_t result = PICO_PQTLS_tcp_stream_read(
        stream, dst + total, len - total, &n, timeout_ms);
    if (result == TCP_RESULT_OK) {
      total += n;
    } else if (result == TCP_RESULT_TIMEOUT || result == TCP_RESULT_ERROR) {
      return result;
    } else if (result == TCP_RESULT_EOF) {
      return TCP_RESULT_EOF;
    }
  }

  return TCP_RESULT_OK;
}

// TODO: Add tcp_stream_flush() and let callers choose when to flush. Only flush
// automatically on: timeouts, buffer full, or stream close
PICO_PQTLS_tcp_err_t
PICO_PQTLS_tcp_stream_write(PICO_PQTLS_tcp_stream_t *stream,
                            const uint8_t *data, size_t len,
                            uint32_t timeout_ms) {
  if (!stream || !stream->connected || !data || len == 0) {
    return TCP_RESULT_ERROR;
  }

  size_t total_sent = 0;
  absolute_time_t start = get_absolute_time();

  while (total_sent < len) {
    // Determine space in the buffer
    size_t space = TCP_STREAM_BUF_SIZE - stream->tx_buflen;
    if (space == 0) {
      // Give lwip time to asynchronously call tcp_stream_sent, which will flush
      // unsent data and reset stream->tx_buflen to 0
      cyw43_arch_poll();
      err_t err = tcp_output(stream->tcp_pcb);
      if (err != ERR_OK)
        return TCP_RESULT_ERROR;
      // TODO: Use sleep_us(100) or exponential backoff for better performance
      // vs CPU usage.
      sleep_ms(1);
      if (timeout_ms > 0 &&
          absolute_time_diff_us(start, get_absolute_time()) / 1000 >=
              timeout_ms) {
        return TCP_RESULT_TIMEOUT;
      }
      continue;
    }

    // Copy as much as we can into the TX buffer
    size_t to_copy = MIN(len - total_sent, space);
    memcpy(stream->tx_buf + stream->tx_buflen, data + total_sent, to_copy);
    stream->tx_buflen += to_copy;
    total_sent += to_copy;

    // Try to write to TCP
    size_t send_now = stream->tx_buflen;
    err_t err = tcp_write(stream->tcp_pcb, stream->tx_buf, send_now,
                          TCP_WRITE_FLAG_COPY);

    if (err == ERR_OK) {
      stream->tx_buflen = 0;
      tcp_output(stream->tcp_pcb);
    } else if (err == ERR_MEM) {
      // Not enough room in TCP buffer, wait a bit
      sleep_ms(1);
      if (timeout_ms > 0 &&
          absolute_time_diff_us(start, get_absolute_time()) / 1000 >=
              timeout_ms) {
        return TCP_RESULT_TIMEOUT;
      }
    } else {
      return TCP_RESULT_ERROR;
    }
  }

  return TCP_RESULT_OK;
}

/**
 * This method will free the stream on success
 */
err_t PICO_PQTLS_tcp_stream_close(PICO_PQTLS_tcp_stream_t *stream) {
  err_t err = ERR_OK;

  if (stream->tcp_pcb) {
    tcp_arg(stream->tcp_pcb, stream);
    tcp_poll(stream->tcp_pcb, NULL, 0);
    tcp_sent(stream->tcp_pcb, NULL);
    tcp_recv(stream->tcp_pcb, NULL);
    tcp_err(stream->tcp_pcb, NULL);
    // tcp_close will free the pcb
    err = tcp_close(stream->tcp_pcb);
    if (err != ERR_OK) {
      DEBUG_printf("close failed %d, calling abort\n", err);
      // tcp_abort will free the pcb
      tcp_abort(stream->tcp_pcb);
      err = ERR_ABRT;
    }
    stream->tcp_pcb = NULL;
  }
  PICO_PQTLS_tcp_stream_free(stream);
  return err;
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

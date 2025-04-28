/**
 * TCP stack copied from colony.pico by John T. Taylor
 */
#ifndef COLONY_TCP_H
#define COLONY_TCP_H
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

// the number of interval (0.5s per interval) between calling tcp_poll
#define COLONY_TCP_TICK 1

typedef struct tcp_stream {
  struct tcp_pcb *pcb;
  ip_addr_t peer_addr;
  struct pbuf *rx_pbuf;
  uint16_t rx_offset;
  // This flag is turned on if `tcp_recv` callback is called with a NULL pbuf
  bool terminated;
  // This flag is flipped at the `connected` callback
  bool connected;
} tcp_stream_t;

void tcp_stream_init(tcp_stream_t *stream);
err_t tcp_stream_connect_ipv4(tcp_stream_t *stream, const char *peer_ipv4,
                              uint16_t port, uint32_t timeout_ms);
bool tcp_stream_can_read(tcp_stream_t *stream);
err_t tcp_stream_read(tcp_stream_t *stream, uint8_t *buf, size_t bufcap,
                      size_t *outlen);
err_t tcp_stream_write(tcp_stream_t *stream, const uint8_t *data,
                       size_t data_len, size_t *written_len,
                       uint32_t timeout_ms);
void tcp_stream_flush(tcp_stream_t *stream);
err_t tcp_stream_close(tcp_stream_t *stream);

#endif // #ifndef COLONY_TCP_H

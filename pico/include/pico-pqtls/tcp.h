#ifndef PICO_PQTLS_TCP_H
#define PICO_PQTLS_TCP_H

#include <lwip/err.h>
#include <lwip/ip_addr.h>
#include <lwip/tcp.h>
#include <stdbool.h>
#include <stdint.h>

#define TCP_CONNECT_TIMEOUT_MS 10000
#define TCP_READ_TIMEOUT_MS 10000
#define TCP_WRITE_TIMEOUT_MS 10000

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

typedef struct dns_result {
  ip_addr_t addr;
  // remote hostname has been successfully found, addr can be used
  bool resolved;
  // DNS resolution is complete
  bool complete;
} dns_result_t;

void dns_result_init(dns_result_t *res);
void dns_gethostbyname_blocking(const char *hostname, dns_result_t *dns_res);

#define NTP_TIMEOUT_MS (10 * 1000)
#define NTP_DELTA_SECONDS 2208988800 // seconds between 1900 and 1970
#define NTP_HOSTNAME "pool.ntp.org"
#define NTP_PORT 123
#define NTP_MSG_LEN 48
#define NTP_STRATUM_INVALID 0
#define NTP_MODE_SERVER 4
#define NTP_MODE_CLIENT 0b00000011
#define NTP_MODE_MASK 0x7
#define NTP_LI_NO_WARNING 0
#define NTP_VN_VERSION_3 0b00011000

typedef struct ntp_client {
  ip_addr_t ntp_ipaddr;
  uint16_t ntp_port;
  struct udp_pcb *pcb;
  // whether NTP response has been processed
  bool processed;
  // indicate the status of the NTP sync
  err_t ntp_err;
  // The UNIX timestamp (seconds since 1970) received from NTP
  time_t epoch;
  // The output of get_absolute_time the moment when NTP response is processed
  absolute_time_t abs_time_at_ntp_resp;
} ntp_client_t;

err_t ntp_client_init(ntp_client_t *client, ip_addr_t ntp_ipaddr,
                      uint16_t ntp_port);
void ntp_client_close(ntp_client_t *client);
err_t ntp_client_sync_timeout_ms(ntp_client_t *client, uint32_t timeout_ms);
time_t get_current_epoch(ntp_client_t *client);
#endif

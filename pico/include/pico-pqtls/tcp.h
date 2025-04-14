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

// BUG: this large buffer size is not ideal (I want 2048 or 4096). However, if
// the TCP server sends a message that is longer than the TCP buffer size,
// tcp_stream_read_exact will fail. In the interest of moving the project along
// I will leave the TCP buffer to be as large as the maximal possible TLS
// message size, but in due time I will need to debug this
#define TCP_STREAM_BUF_SIZE (16992)

typedef enum PICO_PQTLS_tcp_err {
  TCP_RESULT_OK = 0,  // Success
  TCP_RESULT_TIMEOUT, // Timeout occurred
  TCP_RESULT_EOF,     // Peer closed connection (0-byte read)
  TCP_RESULT_ERROR    // General error (e.g. reset, allocation fail)
} PICO_PQTLS_tcp_err_t;

typedef struct PICO_PQTLS_tcp_stream {
  struct tcp_pcb *tcp_pcb;
  ip_addr_t remote_addr;
  uint8_t rx_buf[TCP_STREAM_BUF_SIZE];
  size_t rx_buflen;
  uint8_t tx_buf[TCP_STREAM_BUF_SIZE];
  size_t tx_buflen;
  size_t tx_buf_sent;
  bool complete;
  bool connected;
} PICO_PQTLS_tcp_stream_t;

typedef struct dns_result {
  ip_addr_t addr;
  // remote hostname has been successfully found, addr can be used
  bool resolved;
  // DNS resolution is complete
  bool complete;
} dns_result_t;

void dns_result_init(dns_result_t *res);
void dns_gethostbyname_blocking(const char *hostname, dns_result_t *dns_res);

PICO_PQTLS_tcp_stream_t *PICO_PQTLS_tcp_stream_new(void);
void PICO_PQTLS_tcp_stream_free(PICO_PQTLS_tcp_stream_t *stream);
err_t PICO_PQTLS_tcp_stream_connect_timeout_ms(PICO_PQTLS_tcp_stream_t *stream,
                                               const char *server_ipv4,
                                               uint16_t port, uint32_t timeout);
PICO_PQTLS_tcp_err_t PICO_PQTLS_tcp_stream_read(PICO_PQTLS_tcp_stream_t *stream,
                                                uint8_t *buf, size_t buflen,
                                                size_t *outlen,
                                                uint32_t timeout);
PICO_PQTLS_tcp_err_t
PICO_PQTLS_tcp_stream_read_exact(PICO_PQTLS_tcp_stream_t *stream, uint8_t *dst,
                                 size_t len, uint32_t timeout_ms);
PICO_PQTLS_tcp_err_t
PICO_PQTLS_tcp_stream_write(PICO_PQTLS_tcp_stream_t *stream,
                            const uint8_t *data, size_t len,
                            uint32_t timeout_ms);
err_t PICO_PQTLS_tcp_stream_close(PICO_PQTLS_tcp_stream_t *stream);


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

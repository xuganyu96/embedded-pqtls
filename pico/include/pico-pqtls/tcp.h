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
#endif

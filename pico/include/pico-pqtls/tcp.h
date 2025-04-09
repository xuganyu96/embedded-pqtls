#ifndef PICO_PQTLS_TCP_H
#define PICO_PQTLS_TCP_H

#include <lwip/err.h>
#include <lwip/ip_addr.h>
#include <lwip/tcp.h>
#include <stdbool.h>
#include <stdint.h>

#define TCP_STREAM_BUF_SIZE (2048)

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

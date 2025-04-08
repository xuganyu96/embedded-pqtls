#ifndef PICO_PQTLS_TCP_H
#define PICO_PQTLS_TCP_H

#include <lwip/err.h>
#include <lwip/ip_addr.h>
#include <lwip/tcp.h>
#include <stdbool.h>
#include <stdint.h>

#define BUF_SIZE (2 * 4096)

typedef struct PICO_PQTLS_tcp_stream {
  struct tcp_pcb *tcp_pcb;
  ip_addr_t remote_addr;
  uint8_t buffer[BUF_SIZE];
  int buffer_len;
  int sent_len;
  bool complete;
  int run_count;
  bool connected;
} PICO_PQTLS_tcp_stream_t;

PICO_PQTLS_tcp_stream_t *PICO_PQTLS_tcp_stream_new(void);
void PICO_PQTLS_tcp_stream_free(PICO_PQTLS_tcp_stream_t *stream);
err_t PICO_PQTLS_tcp_stream_connect(PICO_PQTLS_tcp_stream_t *stream,
                                    const char *server_ipv4, uint16_t port);
int PICO_PQTLS_tcp_stream_read(PICO_PQTLS_tcp_stream_t *stream, uint8_t *buf,
                               size_t buflen);
int PICO_PQTLS_tcp_stream_write(PICO_PQTLS_tcp_stream_t *stream,
                                const uint8_t *buf, size_t buflen);
err_t PICO_PQTLS_tcp_stream_close(PICO_PQTLS_tcp_stream_t *stream);
#endif

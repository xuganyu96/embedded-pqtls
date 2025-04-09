#include "pico-pqtls/tcp.h"
#include "pico-pqtls/utils.h"
#include <lwip/err.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <pico/cyw43_arch.h>
#include <string.h>

static err_t tcp_result(PICO_PQTLS_tcp_stream_t *sock, int status) {
  if (status == 0) {
    DEBUG_printf("test success\n");
  } else {
    DEBUG_printf("test failed %d\n", status);
  }
  sock->complete = true;
  return 0;
}

/**
 * The polling callback in lwIP is your chance to handle periodic tasks for a
 * TCP connection—especially when the connection is idle:
 * - Tries to send unsent data (if any).
 * - Optionally closes the connection if the job is complete.
 * - Uses tcp_output() to push data down the stack.
 */
static err_t tcp_stream_poll(void *arg, struct tcp_pcb *tpcb) {
  DEBUG_printf("tcp_stream_poll\n");
  // PICO_PQTLS_tcp_stream_t *state = (PICO_PQTLS_tcp_stream_t *)arg;

  // if (!state || !state->connected) {
  //   return ERR_OK;
  // }

  // // If there's unsent data, try to send it
  // if (state->sent_len < state->buffer_len) {
  //   int remaining = state->buffer_len - state->sent_len;
  //   const void *data = state->buffer + state->sent_len;

  //   err_t err = tcp_write(tpcb, data, remaining, TCP_WRITE_FLAG_COPY);
  //   if (err == ERR_OK) {
  //     state->sent_len += remaining;
  //     tcp_output(tpcb); // Push the data immediately
  //   } else if (err == ERR_MEM) {
  //     // Memory temporarily unavailable – try again later
  //     return ERR_OK;
  //   } else {
  //     // Other error – close connection
  //     tcp_abort(tpcb);
  //     return ERR_ABRT;
  //   }
  // }

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
  DEBUG_printf("callback: tcp_stream_sent %u\n", len);
  PICO_PQTLS_tcp_stream_t *state = (PICO_PQTLS_tcp_stream_t *)arg;
  state->sent_len += len;

  if (state->sent_len >= BUF_SIZE) {

    state->run_count++;
    if (state->run_count >= 999999) {
      tcp_result(arg, 0);
      return ERR_OK;
    }

    // We should receive a new buffer from the server
    state->buffer_len = 0;
    state->sent_len = 0;
    DEBUG_printf("Waiting for buffer from server\n");
  }

  return ERR_OK;
}

static err_t tcp_stream_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p,
                             err_t err) {
  DEBUG_printf("callback: tcp_stream_recv\n");
  PICO_PQTLS_tcp_stream_t *state = (PICO_PQTLS_tcp_stream_t *)arg;
  if (!p) {
    return tcp_result(arg, -1);
  }
  // this method is callback from lwIP, so cyw43_arch_lwip_begin is not
  // required, however you can use this method to cause an assertion in debug
  // mode, if this method is called when cyw43_arch_lwip_begin IS needed
  cyw43_arch_lwip_check();
  if (p->tot_len > 0) {
    DEBUG_printf("recv %d err %d\n", p->tot_len, err);
    for (struct pbuf *q = p; q != NULL; q = q->next) {
      // DUMP_BYTES(q->payload, q->len);
    }
    // Receive the buffer
    const uint16_t buffer_left = BUF_SIZE - state->buffer_len;
    state->buffer_len += pbuf_copy_partial(
        p, state->buffer + state->buffer_len,
        p->tot_len > buffer_left ? buffer_left : p->tot_len, 0);
    tcp_recved(tpcb, p->tot_len);
  }
  pbuf_free(p);

  // If we have received the whole buffer, send it back to the server
  if (state->buffer_len == BUF_SIZE) {
    DEBUG_printf("Writing %d bytes to server\n", state->buffer_len);
    err_t err =
        tcp_write(tpcb, state->buffer, state->buffer_len, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK) {
      DEBUG_printf("Failed to write data %d\n", err);
      return tcp_result(arg, -1);
    }
  }
  return ERR_OK;
}

static void tcp_stream_err(void *arg, err_t err) {
  DEBUG_printf("callback: tcp_stream_err\n");
  if (err != ERR_ABRT) {
    DEBUG_printf("tcp_stream_err %d\n", err);
    tcp_result(arg, err);
  }
}

static err_t tcp_stream_connected(void *arg, struct tcp_pcb *tpcb, err_t err) {
  DEBUG_printf("callback: tcp_stream_connected\n");
  PICO_PQTLS_tcp_stream_t *stream = (PICO_PQTLS_tcp_stream_t *)arg;

  if (err != ERR_OK) {
    DEBUG_printf("connect failed %d\n", err);
    return tcp_result(arg, err);
  }
  stream->connected = true;
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
  stream->buffer_len = 0;
  stream->sent_len = 0;
  stream->complete = false;
  stream->run_count = 0;
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
    if (stream->tcp_pcb) {
      free(stream->tcp_pcb);
    }
    free(stream);
  }
}

/**
 * If fail, caller is responsible for freeing the stream with
 * PICO_PQTLS_tcp_stream_free()
 */
err_t PICO_PQTLS_tcp_stream_connect(PICO_PQTLS_tcp_stream_t *stream,
                                    const char *server_ipv4, uint16_t port) {
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
  DEBUG_printf("tcp_connect returned %d\n", err);
  cyw43_arch_lwip_end();
  return err;
}

int PICO_PQTLS_tcp_stream_read(PICO_PQTLS_tcp_stream_t *stream, uint8_t *buf,
                               size_t buflen);
int PICO_PQTLS_tcp_stream_write(PICO_PQTLS_tcp_stream_t *stream,
                                const uint8_t *buf, size_t buflen);

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

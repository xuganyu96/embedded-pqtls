#include <wolfssl/wolfcrypt/settings.h>

#include <lwip/ip4_addr.h>
#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>
#include <stdio.h>
#include <stdlib.h>

#include <wolfssl/ssl.h>

#include "pico-pqtls/tcp.h"
#include "pico-pqtls/utils.h"
#include "wolfssl/wolfio.h"

#define TLS_MAX_BUFFER_LEN (16992)
#define SLEEP_MS (30 * 1000) // do not DoS the remote host

#define REMOTE_HOSTNAME "api.github.com"
#define HTTPS_PORT 443
#define HTTP_REQUEST                                                           \
  "GET /octocat HTTP/1.1\r\n"                                                  \
  "Host: api.github.com\r\n"                                                   \
  "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) "       \
  "Gecko/20100101 Firefox/136.0\r\n"                                           \
  "Accept: application/json\r\n"                                               \
  "Connection: close\r\n\r\n"

/**
 * WolfSSL will call this when it wants to read stuff
 */
int wolfssl_recv_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  if (!ctx || !buf || sz <= 0)
    return WOLFSSL_CBIO_ERR_GENERAL;

  PICO_PQTLS_tcp_stream_t *stream = (PICO_PQTLS_tcp_stream_t *)ctx;
  size_t outlen = 0;

  PICO_PQTLS_tcp_err_t err = PICO_PQTLS_tcp_stream_read(
      stream, (uint8_t *)buf, (size_t)sz, &outlen, TCP_READ_TIMEOUT_MS);

  if (err == TCP_RESULT_OK) {
    return (int)outlen; // partial reads are OK
  } else if (err == TCP_RESULT_TIMEOUT) {
    return WOLFSSL_CBIO_ERR_WANT_READ;
  } else if (err == TCP_RESULT_EOF) {
    return 0; // graceful close
  } else {
    return WOLFSSL_CBIO_ERR_GENERAL;
  }
}

/**
 * WolfSSL will call this when it wants to write stuff
 */
int wolfssl_send_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  if (!ctx || !buf || sz <= 0)
    return WOLFSSL_CBIO_ERR_GENERAL;

  PICO_PQTLS_tcp_stream_t *stream = (PICO_PQTLS_tcp_stream_t *)ctx;

  PICO_PQTLS_tcp_err_t err = PICO_PQTLS_tcp_stream_write(
      stream, (const uint8_t *)buf, (size_t)sz, TCP_WRITE_TIMEOUT_MS);

  if (err == TCP_RESULT_OK) {
    return sz; // we always try to write all `sz` bytes
  } else if (err == TCP_RESULT_TIMEOUT) {
    return WOLFSSL_CBIO_ERR_WANT_WRITE;
  } else {
    return WOLFSSL_CBIO_ERR_GENERAL;
  }
}

int main(void) {
  stdio_init_all();
  if (cyw43_arch_init()) {
    printf("cyw43_arch_init failed\n");
    return -1;
  }
  cyw43_arch_enable_sta_mode();

  WOLFSSL_CTX *ssl_ctx = NULL;
  WOLFSSL *ssl = NULL;
  int ssl_err;
  wolfSSL_Init();
  wolfSSL_Debugging_ON();

  dns_result_t dns_res;
  err_t lwip_err;

  uint8_t http_buf[8192];
  size_t http_buflen = 0;
  size_t readlen, sendlen;

  while (1) {
    ensure_wifi_connection_blocking(WIFI_SSID, WIFI_PASSWORD,
                                    CYW43_AUTH_WPA2_AES_PSK);

    // Look up IP address of peer
    dns_result_init(&dns_res);
    DEBUG_printf("resolving %s\n", REMOTE_HOSTNAME);
    dns_gethostbyname_blocking(REMOTE_HOSTNAME, &dns_res);
    if (dns_res.resolved) {
      INFO_printf("%s resolved to %s\n", REMOTE_HOSTNAME,
                  ipaddr_ntoa(&dns_res.addr));
    } else {
      WARNING_printf("%s failed to resolve\n", REMOTE_HOSTNAME);
      goto sleep;
    }

    // Establish TCP connection
    PICO_PQTLS_tcp_stream_t *stream = PICO_PQTLS_tcp_stream_new();
    if (!stream) {
      CRITICAL_printf("fail to instantiate TCP stream\n");
      return -1;
    }

    lwip_err = PICO_PQTLS_tcp_stream_connect_timeout_ms(
        stream, ipaddr_ntoa(&dns_res.addr), HTTPS_PORT, TCP_CONNECT_TIMEOUT_MS);
    if (lwip_err == ERR_OK) {
      INFO_printf("Connected to %s:%d\n", REMOTE_HOSTNAME, HTTPS_PORT);
    } else {
      WARNING_printf("Failed to establish connection within %d ms (err=%d)\n",
                     TCP_CONNECT_TIMEOUT_MS, lwip_err);
      PICO_PQTLS_tcp_stream_close(stream);
      goto sleep;
    }

    // Initialize WolfSSL
    if ((ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method())) == NULL) {
      CRITICAL_printf("Failed to create SSL CTX\n");
      exit(-1);
    }
    // TODO: at least verify peer!
    wolfSSL_CTX_set_verify(ssl_ctx, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_SetIORecv(ssl_ctx, wolfssl_recv_cb);
    wolfSSL_SetIOSend(ssl_ctx, wolfssl_send_cb);
    if ((ssl = wolfSSL_new(ssl_ctx)) == NULL) {
      CRITICAL_printf("Failed to create SSL\n");
      exit(-1);
    }
    wolfSSL_SetIOReadCtx(ssl, stream);
    wolfSSL_SetIOWriteCtx(ssl, stream);

    // TLS handshake
    DEBUG_printf("TLS Connecting\n");
    if ((ssl_err = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
      WARNING_printf("TLS handshake failed (%d)\n",
                     wolfSSL_get_error(ssl, ssl_err));
    } else {
      INFO_printf("TLS handshake success\n");
    }

    // HTTP request
    readlen = 0;
    sendlen = wolfSSL_write(ssl, HTTP_REQUEST, strlen(HTTP_REQUEST));
    if (sendlen < 0) {
      printf("Failed to write HTTP request to %s\n", REMOTE_HOSTNAME);
    } else {
      printf("Wrote %d bytes from %s\n", sendlen, REMOTE_HOSTNAME);
    }
    while ((readlen = wolfSSL_read(ssl, http_buf + http_buflen,
                                   sizeof(http_buf) - http_buflen)) > 0) {
      http_buflen += readlen;
    }
    http_buf[http_buflen] = '\0';
    // TODO: the octocat ASCII art is out of shape but otherwise recognizable
    printf("%s\n", http_buf);
    memset(http_buf, 0, sizeof(http_buf));
    http_buflen = 0;

    // Finished, close TCP connection and cleanup
    wolfSSL_shutdown(ssl);
    lwip_err = PICO_PQTLS_tcp_stream_close(stream);
    if (lwip_err == ERR_OK) {
      DEBUG_printf("Gracefully terminated connection\n");
    } else if (lwip_err == ERR_ABRT) {
      WARNING_printf("Aborted connection\n");
    } else {
      CRITICAL_printf("FATAL: UNREACHABLE!\n");
      return -1;
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    wolfSSL_CTX_free(ssl_ctx);
    ssl_ctx = NULL;

  sleep:
    DEBUG_printf("Taking a nap for %d ms\n", SLEEP_MS);
    sleep_ms(SLEEP_MS);
  }
}

/**
 * WolfSSL needs a UNIX timestamp
 * TODO: this is a dummy time, need to implement a real clock with Pi
 */
#include <time.h>
time_t myTime(time_t *t) {
  *t = (((2023 - 1970) * 365 + (8 * 30)) * 24 * 60 * 60);
  return *t;
}

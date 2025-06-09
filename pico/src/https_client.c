#include <wolfssl/wolfcrypt/settings.h>

#include <lwip/ip4_addr.h>
#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>
#include <stdio.h>
#include <stdlib.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>

#include "pico-pqtls/tcp.h"
#include "pico-pqtls/mozilla-ca.h"
#include "pico-pqtls/tcp.h"
#include "pico-pqtls/utils.h"

#define TLS_MAX_BUFFER_LEN (16992)
#define SLEEP_MS (60 * 1000) // do not DoS the remote host

#define REMOTE_HOSTNAME "api.github.com"
#define HTTPS_PORT 443
#define HTTP_REQUEST                                                           \
  "GET /octocat HTTP/1.1\r\n"                                                  \
  "Host: api.github.com\r\n"                                                   \
  "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) "       \
  "Gecko/20100101 Firefox/136.0\r\n"                                           \
  "Accept: application/json\r\n"                                               \
  "Connection: close\r\n\r\n"
// TODO: according to Firefox, GitHub's certificate chain that traces back to
// this root certificate uses SHA256-ECDSA and SHA384-ECDSA. I've tried using
// wolfSSL_CTX_UseSupportedCurve with secp256r1 and secp384r1, but server
// authentication still fails with error code 188, indicating that root
// certificate was not found. Later in the project I will be using self-signed
// root certificates, so for now it is not worth it to try to pinpoint which of
// the Mozilla's trusted CA certificates was used, or how to configure wolfSSL
// to support these signature algorithms.
#define USERTRUST_ECC_CA_CERT                                                  \
  "-----BEGIN CERTIFICATE-----\n"                                              \
  "MIICjzCCAhWgAwIBAgIQXIuZxVqUxdJxVt7NiYDMJjAKBggqhkjOPQQDAzCBiDEL\n"         \
  "MAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNl\n"         \
  "eSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMT\n"         \
  "JVVTRVJUcnVzdCBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAwMjAx\n"         \
  "MDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT\n"         \
  "Ck5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUg\n"         \
  "VVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBFQ0MgQ2VydGlm\n"         \
  "aWNhdGlvbiBBdXRob3JpdHkwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQarFRaqflo\n"         \
  "I+d61SRvU8Za2EurxtW20eZzca7dnNYMYf3boIkDuAUU7FfO7l0/4iGzzvfUinng\n"         \
  "o4N+LZfQYcTxmdwlkWOrfzCjtHDix6EznPO/LlxTsV+zfTJ/ijTjeXmjQjBAMB0G\n"         \
  "A1UdDgQWBBQ64QmG1M8ZwpZ2dEl23OA1xmNjmjAOBgNVHQ8BAf8EBAMCAQYwDwYD\n"         \
  "VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjA2Z6EWCNzklwBBHU6+4WMB\n"         \
  "zzuqQhFkoJ2UOQIReVx7Hfpkue4WQrO/isIJxOzksU0CMQDpKmFHjFJKS04YcPbW\n"         \
  "RNZu9YO6bVi9JNlWSOrvxKJGgYhqOkbRqZtNyWHa0V1Xahg=\n"                         \
  "-----END CERTIFICATE-----\n"

// the clock
static ntp_client_t ntp_client;

/**
 * WolfSSL will call this when it wants to read stuff
 */
int wolfssl_recv_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  if (!ctx || !buf || sz <= 0)
    return WOLFSSL_CBIO_ERR_GENERAL;

  tcp_stream_t *stream = (tcp_stream_t *)ctx;
  size_t outlen = 0;

  err_t err = tcp_stream_read(stream, (uint8_t *)buf, sz, &outlen);
  // DEBUG_printf("WolfSSL wants to read %d bytes and TCP received %zu bytes\n",
  //              sz, outlen);

  if (err == ERR_OK && outlen >= 0) {
    return (int)outlen; // partial reads are OK
  } else if (err == ERR_OK && outlen == 0) {
    return WOLFSSL_CBIO_ERR_WANT_READ;
  } else if (err == ERR_CLSD) {
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

  tcp_stream_t *stream = (tcp_stream_t *)ctx;
  size_t written_len = 0;
  err_t err = tcp_stream_write(stream, (uint8_t *)buf, sz, &written_len, 0);
  // DEBUG_printf("WolfSSL wants to write %d bytes and TCP wrote %zu bytes\n",
  // sz,
  //              written_len);
  tcp_stream_flush(stream);

  if (err == ERR_OK) {
    return written_len;
  } else {
    return WOLFSSL_CBIO_ERR_GENERAL;
  }
}

int main(void) {
  stdio_init_all();
  countdown_s(10);
  if (cyw43_arch_init()) {
    printf("cyw43_arch_init failed\n");
    return -1;
  }
  cyw43_arch_enable_sta_mode();
  ensure_wifi_connection_blocking(WIFI_SSID, WIFI_PASSWORD,
                                  CYW43_AUTH_WPA2_AES_PSK);

  WOLFSSL_CTX *ssl_ctx = NULL;
  WOLFSSL *ssl = NULL;
  int ssl_err;

  dns_result_t peer_dns, ntp_dns;
  err_t lwip_err, ntp_err;

  uint8_t http_buf[8192];
  size_t http_buflen = 0;
  size_t readlen, sendlen;

  tcp_stream_t stream;

  // Synchronize the clock
  dns_result_init(&ntp_dns);
  dns_gethostbyname_blocking(NTP_HOSTNAME, &ntp_dns);
  if (!ntp_dns.resolved) {
    CRITICAL_printf("Failed to resolve %s\n", NTP_HOSTNAME);
    exit(-1);
  } else {
    INFO_printf("%s resolved to %s\n", NTP_HOSTNAME,
                ipaddr_ntoa(&ntp_dns.addr));
  }

  ntp_client_init(&ntp_client, ntp_dns.addr, NTP_PORT);
  while (!ntp_client.processed) {
    ntp_err = ntp_client_sync_timeout_ms(&ntp_client, NTP_TIMEOUT_MS);
    if (ntp_err == ERR_TIMEOUT) {
      WARNING_printf("NTP server timed out\n");
    }
  }

  // Look up IP address of peer
  dns_result_init(&peer_dns);
  // DEBUG_printf("resolving %s\n", REMOTE_HOSTNAME);
  dns_gethostbyname_blocking(REMOTE_HOSTNAME, &peer_dns);
  if (peer_dns.resolved) {
    INFO_printf("%s resolved to %s\n", REMOTE_HOSTNAME,
                ipaddr_ntoa(&peer_dns.addr));
  } else {
    WARNING_printf("%s failed to resolve\n", REMOTE_HOSTNAME);
    goto sleep;
  }

  // configure wolfssl
  // Initialize WolfSSL
  wolfSSL_Init();
  // wolfSSL_Debugging_ON();
  if ((ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method())) == NULL) {
    CRITICAL_printf("Failed to create SSL CTX\n");
    exit(-1);
  }
  // TODO: when using USERTRUST_ECC_CA_CERT WolfSSL will error out (188)
  //   it is probably because WolfSSL advertised a different set of supported
  //   signature algorithms than my browser (Firefox), which causes
  //   api.github.com to return a different Certificate chain that then traces
  //   to a different root
  uint8_t ca_certs[] = MOZILLA_CA_CERTS;
  size_t ca_certs_size = sizeof(ca_certs);
  // wolfSSL_CTX_set_verify(ssl_ctx, WOLFSSL_VERIFY_NONE, NULL);
  wolfSSL_CTX_set_verify(ssl_ctx, WOLFSSL_VERIFY_PEER, NULL);
  if (wolfSSL_CTX_load_verify_buffer(ssl_ctx, ca_certs, ca_certs_size,
                                     SSL_FILETYPE_PEM) != SSL_SUCCESS) {
    CRITICAL_printf("Failed to load CA certificate\n");
    exit(-1);
  }
  wolfSSL_SetIORecv(ssl_ctx, wolfssl_recv_cb);
  wolfSSL_SetIOSend(ssl_ctx, wolfssl_send_cb);

  while (1) {
    ensure_wifi_connection_blocking(WIFI_SSID, WIFI_PASSWORD,
                                    CYW43_AUTH_WPA2_AES_PSK);

    // Establish TCP connection
    tcp_stream_init(&stream);
    lwip_err = tcp_stream_connect_ipv4(&stream, ipaddr_ntoa(&peer_dns.addr),
                                       HTTPS_PORT, TCP_CONNECT_TIMEOUT_MS);
    if (lwip_err == ERR_OK) {
      INFO_printf("Connected to %s:%d\n", REMOTE_HOSTNAME, HTTPS_PORT);
    } else {
      WARNING_printf("Failed to establish connection within %d ms (err=%d)\n",
                     TCP_CONNECT_TIMEOUT_MS, lwip_err);
      tcp_stream_close(&stream);
      goto sleep;
    }

    if ((ssl = wolfSSL_new(ssl_ctx)) == NULL) {
      CRITICAL_printf("Failed to create SSL\n");
      exit(-1);
    }
    wolfSSL_SetIOReadCtx(ssl, &stream);
    wolfSSL_SetIOWriteCtx(ssl, &stream);

    // TLS handshake
    // DEBUG_printf("TLS Connecting\n");
    if ((ssl_err = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
      WARNING_printf("TLS handshake failed (%d)\n",
                     wolfSSL_get_error(ssl, ssl_err));
      char errmsg[80];
      wolfSSL_ERR_error_string(ssl_err, errmsg);
      printf("Error string: %s\n", errmsg);
      goto shutdown;
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
  shutdown:
    wolfSSL_shutdown(ssl);
    lwip_err = tcp_stream_close(&stream);
    if (lwip_err == ERR_OK) {
      INFO_printf("Gracefully terminated connection\n");
    } else if (lwip_err == ERR_ABRT) {
      WARNING_printf("Aborted connection\n");
    } else {
      CRITICAL_printf("FATAL: UNREACHABLE!\n");
      return -1;
    }
    wolfSSL_free(ssl);
    ssl = NULL;
    cyw43_arch_poll();

  sleep:
    DEBUG_printf("Taking a nap for %d ms\n", SLEEP_MS);
    sleep_ms(SLEEP_MS);
  }
}

/**
 * WolfSSL needs a UNIX timestamp
 */
#include <time.h>
time_t myTime(time_t *t) {
  *t = get_current_epoch(&ntp_client);
  return *t;
}

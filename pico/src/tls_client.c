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
#define SLEEP_MS (5 * 60 * 1000) // do not DoS the remote host

#define REMOTE_HOSTNAME "api.github.com"
#define HTTPS_PORT 443
#define HTTP_REQUEST                                                           \
  "GET /octocat HTTP/1.1\r\n"                                                  \
  "Host: api.github.com\r\n"                                                   \
  "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) "       \
  "Gecko/20100101 Firefox/136.0\r\n"                                           \
  "Accept: application/json\r\n"                                               \
  "Connection: close\r\n\r\n"
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
#define GITHUB_CHAIN_CERTS                                                     \
  "-----BEGIN CERTIFICATE-----\n"                                              \
  "MIIEoDCCBEagAwIBAgIQKhb1wgEYB/cKkmPdPDmp8jAKBggqhkjOPQQDAjCBjzEL\n"         \
  "MAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE\n"         \
  "BxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5T\n"         \
  "ZWN0aWdvIEVDQyBEb21haW4gVmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENBMB4X\n"         \
  "DTI1MDIwNTAwMDAwMFoXDTI2MDIwNTIzNTk1OVowFzEVMBMGA1UEAwwMKi5naXRo\n"         \
  "dWIuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElbQ+DErBU9/BYlYXV5qx\n"         \
  "aS5Nu5Ucd+scwICjYp7Z2YcJ2Jgu7HBjM1R6+b2d8yZYJlpLB2aX3qGwc1ZscE7w\n"         \
  "HKOCAvkwggL1MB8GA1UdIwQYMBaAFPaFCjsRhuEEfQ6qCyzS7sxke3uuMB0GA1Ud\n"         \
  "DgQWBBSY8zci2pdh0RUe+FTOokexsSdvADAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0T\n"         \
  "AQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwSQYDVR0gBEIw\n"         \
  "QDA0BgsrBgEEAbIxAQICBzAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28u\n"         \
  "Y29tL0NQUzAIBgZngQwBAgEwgYQGCCsGAQUFBwEBBHgwdjBPBggrBgEFBQcwAoZD\n"         \
  "aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvRUNDRG9tYWluVmFsaWRhdGlv\n"         \
  "blNlY3VyZVNlcnZlckNBLmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2Vj\n"         \
  "dGlnby5jb20wggF9BgorBgEEAdZ5AgQCBIIBbQSCAWkBZwB1AJaXZL9VWJet90OH\n"         \
  "aDcIQnfp8DrV9qTzNm5GpD8PyqnGAAABlNNtegoAAAQDAEYwRAIgARjCCRJjeSsj\n"         \
  "1aDf1k2e9k7BMQOzBk5NH2yNZnExXJYCIEx3XBFFZ4kmjLneOJG0C/W/K+1W+Lx5\n"         \
  "vY+UM1oFAV7SAHYAGYbUxyiqb/66A294Kk0BkarOLXIxD67OXXBBLSVMx9QAAAGU\n"         \
  "0215mgAABAMARzBFAiA9Ui4Z4WE8Mg11ZmjscGtczwGRFgRySEgdY3O/Hmn3rgIh\n"         \
  "AJSNm0C0lHX7yf3IW+dMIctrApWm2rL2P6Wei1wEBuovAHYAyzj3FYl8hKFEX1vB\n"         \
  "3fvJbvKaWc1HCmkFhbDLFMMUWOcAAAGU0215zwAABAMARzBFAiBNfjmh0gVRA7aq\n"         \
  "sfUsyIvg9rvkxJjrV0/w4sjsTbVqngIhAM8fdljMks2Hh+It5rYLMS4utsRzTDEU\n"         \
  "8zBOHS3K9bSDMCMGA1UdEQQcMBqCDCouZ2l0aHViLmNvbYIKZ2l0aHViLmNvbTAK\n"         \
  "BggqhkjOPQQDAgNIADBFAiAHU6XJYeE/cjpdM9Rfn0IdGZEEs0zTAuyN0mUkXnZa\n"         \
  "KQIhAPkzw1jn3t/HCIVT98ZYrTYNsxElJRY6JH89pJlVt3Ay\n"                         \
  "-----END CERTIFICATE-----\n"                                                \
  "-----BEGIN CERTIFICATE-----\n"                                              \
  "MIIDqDCCAy6gAwIBAgIRAPNkTmtuAFAjfglGvXvh9R0wCgYIKoZIzj0EAwMwgYgx\n"         \
  "CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJz\n"         \
  "ZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQD\n"         \
  "EyVVU0VSVHJ1c3QgRUNDIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE4MTEw\n"         \
  "MjAwMDAwMFoXDTMwMTIzMTIzNTk1OVowgY8xCzAJBgNVBAYTAkdCMRswGQYDVQQI\n"         \
  "ExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoT\n"         \
  "D1NlY3RpZ28gTGltaXRlZDE3MDUGA1UEAxMuU2VjdGlnbyBFQ0MgRG9tYWluIFZh\n"         \
  "bGlkYXRpb24gU2VjdXJlIFNlcnZlciBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEH\n"         \
  "A0IABHkYk8qfbZ5sVwAjBTcLXw9YWsTef1Wj6R7W2SUKiKAgSh16TwUwimNJE4xk\n"         \
  "IQeV/To14UrOkPAY9z2vaKb71EijggFuMIIBajAfBgNVHSMEGDAWgBQ64QmG1M8Z\n"         \
  "wpZ2dEl23OA1xmNjmjAdBgNVHQ4EFgQU9oUKOxGG4QR9DqoLLNLuzGR7e64wDgYD\n"         \
  "VR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYB\n"         \
  "BQUHAwEGCCsGAQUFBwMCMBsGA1UdIAQUMBIwBgYEVR0gADAIBgZngQwBAgEwUAYD\n"         \
  "VR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVz\n"         \
  "dEVDQ0NlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMHYGCCsGAQUFBwEBBGowaDA/\n"         \
  "BggrBgEFBQcwAoYzaHR0cDovL2NydC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdEVD\n"         \
  "Q0FkZFRydXN0Q0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1\n"         \
  "c3QuY29tMAoGCCqGSM49BAMDA2gAMGUCMEvnx3FcsVwJbZpCYF9z6fDWJtS1UVRs\n"         \
  "cS0chWBNKPFNpvDKdrdKRe+oAkr2jU+ubgIxAODheSr2XhcA7oz9HmedGdMhlrd9\n"         \
  "4ToKFbZl+/OnFFzqnvOhcjHvClECEQcKmc8fmA==\n"                                 \
  "-----END CERTIFICATE-----\n"                                                \
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
    // uint8_t ca_cert[] = USERTRUST_ECC_CA_CERT;
    uint8_t ca_cert[] = GITHUB_CHAIN_CERTS;
    size_t ca_cert_size = sizeof(ca_cert);
    // wolfSSL_CTX_set_verify(ssl_ctx, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_CTX_set_verify(ssl_ctx, WOLFSSL_VERIFY_PEER, NULL);
    if (wolfSSL_CTX_load_verify_buffer(ssl_ctx, ca_cert, ca_cert_size,
                                       SSL_FILETYPE_PEM) != SSL_SUCCESS) {
      CRITICAL_printf("Failed to load CA certificate\n");
      exit(-1);
    }
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
  // date +%s
  *t = 1744639028;
  return *t;
}

#include <lwip/dns.h>
#include <lwip/ip4_addr.h>
#include <pico/cyw43_arch.h>
#include <pico/stdlib.h>
#include <stdio.h>
#include <stdlib.h>

#include "pico-pqtls/tcp.h"
#include "pico-pqtls/utils.h"

#define TCP_CONNECT_TIMEOUT_MS 10000
#define TCP_READ_TIMEOUT_MS 10000
#define TLS_MAX_BUFFER_LEN (16992)

#define REMOTE_HOSTNAME "OTPYRC40.eng.uwaterloo.ca"
#define HTTPS_PORT 8000

typedef struct dns_result {
  ip_addr_t addr;
  // remote hostname has been successfully found, addr can be used
  bool resolved;
  // DNS resolution is complete
  bool complete;
} dns_result_t;

void dns_result_init(dns_result_t *res) {
  ip_addr_set_zero(&res->addr);
  res->resolved = false;
  res->complete = false;
}

static void dns_handler(const char *name, const ip_addr_t *ipaddr, void *arg) {
  dns_result_t *dns_res = (dns_result_t *)arg;
  if (ipaddr) {
    dns_res->addr = *ipaddr;
    dns_res->resolved = true;
  } else {
    dns_res->resolved = false;
  }
  dns_res->complete = true;
}

/**
 * Block until callback is called. Check dns_res->resolved for success or not
 * TODO: there is currently a bug that if this is called twice, the second time
 * will hang
 */
void dns_gethostbyname_blocking(const char *hostname, dns_result_t *dns_res) {
  err_t err = dns_gethostbyname(hostname, &dns_res->addr, dns_handler, dns_res);
  if (err == ERR_OK) {
    // DNS record has been cached, no need to check callback
    dns_res->complete = true;
    dns_res->resolved = true;
    return;
  } else if (err == ERR_INPROGRESS) {
    // Wait for callback
    while (!dns_res->complete) {
      cyw43_arch_poll();
      sleep_ms(1);
    }
  } else {
    CRITICAL_printf("Unhandled error (err %d)!\n", err);
    exit(-1);
  }
}

int main(void) {
  stdio_init_all();
  if (cyw43_arch_init()) {
    printf("cyw43_arch_init failed\n");
    return -1;
  }
  cyw43_arch_enable_sta_mode();

  dns_result_t dns_res;
  err_t lwip_err;

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

    lwip_err = PICO_PQTLS_tcp_stream_close(stream);
    if (lwip_err == ERR_OK) {
      DEBUG_printf("Gracefully terminated connection\n");
    } else if (lwip_err == ERR_ABRT) {
      WARNING_printf("Aborted connection\n");
    } else {
      CRITICAL_printf("FATAL: UNREACHABLE!\n");
      return -1;
    }

  sleep:
    sleep_ms(2000);
  }
}

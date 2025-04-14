#include <lwip/err.h>
#include <lwip/ip_addr.h>
#include <lwip/udp.h>
#include <pico/cyw43_arch.h>
#include <pico/stdio.h>
#include <pico/time.h>

#include "pico-pqtls/tcp.h"
#include "pico-pqtls/utils.h"

int main(void) {
  stdio_init_all();

  if (cyw43_arch_init() != 0) {
    CRITICAL_printf("cyw43 failed to initialize\n");
    exit(-1);
  }
  cyw43_arch_enable_sta_mode();
  ensure_wifi_connection_blocking(WIFI_SSID, WIFI_PASSWORD,
                                  CYW43_AUTH_WPA2_AES_PSK);
  struct ntp_client client;
  err_t ntp_err;
  dns_result_t ntp_dns;

  while (1) {
    ensure_wifi_connection_blocking(WIFI_SSID, WIFI_PASSWORD,
                                    CYW43_AUTH_WPA2_AES_PSK);
    // First resolve the IP address of the NTP server
    dns_result_init(&ntp_dns);
    dns_gethostbyname_blocking(NTP_HOSTNAME, &ntp_dns);
    if (!ntp_dns.resolved) {
      CRITICAL_printf("Failed to resolve %s\n", NTP_HOSTNAME);
      exit(-1);
    } else {
      INFO_printf("%s resolved to %s\n", NTP_HOSTNAME,
                  ipaddr_ntoa(&ntp_dns.addr));
    }

    ntp_client_init(&client, ntp_dns.addr, NTP_PORT);
    ntp_err = ntp_client_sync_timeout_ms(&client, NTP_TIMEOUT_MS);
    if (ntp_err == ERR_TIMEOUT) {
      WARNING_printf("NTP server timed out\n");
      goto cleanup;
    }
    // check the clock for a few seconds
    for (int i = 0; i < 60; i++) {
      INFO_printf("Current epoch %llu\n", get_current_epoch(&client));
      sleep_ms(1000);
    }

  cleanup:
    ntp_client_close(&client);
  }
}

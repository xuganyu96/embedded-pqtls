#include <lwip/err.h>
#include <lwip/ip_addr.h>
#include <lwip/udp.h>
#include <pico/cyw43_arch.h>
#include <pico/stdio.h>
#include <pico/time.h>

#include "pico-pqtls/tcp.h"
#include "pico-pqtls/utils.h"

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

struct ntp_client {
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
};

static void ntp_resp_handler(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                             const ip_addr_t *peer_addr, u16_t peer_port) {
  struct ntp_client *client = (struct ntp_client *)arg;
  client->processed = true;
  client->abs_time_at_ntp_resp = get_absolute_time();
  if (p->tot_len != NTP_MSG_LEN) {
    WARNING_printf("UDP response length %d, expected %d\n", p->tot_len,
                   NTP_MSG_LEN);
    client->ntp_err = ERR_VAL;
    goto cleanup;
  }
  uint8_t *payload = (uint8_t *)(p->payload);
  uint8_t resp_mode = payload[0] & NTP_MODE_MASK;
  uint8_t resp_stratum = payload[1];

  if (!ip_addr_cmp(&client->ntp_ipaddr, peer_addr)) {
    WARNING_printf("Mismatched IP addr: expect %s found %s\n",
                   ip4addr_ntoa(&client->ntp_ipaddr), ip4addr_ntoa(peer_addr));
    client->ntp_err = ERR_VAL;
    goto cleanup;
  }
  if (peer_port != client->ntp_port) {
    WARNING_printf("Mismatched Port: expect %d found %d\n", client->ntp_port,
                   peer_port);
    client->ntp_err = ERR_VAL;
    goto cleanup;
  }
  if (resp_mode != NTP_MODE_SERVER) {
    WARNING_printf("Unexpected NTP mode: expect %d found %d\n", NTP_MODE_SERVER,
                   resp_mode);
    client->ntp_err = ERR_VAL;
    goto cleanup;
  }
  if (resp_stratum == NTP_STRATUM_INVALID) {
    WARNING_printf("Invalid NTP stratum\n");
    client->ntp_err = ERR_VAL;
    goto cleanup;
  }
  client->ntp_err = ERR_OK;
  uint8_t seconds_buf[4] = {0};
  pbuf_copy_partial(p, seconds_buf, sizeof(seconds_buf), 40);
  uint32_t seconds_since_1900 = seconds_buf[0] << 24 | seconds_buf[1] << 16 |
                                seconds_buf[2] << 8 | seconds_buf[3];
  uint32_t seconds_since_1970 = seconds_since_1900 - NTP_DELTA_SECONDS;
  client->epoch = seconds_since_1970;
  INFO_printf("got ntp response: %llu\n", client->epoch);

cleanup:
  pbuf_free(p);
}

err_t ntp_client_init(struct ntp_client *client, ip_addr_t ntp_ipaddr,
                      uint16_t ntp_port) {
  client->ntp_ipaddr = ntp_ipaddr;
  client->ntp_port = ntp_port;
  client->processed = false;
  client->pcb = udp_new_ip_type(IPADDR_TYPE_V4);
  if (!client->pcb) {
    CRITICAL_printf("Failed to allocate for NTP's UDP control block\n");
    return ERR_MEM;
  }
  udp_recv(client->pcb, ntp_resp_handler, client);
  return ERR_OK;
}

void ntp_client_close(struct ntp_client *client) {
  if (client->pcb) {
    udp_remove(client->pcb);
    client->pcb = NULL;
  }
}

/**
 * This method will handle the UDP PCB
 */
err_t ntp_client_sync_timeout_ms(struct ntp_client *client,
                                 uint32_t timeout_ms) {
  cyw43_arch_lwip_begin();
  struct pbuf *ntp_req = pbuf_alloc(PBUF_TRANSPORT, NTP_MSG_LEN, PBUF_RAM);
  if (!ntp_req) {
    WARNING_printf("Failed to allocate %d pbuf\n", NTP_MSG_LEN);
    return ERR_MEM;
  }
  uint8_t *payload = (uint8_t *)ntp_req->payload;
  memset(payload, 0, NTP_MSG_LEN);
  payload[0] = NTP_LI_NO_WARNING | NTP_VN_VERSION_3 | NTP_MODE_CLIENT;
  udp_sendto(client->pcb, ntp_req, &client->ntp_ipaddr, client->ntp_port);
  pbuf_free(ntp_req);
  cyw43_arch_lwip_end();

  uint32_t timeout_begin = to_ms_since_boot(get_absolute_time());
  while ((to_ms_since_boot(get_absolute_time()) - timeout_begin) < timeout_ms &&
         !client->processed) {
    cyw43_arch_poll();
    sleep_ms(1);
  }

  if (!client->processed) {
    return ERR_TIMEOUT;
  }
  return client->ntp_err;
}

/**
 * Return the current time
 */
time_t get_current_epoch(struct ntp_client *client) {
  uint64_t diff_us =
      absolute_time_diff_us(client->abs_time_at_ntp_resp, get_absolute_time());
  return client->epoch + (us_to_ms(diff_us) / 1000u);
}

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

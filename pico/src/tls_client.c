#include <pico/cyw43_arch.h>
#include <pico/stdio.h>
#include <wolfssl/ssl.h>

#include "pico-pqtls/tcp.h"
#include "pico-pqtls/utils.h"

#define SLEEP_MS (5 * 1000)
#define ML_DSA_CA_CERT                                                         \
  "-----BEGIN CERTIFICATE-----\n"                                              \
  "MIIP+DCCBm6gAwIBAgIQW7blRbQEqt2Rkx+oFa7PEzALBglghkgBZQMEAxEwbzEL\n"         \
  "MAkGA1UEBhMCQ0ExCzAJBgNVBAgMAk9OMREwDwYDVQQHDAhXYXRlcmxvbzEjMCEG\n"         \
  "A1UECgwaQ29tbXVuaWNhdGlvbiBTZWN1cml0eSBMYWIxGzAZBgNVBAMMEiouZW5n\n"         \
  "LnV3YXRlcmxvby5jYTAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAwMDBaMG8x\n"         \
  "CzAJBgNVBAYTAkNBMQswCQYDVQQIDAJPTjERMA8GA1UEBwwIV2F0ZXJsb28xIzAh\n"         \
  "BgNVBAoMGkNvbW11bmljYXRpb24gU2VjdXJpdHkgTGFiMRswGQYDVQQDDBIqLmVu\n"         \
  "Zy51d2F0ZXJsb28uY2EwggUyMAsGCWCGSAFlAwQDEQOCBSEAsFF38TD2SQp266Fy\n"         \
  "RQHEhh9PJfmDnu3VJFEU86SbDJkBuFghVBrzY4JLPKdA6hxBVLrf1V7IIbw+FNQX\n"         \
  "1G657jPaWT2UxMN+H7fh4CRL9VaUIGhWfbVGC9zDhjlSWPTXA6A+1rBL8/NHaWyO\n"         \
  "rcgPTU2X+KWB/FkiKLl27d7up50tT6S22ZAAfbHk2GZCns8hw3aK/Ej0TPUuNNp/\n"         \
  "bE8J4DBv+vmxoPWKE48mVTLDp2HyKXxoAyKeumPqu+ltzTm0lS2CPf9cyCGuiP14\n"         \
  "rjpVvX5VsJ4PPU//k+RT1qUjzVV43I7rtSYW3iBb0fgE04i0ciaHGPAq3exF8Pnm\n"         \
  "mUZtfAafA5RBwaxCLJmB2zUZ1EHLfwQSSPwTZPQOA1QBJXqhyND+f3whe1BXG7st\n"         \
  "6oV6jlMX5/O7e8L4cJGHQI5IqHaoFv5cXdtvCqH2hETZu9V3SGQDg/5crV78bqrX\n"         \
  "bDGWFzQlnuKLiQzwu/qkIpi3Hga8s3tsBVQe3Gg6jwixSA3lOtQRvIHf+Gh5tVOb\n"         \
  "PBfaZyC1TxsCoKeNKMLj5dvsuWl+IpMvCybff+JuEyufxE256vmhQ3c2VW8wK1uO\n"         \
  "9G3TkXnumcaSve8Iyzr+kSV+O/LZfZC2yXs5dnPV/JHeEYKdI/LUskcwtjJRGAaq\n"         \
  "LwL11vF3Ck5CuLerdw7nmwMw4U4xubiBTRKy5F5NZDjY46abi3/WIogajdgabUo/\n"         \
  "VOKABDerx6ETjd1x2fvGF2pcKRalVkABxdiSvuaWjLx+V19FcJIS9ON0U2z/bJGz\n"         \
  "KJVVAJQvGXTTEFSTDNESmfTZJ1uaT61iq5AF12Sx23HPyZ1rHpGkvoPYWA3FwEqG\n"         \
  "b3x6etmW7W/zKVVZs97E12HrCMVhP6HtTmZF8ZFwLBtSM7p9NIQss66nGhnrq//i\n"         \
  "8zNeV1fHr60Fasla9oKUPI6KIsYh4TuvbyOHfdY9IEillP4BPajoEfFVSLgv5EQE\n"         \
  "c60bslbRoEny//nMYlKMKerOVgqFd9OSyYhn0e88+76QLlKJ2jh7TPzEEpGOynSL\n"         \
  "yh3PYNrt62GQ4T3f1I6SbCuAFEIPY9ixgkjigS8AOHJaEmkrrFkZATh3hld+xvKa\n"         \
  "s0+2Q3VQ2Qa9V0I5W/axBdgS0BLTtaxSzqFMjZ2EsGVWar0wYTHuyKLG6QbdZKbK\n"         \
  "UTpyYV3Mg6/ZVlz8+7Z/aCnJTiexFBbpbgT+2ST0f74o9xKgSuDXYD6cXGQ/j/+U\n"         \
  "No2CfEuMD6IBQXw9/Ml7XpE4Uwb6cUxknXFaYf01UzYdEF184QCyHfeKmkVGja4o\n"         \
  "33cI4yVMa8Q8XtRWmb3f7oFPe8CcI0GXbkYJ1VMvZH1EtpdPhai1K5bR7KshLdF5\n"         \
  "RyvGhTfc6rmooRTFAE81PCIVBiajPP/cjmSOuOOoDFKVFDED9m+fyvGAV9hzDjGF\n"         \
  "opQDQO6YP3oLLcAXIEKPTPzsvOxIAOyEszGjyOED/qWUD8g5IKvKp+H15XCA16Zl\n"         \
  "3WPNJbBHsiZLB8kUpHrAEHbG2Fmij8+wYJAERKfUydU3crqAwrfad7ph6YbIp3oy\n"         \
  "e+PrtXL/IzE4qbH8Lzc3+SiIZrvWStJgUnbkcfQPZrPBZOOOhbHtXMsEVZmVYCHc\n"         \
  "PG0OjcAfos5e8oYEEBr8DUplsSF7YusUWc5k1FnGP0MNnZRzIhTJwQhCvrx5Nwdy\n"         \
  "7lv88r9yNzk9UtJ5tUJJDGzqpoEhkc8OM1VUvD6yJtmrBbL8Pj/3ykPkYHsZh6z8\n"         \
  "QU6GGqMQMA4wDAYDVR0TBAUwAwEB/zALBglghkgBZQMEAxEDggl1AKWuLEMcMB7d\n"         \
  "ciCmzMcb/Qt5CDM2T5f+y50eFfsSX1d/aj2fwMnxeKiNhy24q3aBCG1UFquIwTq6\n"         \
  "dl+KAJ5kY8w8J7kvt8SFJ/1tZgp6DhyKpKml5y4Bdgx/rKtBsItIuBeoGNc3epOr\n"         \
  "rLPDxxbOiXArFvRyoM8nlNoMVDmK9IxUfeOtj5acRjXswwycFa2I9lJXVSw/bYP6\n"         \
  "XS0ghTrpCDM2o3ld861R67sX5Atw9EtSxO+xNxHN1cYXNKkVKQtw2JA3okKlTQgU\n"         \
  "i+W3JltoP6uMCW7rMhU/rhJrhJLMuMMby5h9F/OJ8mRGxuPCir2l0FgPl9W4/Z7I\n"         \
  "5OSLdaHdZxwlMyMXZsEz2e8xpI/elrDGk0qJp6VibFqOkaVrq45wQ/Gsb09ZtxHy\n"         \
  "bcIp74Qk/lRvtHEgOYzbsxrV9L/rrV6P9cuSzRQecdB7uklO2cTJNuGbQCq5VY/b\n"         \
  "2ICXNOxBD2UZA3MAqCsDR4Om9X5mtwydPY9EPgAzvLf2Z58058+ncJ2LXoNJSLEb\n"         \
  "ZgOdqRhnOEwTjE0modkewDUSG9ydbIzhH/jHSYjYrioE3zuWgMg8fR0jQXLq1TVq\n"         \
  "iY8OIQ223i51XW090Cn2EF4lj0lMlqAqSLYAtC23dDdMduB8nVXpwaEBMVMdNKuH\n"         \
  "Pf6vvnzc3ovwucPYp9T8xNbbLCyIyHqVUWtAVQLlVJb8DJNjMwf33vat1mEXyYXi\n"         \
  "WMbufNRuLW/OfPodh7L245E9FXHImN+lzvqz2T/9n4HV7P988FjvU3oIO6m/dP/M\n"         \
  "cNBQto3N94Fv6MSwionSrpPFP32Ao4A/Y4xo2hCI8qajofbC5gt1pHCuQz6k4ZFI\n"         \
  "jm9uD+U0YzxfAF2/ZCj6gTbBuG6MdQLbrYcVOtEyc20V90fvPmgRyuKHkQ/LgCAK\n"         \
  "UoVhOtCPYZmIOnGh1Wq20GhIZmwGsNfEiaW8kFRWsy7201d6U/Fw/fhES1G1tp8g\n"         \
  "2EvIYf/JV+8AAiUQmhZzv5Zdh3uUISkF8CebM72GAboEhKVC+l5KStWD1fl2VAWF\n"         \
  "QZrHF34puhWEPQoFId+nCYgldh4AIPcmDNzdSNZG3UMOmTjROOBevtfBsZ00uf9M\n"         \
  "cgFZty51U1gJlpgIHAbIq86WVpOTmBm3+Cm0GFOmViDO/IKvGsvaVYsQu3IULSOZ\n"         \
  "d//3MCcNROFciuaxvG1HpwtcHT0lLobaDAZgjHea5Zy3BFe0RxkcNP3aSBnG+8X7\n"         \
  "gr7auurfjMFLc0heFDWhXsf1gVTH7mfGwzsr44e1M5B02z9QWq9tZYoDTJ/p8/Zj\n"         \
  "jKbgF8JhRuAEM6BuyrYKBBedN36TySEbzKmzBHrZOPcWCy7U4OL/FQ7TI5ycgcUc\n"         \
  "aUZgf+5oK+9wEXEqpUzdrs3GVVY64AS+q8BQXstfIaMy6NFC/CgoX49ra+2XRfGU\n"         \
  "IKWgy4oFvdp478Cdkp85/hJOAFlf2MBfUTmpDWxQfTDb/BV26kbcYzSbc245QlG9\n"         \
  "CEQEL5kLtSbKX4gxIH/3RLlujyZ7cdNBoo00z4w6BTY8WkciLiqT0vMpRkU/GR2R\n"         \
  "ac5T5chLNkW9NXm3kGb+vaQ4nyEbJI7O7+HrD2V+TlE2jkpVZueUHGK71WdHsI3l\n"         \
  "Ttx2yJYVjPZkndtok8B/jlX7Mo0yhG5O2qU6dTXLULuF8uIjYDaTyPXUdq04+iQX\n"         \
  "Rop+mO+D2WFstL+PmOhBzb9FWsW1PQvJKhSB9y12FcWxnCW60z9i5M8yl31+QbgZ\n"         \
  "qoIgHZkzv44+KMlA4LUoIdMu9ff7LBqtbnSn23QcIhPBZ/mtMmIEOQ01PrMFj972\n"         \
  "39rbaYx3npWRuw+kj/n5BzFIJQAZArhx1d9gcj8jLfOY8/UlXTyoV6sEEIJSk/6G\n"         \
  "BniMsNxjH3UZdho7MS6aRTVdmo7FFnmaoQUOf3Lyuy+WVmApVqdHqW39TJNNuNHO\n"         \
  "i1EoDIXDxuNyMc8wTBULlBBFhP5IlNpQQC4XN9VjxzEODYauuSfkesqcXml8TntJ\n"         \
  "HsO7Q0LS56R79Xw0FJJn4z1583Wzh9s0Z8vFkjR2NKbMO/9EhFMrBxwnpX/9we/Z\n"         \
  "stW1J4CqZI+t1a4EdeFOo8la8V6j4gXBYNhSy7CsX4HStgETq73+Hg0KyFvFkWsc\n"         \
  "I/7YATQQk7PM7HSnU2uDnQtM0IPR0QiCEdcGnIkxAmVbBklt1CruQRcgxVAD9g5N\n"         \
  "63SBOlHFUujLhxSdH1fkJOU7VFgBT2PV/CFBL7bMsS25flbPhodC3uml+IeXHKdw\n"         \
  "r0kccJvVEXs52wtYoO6/C4MofmLrPLZJ+mu7QcsrbEKX5T8x4BEmLES3yCPSMleG\n"         \
  "OZ+lp4iq+c7L71myyGFeQ3NxkBVZDZiztiR6irom0+tPx3jbsj12EWtds0QqA+Fv\n"         \
  "KvWnMFIysyCOLIl8h3qxueVpFdK0CZC73k8B45VP7ym9Wg192ODIDBEMPpwpwsvL\n"         \
  "JfGCrPIONuZ4RCdajAWisKxSZBY8h1PycVHOMQjo4RNSB8LLziBkyxI1nYsV78IV\n"         \
  "1obRq6P6DwySsO3KHevmia0JvmKuKkNvs2/Phu5H2v20Ia6q+i5Oh/R2maqXLmtM\n"         \
  "RkZrr+z7QMRbIwtJ/HJCU0K8hl/ZVVQHvdE8x06hcOjwHJZZatXCCMrUrj4Z4di0\n"         \
  "Fy9dLrYa3cLIT4aXfSE+PHo8oiJ4w4OYNtGc8SVCUVg4TJNIR19baWOwx+gnYFmk\n"         \
  "PAxyhAFDYnqMxR6OfvIsHwgtC98p2n6akD5p46F6LoN51eMzFe7gAPM/0bY71BYq\n"         \
  "sHF539JqiRlQeAFJT234S9tHzVuDF8TrgUbLNoV6IBTcxTlu4JsQimbbrpEVmdkn\n"         \
  "gvDAwEncMKXV4THE4mm5u/0mMOetWFoDIUKyxIhQEqSFnYlwvIa9FV3NKsZ8KkXq\n"         \
  "gPmgc7/BdygC8XwgGc7iR6kK4H/SxCGpIFkq6XuKEB2ngKBR4+F5VgLuuVT/ivGE\n"         \
  "Mk80gDz8OSplUCZDJ935P9NdgvJYpjg3dIifD5jd0x+KhS24EcuUq1MfAwIjxaE1\n"         \
  "DaZ1XIFQvstKIHu6ECKXubXJYbJ5G7JFVWXSU63U+A9I8Jc6DNdin9e0K/Qdqd9H\n"         \
  "sh5xMx5IzXwoU/rfGwWjFqqIs03wOUo8Aw4wNztBS15jb5KusbLKHygyTYGLjZaa\n"         \
  "oqiuxd/6CxIdLDY3dXqBibTN0N0DDBUaICQnRVJtbnGHp7rB1tfY+vz/AAAAAAAA\n"         \
  "AAAAAAAAAAAPHixC\n"                                                         \
  "-----END CERTIFICATE-----"

static ntp_client_t ntp_client;
static int kex_groups_pqonly[] = {WOLFSSL_ML_KEM_512, WOLFSSL_ML_KEM_768,
                                  WOLFSSL_ML_KEM_1024};
static int kex_groups_pqonly_nelems = sizeof(kex_groups_pqonly) / sizeof(int);

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
  countdown_s(5);

  if (cyw43_arch_init()) {
    CRITICAL_printf("cyw43_arch_init failed\n");
    return -1;
  }
  cyw43_arch_enable_sta_mode();
  ensure_wifi_connection_blocking(WIFI_SSID, WIFI_PASSWORD,
                                  CYW43_AUTH_WPA2_AES_PSK);

  dns_result_t peer_dns, ntp_dns;
  err_t lwip_err, ntp_err;
  int ssl_err;
  tcp_stream_t stream;

  // Synchronize the clock
  dns_result_init(&ntp_dns);
  dns_gethostbyname_blocking(NTP_HOSTNAME, &ntp_dns);
  ntp_client_init(&ntp_client, ntp_dns.addr, NTP_PORT);
  while (!ntp_client.processed) {
    ntp_err = ntp_client_sync_timeout_ms(&ntp_client, NTP_TIMEOUT_MS);
    if (ntp_err == ERR_TIMEOUT) {
      WARNING_printf("NTP server timed out\n");
    }
  }

  // Look up IP address of peer
  dns_result_init(&peer_dns);
  DEBUG_printf("resolving %s\n", TEST_TCP_SERVER_HOSTNAME);
  dns_gethostbyname_blocking(TEST_TCP_SERVER_HOSTNAME, &peer_dns);
  if (peer_dns.resolved) {
    INFO_printf("%s resolved to %s\n", TEST_TCP_SERVER_HOSTNAME,
                ipaddr_ntoa(&peer_dns.addr));
  } else {
    CRITICAL_printf("%s failed to resolve\n", TEST_TCP_SERVER_HOSTNAME);
    exit(-1);
  }

  WOLFSSL_CTX *ctx = NULL;
  WOLFSSL *ssl = NULL;
  if (wolfSSL_Init() != SSL_SUCCESS) {
    CRITICAL_printf("wolfssl failed to initialize\n");
    return -1;
  }
  ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
  if (ctx == NULL) {
    CRITICAL_printf("failed to create new wolfssl ctx\n");
    return -1;
  }
  uint8_t ca_certs[] = ML_DSA_CA_CERT;
  size_t ca_certs_size = sizeof(ca_certs);
  // BUG: 04-24-2025, can perform one successful handshake; on second loop,
  // handshake will fail with error code -155 `ASN_SIG_CONFIRM_E`. This error
  // cannot be re-produced with the desktop client.
  wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
  ssl_err = wolfSSL_CTX_load_verify_buffer(ctx, ca_certs, ca_certs_size,
                                           SSL_FILETYPE_PEM);
  if (ssl_err != SSL_SUCCESS) {
    CRITICAL_printf("Failed to load CA certificate (err %d)\n", ssl_err);
    return -1;
  }
  wolfSSL_SetIORecv(ctx, wolfssl_recv_cb);
  wolfSSL_SetIOSend(ctx, wolfssl_send_cb);
  wolfSSL_CTX_set_groups(ctx, kex_groups_pqonly, kex_groups_pqonly_nelems);

  while (1) {
    ensure_wifi_connection_blocking(WIFI_SSID, WIFI_PASSWORD,
                                    CYW43_AUTH_WPA2_AES_PSK);

    // Establish TCP connection
    tcp_stream_init(&stream);
    lwip_err =
        tcp_stream_connect_ipv4(&stream, ipaddr_ntoa(&peer_dns.addr),
                                TEST_TCP_SERVER_PORT, TCP_CONNECT_TIMEOUT_MS);
    if (lwip_err == ERR_OK) {
      INFO_printf("Connected to %s:%d\n", ipaddr_ntoa(&peer_dns.addr),
                  TEST_TCP_SERVER_PORT);
    } else {
      WARNING_printf("Failed to establish connection within %d ms (err=%d)\n",
                     TCP_CONNECT_TIMEOUT_MS, lwip_err);
      tcp_stream_close(&stream);
      goto sleep;
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
      CRITICAL_printf("Failed to create ssl\n");
      return -1;
    }
    wolfSSL_SetIOReadCtx(ssl, &stream);
    wolfSSL_SetIOWriteCtx(ssl, &stream);

    DEBUG_printf("TLS Connecting\n");
    if ((ssl_err = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
      CRITICAL_printf("TLS handshake failed (%d)\n",
                      wolfSSL_get_error(ssl, ssl_err));
      return -1;
    } else {
      INFO_printf("TLS handshake success\n");
    }

    if (ssl) {
      wolfSSL_shutdown(ssl);
    }
    lwip_err = tcp_stream_close(&stream);
    if (lwip_err == ERR_OK) {
      INFO_printf("Gracefully terminated connection\n");
    } else if (lwip_err == ERR_ABRT) {
      WARNING_printf("Aborted connection\n");
    } else {
      CRITICAL_printf("FATAL: UNREACHABLE!\n");
      return -1;
    }
    if (ssl) {
      wolfSSL_free(ssl);
      ssl = NULL;
    }
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

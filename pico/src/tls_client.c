#include <inttypes.h>
#include <pico/cyw43_arch.h>
#include <pico/stdio.h>
#include <pico/types.h>

#include <wolfssl/internal.h>
#include <wolfssl/ssl.h>

#include "pico-pqtls/tcp.h"
#include "pico-pqtls/utils.h"

#define SLEEP_MS (100)

// #include "pico-pqtls/cafiles/rsa2048-rsa2048-rsa2048.h"
// #include "pico-pqtls/cafiles/sha256ecdsa.h"
// #include "pico-pqtls/cafiles/ed25519.h"
// #include "pico-pqtls/cafiles/mldsa44.h"
// #include "pico-pqtls/cafiles/sphincs128f-mldsa44-mldsa44-mldsa44.h"
// #include "pico-pqtls/cafiles/falcon512-mldsa44-mldsa44-mldsa44.h"
#include "pico-pqtls/cafiles/sphincs128s-mldsa44-mldsa44.h"
// #include "pico-pqtls/cafiles/mldsa44-mldsa44-mlkem512-mldsa44.h"
// #include "pico-pqtls/cafiles/mldsa44-mldsa44-hqc128-mldsa44.h"
#if !defined(AUTH_SUITE) || !defined(CA_CERT)
#error "AUTH_SUITE or CA_CERT missing"
#endif
#define CSV_HEADER                                                             \
    "kex,auth,ch_start,ch_sent,sh_start,sh_done,auth_start,auth_done"

static ntp_client_t ntp_client;

#define KEX_NAME "mlkem512"
static int kex_groups[] = {
    // WOLFSSL_ECC_SECP256R1,
    // WOLFSSL_ECC_SECP384R1,
    // WOLFSSL_ECC_SECP521R1,
    // WOLFSSL_ECC_X25519,
    // WOLFSSL_ECC_X448,
    WOLFSSL_ML_KEM_512,
    // WOLFSSL_ML_KEM_768,
    // WOLFSSL_ML_KEM_1024
    // HQC_128,
    // HQC_192,
    // HQC_256,
    // OT_ML_KEM_512,
    // OT_ML_KEM_768,
    // OT_ML_KEM_1024,
};
static int kex_groups_nelems = sizeof(kex_groups) / sizeof(int);

/**
 * WolfSSL will call this when it wants to read stuff
 */
int wolfssl_recv_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    if (!ctx || !buf || sz <= 0)
        return WOLFSSL_CBIO_ERR_GENERAL;

    tcp_stream_t *stream = (tcp_stream_t *)ctx;
    size_t outlen = 0;

    err_t err = tcp_stream_read(stream, (uint8_t *)buf, sz, &outlen);
    // DEBUG_printf("WolfSSL wants to read %d bytes and TCP received %zu
    // bytes\n",
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

/* Send a short message to the server, then check if the response matches what
 * was sent
 */
static int test_echo(WOLFSSL *ssl) {
    uint8_t msg[] = {6, 9, 4, 2, 0}; /* NICE is not random! */
    size_t msglen = sizeof(msg);
    uint8_t cmp[128];
    size_t cmplen;

    int ret = wolfSSL_write(ssl, msg, sizeof(msg));
    if (ret <= 0) {
        DEBUG_printf("wolfSSL_write returned %d\n", ret);
        return ret;
    } else {
        DEBUG_printf("wrote %d bytes\n", ret);
    }

    ret = wolfSSL_read(ssl, cmp, sizeof(cmp));
    if (ret <= 0) {
        DEBUG_printf("wolfSSL_read returned %d\n", ret);
        return ret;
    } else {
        DEBUG_printf("received %d bytes\n", ret);
    }
    cmplen = (size_t)ret;

    if (cmplen != msglen) {
        DEBUG_printf("expected %zu bytes, received %zu bytes\n", msglen,
                     cmplen);
        return -1;
    }

    if (memcmp(msg, cmp, msglen) != 0) {
        CRITICAL_printf("tx and rx do not match\n");
        return -1;
    }

    return 0;
}

uint64_t current_time_us(void) {
    absolute_time_t now = get_absolute_time();
    return to_us_since_boot(now);
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
    uint16_t round = 0;

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
    // DEBUG_printf("resolving %s\n", TEST_TCP_SERVER_HOSTNAME);
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

    // main loop
#ifdef WOLFSSL_HAVE_TELEMETRY
    printf("%s\n", CSV_HEADER);
#endif
    while (1) {
        ensure_wifi_connection_blocking(WIFI_SSID, WIFI_PASSWORD,
                                        CYW43_AUTH_WPA2_AES_PSK);

        ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
        if (ctx == NULL) {
            CRITICAL_printf("failed to create new wolfssl ctx\n");
            return -1;
        }
        uint8_t ca_certs[] = CA_CERT;
        size_t ca_certs_size = sizeof(ca_certs);
        // BUG: 04-24-2025, can perform one successful handshake; on second
        // loop, handshake will fail with error code -155 `ASN_SIG_CONFIRM_E`.
        // This error cannot be re-produced with the desktop client.
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
        ssl_err = wolfSSL_CTX_load_verify_buffer(ctx, ca_certs, ca_certs_size,
                                                 SSL_FILETYPE_PEM);
        if (ssl_err != SSL_SUCCESS) {
            CRITICAL_printf("Failed to load CA certificate (err %d)\n",
                            ssl_err);
            return -1;
        }
        ssl_err = wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME,
                                     TEST_TCP_SERVER_HOSTNAME,
                                     strlen(TEST_TCP_SERVER_HOSTNAME));
        if (ssl_err != SSL_SUCCESS) {
            CRITICAL_printf("Failed to load SNI\n");
            return -1;
        }
        wolfSSL_SetIORecv(ctx, wolfssl_recv_cb);
        wolfSSL_SetIOSend(ctx, wolfssl_send_cb);
        wolfSSL_CTX_set_groups(ctx, kex_groups, kex_groups_nelems);

        // Establish TCP connection
        tcp_stream_init(&stream);
        lwip_err = tcp_stream_connect_ipv4(&stream, ipaddr_ntoa(&peer_dns.addr),
                                           TEST_TCP_SERVER_PORT,
                                           TCP_CONNECT_TIMEOUT_MS);
        if (lwip_err == ERR_OK) {
            INFO_printf("Connected to %s:%d\n", ipaddr_ntoa(&peer_dns.addr),
                        TEST_TCP_SERVER_PORT);
        } else {
            WARNING_printf(
                "Failed to establish connection within %d ms (err=%d)\n",
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

        // DEBUG_printf("TLS Connecting\n");
        absolute_time_t tls_hs_start = get_absolute_time();
#ifdef WOLFSSL_HAVE_TELEMETRY
        wolfSSL_reset_telemetry(ssl);
        wolfSSL_set_time_cb(ssl, current_time_us);
#endif
        if ((ssl_err = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
            WARNING_printf("TLS handshake failed (%d)\n",
                           wolfSSL_get_error(ssl, ssl_err));
        } else {
            absolute_time_t tls_hs_end = get_absolute_time();
            uint64_t hs_dur_us =
                absolute_time_diff_us(tls_hs_start, tls_hs_end);
            INFO_printf("TLS handshake #%03d success, dur=%" PRIu32 " ms\n",
                        round, us_to_ms(hs_dur_us));
#ifndef USE_COLORED_LOGGING
            (void)hs_dur_us;
            (void)round;
#endif
        }
        int echo_ret = test_echo(ssl);
        if (echo_ret) {
            WARNING_printf("test_echo failed\n");
        } else {
            INFO_printf("echo Ok.\n");
        }
#ifdef WOLFSSL_HAVE_TELEMETRY
        printf("%s,%s,", KEX_NAME, AUTH_SUITE);
        if (ssl->tel.ch_start_set) {
            printf("%" PRIu64 ",", ssl->tel.ch_start_ts);
        } else {
            printf("-1,");
        }
        if (ssl->tel.ch_sent_set) {
            printf("%" PRIu64 ",", ssl->tel.ch_sent_ts);
        } else {
            printf("-1,");
        }
        if (ssl->tel.sh_start_set) {
            printf("%" PRIu64 ",", ssl->tel.sh_start_ts);
        } else {
            printf("-1,");
        }
        if (ssl->tel.sh_done_set) {
            printf("%" PRIu64 ",", ssl->tel.sh_done_ts);
        } else {
            printf("-1,");
        }
        if (ssl->tel.cert_start_set) {
            printf("%" PRIu64 ",", ssl->tel.cert_start_ts);
        } else {
            printf("-1,");
        }
        if (ssl->tel.hs_done_set) {
            printf("%" PRIu64 "\n", ssl->tel.hs_done_ts);
        } else {
            printf("-1\n");
        }
#endif

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
            wolfSSL_shutdown(ssl);
            wolfSSL_free(ssl);
            ssl = NULL;
        }
        if (ctx) {
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }
        cyw43_arch_poll();

    sleep:
        // DEBUG_printf("Taking a nap for %d ms\n", SLEEP_MS);
        // printf("\n\n");
        round++;
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

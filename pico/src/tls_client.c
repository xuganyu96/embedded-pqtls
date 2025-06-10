#include <inttypes.h>
#include <pico/cyw43_arch.h>
#include <pico/stdio.h>
#include <pico/types.h>

#include <wolfssl/internal.h>
#include <wolfssl/ssl.h>

#include "pico-pqtls/tcp.h"
#include "pico-pqtls/utils.h"

#define SLEEP_MS (100)

#define CSV_HEADER                                                             \
    "kex,auth,ch_start,ch_sent,sh_start,sh_done,auth_start,auth_done"
#define KEX_NAME "hqc-128"
#define AUTH_SUITE "mldsa65-mldsa65-hqc128"
#define CA_CERT                                                                \
    "-----BEGIN CERTIFICATE-----"                                              \
    "MIIV8TCCCO6gAwIBAgIQHzV+heXCeM+Xweu2376oOjALBglghkgBZQMEAxIwbzEL"         \
    "MAkGA1UEBhMCQ0ExCzAJBgNVBAgMAk9OMREwDwYDVQQHDAhXYXRlcmxvbzEjMCEG"         \
    "A1UECgwaQ29tbXVuaWNhdGlvbiBTZWN1cml0eSBMYWIxGzAZBgNVBAMMEiouZW5n"         \
    "LnV3YXRlcmxvby5jYTAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAwMDBaMG8x"         \
    "CzAJBgNVBAYTAkNBMQswCQYDVQQIDAJPTjERMA8GA1UEBwwIV2F0ZXJsb28xIzAh"         \
    "BgNVBAoMGkNvbW11bmljYXRpb24gU2VjdXJpdHkgTGFiMRswGQYDVQQDDBIqLmVu"         \
    "Zy51d2F0ZXJsb28uY2EwggeyMAsGCWCGSAFlAwQDEgOCB6EAAnwnWyCSfBWlpN4Q"         \
    "6iWIL1OBzm3rHVtuiNkJveGUHvFEyeI/u//QreZKCKLo+9aJGHRiUwoqL5YphzO0"         \
    "5fdFgqNz/S67dtoHSrF2AR/N1gDibM1iNKyHcOldBARQ9OsQcdh9Yersrp7xFddv"         \
    "eBiXL7uOEW8bsva7uE3FHwsxy4fQxemQOycW0d5Z83liX+LBq/pICZzB4OO32ATN"         \
    "ozbhChSkNKo/sZCVm4ZKCteHgzl47XYRB6ayvnC+Auc+1u8qcZAd/63EpE0m5EeP"         \
    "DPNoL1MroUPlXTYdzUztu3k9OmfeNVnWVoHXdBSeAnO8XZeUv0p221N24CNc02UP"         \
    "0wuIklmX7SNGsSbkC1PQTJG4IMQrYoQmcO5hzMPyY5k1beR/65X1hUPbbVhU3pOQ"         \
    "VTWaC2YZAGwsDgeepQxSSl7PlXgeaszog9Cwq4J0Vphv6xmZVe7lx3NLJt6vSc3f"         \
    "DI/RkUYhdQGH9N99T3mo03j8IyuDiww3DtZW/aSHtLvA3MikYfr35RQc/jKApTps"         \
    "yXgGiODN9qRS2SXX4FQQcCqYGN0uybTHigSNqUhUPNBFmN7gBvtd1Pozb1K2HYig"         \
    "ukw4PczF8JoS6871X26JYph+mt1sjP8OWcrERSE627KeLYxTXiFeqDGbJhk0dUQM"         \
    "kS9qDullXcJ+CB5kF1tKLIYq+Zlz1eXwuxORDYtYTVmqJUeJZkbLajJ10Bp+nOcY"         \
    "9cqRv/ybEpg0ZTXxiXcRyAOBEvH8dymGlxeEk9D5nSKHDzQC3B88qvVwP7ewcUIX"         \
    "le6JnNoQfl5awV0ADyazgiqb2o8pxiIU/qDXpZEAJ1liOmy5gqd6bjj7jX9FoitJ"         \
    "VPLK28a4jbTIB/qZRztnrxu5c7vGDSdvWoUx4nnY01+L2Qsie5TmWpKC6quXIebn"         \
    "oVZpDUlnzdqQx45+XksItA6/DlGAkol2fI0KV07D1n1tXvoNdH8zXjRrQnWQzuVU"         \
    "zH8QNaAzhU/vEvDzLNBzwl+OVdIDv1TYuyl8Q4BXGCGMeyBESfk06ilDRnaeUYC9"         \
    "PhDFF2BsmHm6v7Z6cPC4uduJizb5+d3j04BJTefbZ4Z09AiMLZ46ewJoR0FDE77n"         \
    "NCWPVnhDi78nlgeWPvC24SD4QFpbKmf1OaHd8tfL51ux9nAFSJEHur/o/EMayuvK"         \
    "Pq88HlmKabtY+Ud+v6gldUoQ4lbZ1qiZK6G05hIUv+0u1AhZ/PtSmgfu2d/dgmvR"         \
    "Xsh/m+ILUUp1bSuVAAyAkjD+zo4t3QAeVMx8CAvM1Cq8Bd1RG0II++bxkoI+btLt"         \
    "7JLN/PoSDtH36GcdrPAVnb9Gl6VUl3EI1XS0MQsYgQoRPBI7Cgb6DJ1HPga2c0b/"         \
    "5VO3QNP0jeWHdZKnW2tFzYIupQVx/jfCIXpvfadSRzyovFoKIQBFx3/e6Mhkrjqp"         \
    "k65dZnOm0V4gfd86HLlq4brDQY3v0qRMT5YQJ6A4mJspWMm8uxTjtSfePC6L744Q"         \
    "pDge2M+5z6VkXsiMqKu5wTaaOgKsM8LSXccVtRsbYnPzf4ByR3euBU/xQEZmUGG7"         \
    "f1APlZ0xMfYmWUwdYyglMKNMrzz6tE7r3E/yh3WmIVj4Zh++4x1sCZdXTtZNkjNU"         \
    "aYCVlI1aRjJWuEeg4thIeJLqB+S9nsfvy8r5tEmx4o8eWQt9pOg4sq/B5/2tVf2X"         \
    "8UDYFTYLnNpntjs+X3A2m+VJg49/sv/Rnpdj0hyaJk0SBQ2VpzbFqbNy2IYoYJrc"         \
    "HvqwBsL+DRYIgEGOxV7yg6LXvky2jxC/QApA0VWKWAtli4Cny4L+ARDBI0+FDA33"         \
    "4l11V/ze1OFCPR/3eh8tXQCBNwRddi//KMTKOn5fVn3VEon1s91K74H+SHVgGEN5"         \
    "x4cckiA//pn7IW0TLEHwoY9v83u3MbpMPxl6oC1PMO2oeYBwGIouFlx+zWelImdQ"         \
    "t2AGjI9UyDcgjYboM6ceNbUrFfmwVj9TvZg4zpDVQU8K02IM9G6OsGOBwHIvE2qg"         \
    "q7FFPQ7l25v6m3ZOMCuRf9jnHuKyzC9MmYs9Bnd7AeDQKuEzJx5pMh3YYxJ65B2F"         \
    "TOLfg+i/Utvoopv/5n+hFYjBaQl7KUnE7ITYEPx56KTFHy7O2uUvbDg0e+N/zKua"         \
    "LWk2uuSA9TDIM/9QFWOjzwtAMLV4uYei6cUdouPAOH3BuWJlP6aZgTJIWwE1SUJ0"         \
    "/xVVi6oNlJwztXzG2de60tMGtLzFjZiqndtGvfAlAXfD0Ctdrz+Z0Gw9gcdQQ+aw"         \
    "FB8lirqHkuzNGIirN7P8H3IqenF0KzHWQR9nqrmuhcQgoey5bbQ0UaO3zwwvOi1+"         \
    "fX2OSQY29rP1MzGrdxkKv2mT+q9NtewtOmicy1VTLY7w+dT/3Aob/Pb8a+jEJBwR"         \
    "IMumOnChuc5VTf88vHYNUD1ieQwipgZIreXWb/rhh8N6TejHexjI8GawltQdIeRt"         \
    "mwZt5gqb8+OV3jToyNsAZRng/9DL5MRcduTbd7JyV4D/m+sz0fi5yb73qCq2vPO6"         \
    "VPMM3qa0hc/7UwtTjs/UpJ66IDVhLDFbGj9kWrjowTVRIuHyhJiAMbD9qxUMWVf+"         \
    "aI2bUb5saszBJxVPn7xOi3bfMA2jEDAOMAwGA1UdEwQFMAMBAf8wCwYJYIZIAWUD"         \
    "BAMSA4IM7gC/8PbcQ0PlcTgWpkZj6HN+lfgHuIpZ+KTi7gk2iWhMZFS+yCyaTJP+"         \
    "QRHWxfhI8xqqvC4nqN5cDM8Dr7XfAdz5Rogfap4e9H16RnwumbtsIGI781EVJM68"         \
    "45ig57L3f+mf1xm6y0ZVRCkKIiqCfFUKXDb6TYTcFwttOTo9/zwrlXOGy4V7znlv"         \
    "+VBnFqQi2SZJi7x0TJKr2CM//s44TKkCYR4VhSm0LeVJQ8hKOPz16nRF9fiYWfjn"         \
    "yG8ZJQcBziGErhaMj8gTRIM5CkLBCGdXEAOD1N+zyOMCxo5DpA2Nc0/XaFamPQCb"         \
    "nmzDpnGReBD/Di7z6lrDrmp3wGtxdOIXiOr3NuLcSvH4dFXgST4leybbzvhjhuQu"         \
    "HmLcto6PPPCGkj8eZaE8rqCj5EZSaiDJSMuWtY21JBOwpHf6+RhhtuAdgWfiRkCh"         \
    "Oa8R8r2JDwPp18arh5hjpTv4rhUsovjdKBGTkyo65HSqSLQSrvUGS00jtSvTB3nC"         \
    "oWtDtrn/OOMQygi+nMZa8G/2IkLxnNW/t28/SyP93SCE32b2ieihzkNmCgpPPkir"         \
    "dh/Ryyzt8Rx0azJBCHjeNjCyPYU2rLjm8VhNYNtABEu964QTd0Jfr2y2vS28HBlD"         \
    "14l1DhLtbwF28wXCnwad+zupJBlFoWMmT4NORMw42gWG8pbPKFnlI7XOxygcEvMU"         \
    "sC6t10Z8iPErmF0BW6ZpFK6kksrdqoZGEKQ0/RrF9zAJ7uqVy2jQGzDHRGUOqKET"         \
    "FhZcfoGnK0sYo8GkVPFbA9wLvC57vwCArO2fUOYgP/VirPmxCvj7CifAKg0YGKfL"         \
    "9M9yiRpqvX55ras305uYodcN2EU+Tx2Oh4mJA1468hLxshu87yj+om5xMQhu5k0T"         \
    "QA6k/ANys7KqZgTJOt5Ofwfgnjg1s+HNFKGR1Tgekc2Unmg5oBlYOiwkCBVwM3mz"         \
    "WemfBj74qgBrwV6P/6nkj3M10f+mit5/xOzRK+ZSnhPX/BoSbiIb3nf14it6pAmF"         \
    "UaVg+sPfY80RAPgYRSX/8S6mZVMo6cMZOfCKrDg5U/wdOWzLlJJL21dL5zaMhLvC"         \
    "STU+YqesHsMqhFSzJd5XLDscYYhkJhoSgFlP5kDI/8IFt4SaerTfB7ITLz8ZdKG/"         \
    "vbVAVOioYJphV43aNIkIzTBmBDCXhrlO05+qX2vzY7ALk1xQLDaE7hJ57d8fZ+PN"         \
    "EOwuhBP73ffoP1rZDgak5wI7vnYKWOR0/nHNqvWZ/+VLgGD378xbMk23QoBas7p3"         \
    "yUvl30xfTBK8H6pQEiHofEaFKeOYMNAOT0hpF5KgPTQIIC6lKyPB+YGkf3C11+nN"         \
    "+SCyIdHgQg2QJCQbMBZs82FVGOBvsNeBFbuWNWPzB4MeYpBoOYAcQzKMW9ga4PJ7"         \
    "lp5COlKLn2yPEOofCf4rWTBaJcluZM0pOFndc1JI5mppmJPpHHIaS59F15BYn/bV"         \
    "ik+kzx34w3TE+jkCF4nqu8eC4ym5T01sb0jymBMkEZlHcErAHe/Lpwj7v2/qgubQ"         \
    "lhu6ukF9E2np0IvDdANgjDfEodf5O7Yd6LZIdk0nWMsNQ7d60BK2hk3XOZ+mlI8p"         \
    "QyeGD/aWSx7NImNwtTlT/hWi3pI7oUs36dQFFYDeb1NAz6nZ1Off+dzREV4v4Mnl"         \
    "jkWImsIqQ1n3XvkaI8HuNWyhaq6iZxBncm7HO7xx2+/FoFB1Yqe6NRmCCg5kNy05"         \
    "bUg+em8wZ9kAbIiQonwiuaz3m4W48igPKJ6dMTe9O9CBjbP/4PPxV3M24VVoDT0F"         \
    "PtiM0ow72MK2bgL/6S6PP/8p3u4wQFbfIQ6IritAq2KouCTcTVvimKDM96tMTjRn"         \
    "DToCqX9Cr6gra2FOoB7BERBKO6Yc4B6jrvY9jSio+xOIfyz9JD1BxvuLh12w6icG"         \
    "OeSDnwmAjDYPjZFKrO5VLV5e1tzXgu+uz9cOd7PkXyEzVbobLciTVnlQUg6t0ysY"         \
    "AaIgTKpVlTzm0osVe64F+tLGnMxoLFdlI+rBREDCTYgrgeY+oYNF5tYwdwiOsGZt"         \
    "ow6Uzf6OQFHoWgpH22APsCdU8L5jr9i0k3hzwBbh3H5m2d9JHSrCCEM0uT8voo4p"         \
    "9Jaw8+O62Nno3QriuoNTHGb9iq9eketvuMfdgSU75h6cbW7xHKtYIJv9ymxdapv4"         \
    "e9tj6Hq0qiIP6jMWdZWNAV7qTwOzXrve8YLZJgPb06Gg+9bYd8Ed37GXeBwaO6Qb"         \
    "iUfNdMiIVan9KDerQgmaO7JHeR97jUKkH3N4NqVrmmD5vAnyOov86ABraYD9fnrJ"         \
    "8Ior9SOfnZ3ZCjx3R93PAHjdkjO6SleZnOfjCBofuXcPd3or52muL3J3a1iouj1+"         \
    "BAyizNs20mhyFwO0a5k5NF6uVOslwrrlh9QPTEPstiuF1syLJPqPAwCfPTUICHAw"         \
    "5NBbm5erf+D7TH79FfUzXcrLFJrRVf7LySiqJ1gFamrRog88uh9QzeJyISDdX8LC"         \
    "Cb+q++oqYdqLG3v72lxhfl4rdntsM6SLPitakHccFNKISuRssG+kvYcQJVfM6Qbc"         \
    "Zn3Uv1EnhUFxCtAwjvzNV38LKh3WzewbGo+FRGtHRjItAvJ8YgoUtvcoZ8eZM1+k"         \
    "jLIf7CLewT7ay686QDLtM0Pe7bmfZOMdnROSq7UJ/MnXPxkdFQSFPUejKeJQ305Q"         \
    "aFD5lLET3IvQ1hpoGvMEw7LmoF/3v0XyBkAdKrMzJUHn3a0teLFxoz9kDbXk8xWI"         \
    "BeY//aIHyyRqkoD33ur9MtVjPpA6Nsg86tJK45zADKctA+/tj+3FO0Xh9uP75ueB"         \
    "ghzbJTplgnc/hXEiO9u7i0IkOfOBp2RYkxuJzORvCWxquxAkXNikDTzuqc+cuFqy"         \
    "iUDvTgwR7iuqBIS8JfZjBGbaR0wiVlgBPqzuJIgEeeZ4rHFdG2Ac0Mh4knoWHPXk"         \
    "kjEfYRWwqUkzALe3jPuRFx6vpm9w3oGYizpf9JFRnQbgu7M2vfyfXhJC8anDZkQx"         \
    "CzGRjv/80Wj/VzM+x4/a6LxGr7IMXURROXWKoFnhTUHt0AnP+bF22m7yyXgOuJ7y"         \
    "9DzTlziGQuyUbLXwoAKDCpkf5wQjSeeUcYsPAo9dNcuS0f5pmn9yqPMGprScLr5M"         \
    "oiSZpxlIQxaT8Q+OrIhQk3C5wDdsIKve4IJPPfqvJOH6M0qjyuhCUxLxTJqZtwTF"         \
    "ux5Ulanbb2fSMyx1CxSbFOYSWh4+iI6K93rn8zNVzi1O6dmf3DPVXmMkayFSuZuK"         \
    "0H2demltX2te+PCSYPkNqRZ3XsSGewNC0PYc2w0790znG0NpsQdjfAz10240q/le"         \
    "WYC/cnc/5eSmreCrgLTFL1KdM4qh/gm8KkcCd77DVxQ6gEkDdMDt73+fmHDD5AvH"         \
    "QssB1EDV9PLk5swu2myufZZsFRDStciOygt6LESI8iqNl27xqhBDg6nmg6gCqCKo"         \
    "5X3Vkop2yJeBwHVAy8ZhvPkx+iOzGQhtoECLE7XZojhYWcgySWQifEHx1DYVKty7"         \
    "T49ba2A5sYH0R3ymFGFImb8V9AgchIiiBbhxi3usWPO+L1SPGkJ5RMIqOxXw3ay/"         \
    "DJczF0Bc8kZxMyg29MOkm5q0Cu/CEsp/nnksfKHmvSDya2qCpsMzgRQrQNnR6Xg+"         \
    "xTINwfEZzFI9AdqK8Tis6BTLPow5yRaDEsUZpShzOd8N9ORvFuQAgKVoPe4VLXvl"         \
    "NkQySGoEAuw+mf+f0JoKXwxAF3PwfKmHolF0nVxNSQ1ogJSIH2LMiBvBunof0TkQ"         \
    "9UWqI35s5DTST8yBSMnVKXrjdX/xJocnU8l2JWhDeEUGzN8OshED7ASuuZi7CeGV"         \
    "1PpahHQetz1rbBhFB6uWHRAR2w1jb21tYcyCbhoTpmhe6UX+bD1G6efUqX3TuMu9"         \
    "sjpvo741KhkmfwX1bGKWqsnl3N8ceguIFgXNVsqA5Q1ofQ+wNJFdcHbu2UnTNyQt"         \
    "Uf2AmuAlk8RE/MbbRjlFkvoHlwwhKk/c+rqhMi5saFbPYhx5PmmzsvJjoZxbWWKO"         \
    "oqgNuj6aGHjog4zyQ0mRZVRRnVxYNTngwNU7j09716bUGiyAHKFUL3bi8qzoCRmu"         \
    "593I+wdrZzwqKI05i3RXtm75HBiSu449rPw7N8PLhDuBwVlIVzUt/6v7FyY152pL"         \
    "1Jy4+G8jIk1dNur5B+ZzUU0XxnADyN1AoBuAorUKeNhBw1e/4hduuGpr70Iuq2aM"         \
    "j1J2L/Y67cYcvpB44faEa0AtNQhWbh+stzvRSQR93ZwYe7WoGA53UF8GjWPBnbZp"         \
    "HA9f05nPKnDv+2GsY4Mwd9fCEp8gEeVPLvII88qDMA9WgWFZm7ha+g83aHWFksBp"         \
    "bI+Xv9HwTl5tvsrldLtfY3ypubvn8gItLk5UZorX2d4AAAAAAAAAAAAAAAAAAAAH"         \
    "DhQWHig="                                                                 \
    "-----END CERTIFICATE-----"

static ntp_client_t ntp_client;
static int kex_groups[] = {
    // WOLFSSL_ECC_SECP256R1,
    // WOLFSSL_ECC_SECP384R1,
    // WOLFSSL_ECC_SECP521R1,
    // WOLFSSL_ECC_X25519,
    // WOLFSSL_ECC_X448,
    // WOLFSSL_ML_KEM_512,
    // WOLFSSL_ML_KEM_768,
    // WOLFSSL_ML_KEM_1024
    HQC_128,
    // HQC_192,
    // HQC_256,
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

#ifndef PICO_CAFILE_H
#define PICO_CAFILE_H

#define AUTH_SUITE "ed25519-ed25519-ed25519"
#define CA_CERT                                                                \
    "-----BEGIN CERTIFICATE-----"                                              \
    "MIIBrDCCAV6gAwIBAgIQQiROwBifSeApDDyvfV5dTjAFBgMrZXAwbzELMAkGA1UE"         \
    "BhMCQ0ExCzAJBgNVBAgMAk9OMREwDwYDVQQHDAhXYXRlcmxvbzEjMCEGA1UECgwa"         \
    "Q29tbXVuaWNhdGlvbiBTZWN1cml0eSBMYWIxGzAZBgNVBAMMEiouZW5nLnV3YXRl"         \
    "cmxvby5jYTAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAwMDBaMG8xCzAJBgNV"         \
    "BAYTAkNBMQswCQYDVQQIDAJPTjERMA8GA1UEBwwIV2F0ZXJsb28xIzAhBgNVBAoM"         \
    "GkNvbW11bmljYXRpb24gU2VjdXJpdHkgTGFiMRswGQYDVQQDDBIqLmVuZy51d2F0"         \
    "ZXJsb28uY2EwKjAFBgMrZXADIQC1wKTkXoWgx7SZoxO1kfD9WaJJOj2mj9Q7Nx2l"         \
    "1uUQ/qMQMA4wDAYDVR0TBAUwAwEB/zAFBgMrZXADQQCYiSeuN6tuIquxsymY8zG/"         \
    "SO3BRXsa2H1E62erF/fGmDJtW4NEZo9JuxUiXTpOl7jmsXmbTaeDd5W8D4vr0R0N"         \
    "-----END CERTIFICATE-----"

#else
#error "duplicate root certificate header"
#endif

#ifndef PICO_CAFILE_H
#define PICO_CAFILE_H

#define AUTH_SUITE "sha256ecdsa-sha256ecdsa-sha256ecdsa"
#define CA_CERT                                                                \
    "-----BEGIN CERTIFICATE-----"                                              \
    "MIIB7DCCAZKgAwIBAgIQJlHKQX8eJwCf/hW3kExsHzAKBggqhkjOPQQDAjBvMQsw"         \
    "CQYDVQQGEwJDQTELMAkGA1UECAwCT04xETAPBgNVBAcMCFdhdGVybG9vMSMwIQYD"         \
    "VQQKDBpDb21tdW5pY2F0aW9uIFNlY3VyaXR5IExhYjEbMBkGA1UEAwwSKi5lbmcu"         \
    "dXdhdGVybG9vLmNhMB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowbzEL"         \
    "MAkGA1UEBhMCQ0ExCzAJBgNVBAgMAk9OMREwDwYDVQQHDAhXYXRlcmxvbzEjMCEG"         \
    "A1UECgwaQ29tbXVuaWNhdGlvbiBTZWN1cml0eSBMYWIxGzAZBgNVBAMMEiouZW5n"         \
    "LnV3YXRlcmxvby5jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHmK7jsd5Whf"         \
    "zvCLuitVvOMkUaFjsXHjJ1ANzijiAjVNs7kyYQDhxklaS2Wf3CmJbQFUqp8ucnZu"         \
    "p4Ye0FWo/iajEDAOMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAKlf"         \
    "QNK6EnBNTH4iKb8YLPeQkp20tgl71vYt+D46D3WRAiBmXNGd3G4ge8iIo/U43Eju"         \
    "TpynKNj69qJG41CBa8OgUA=="                                                 \
    "-----END CERTIFICATE-----"

#else
#error "duplicate root certificate header"
#endif

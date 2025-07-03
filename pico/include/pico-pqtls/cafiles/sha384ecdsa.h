#ifndef PICO_CAFILE_H
#define PICO_CAFILE_H

#define AUTH_SUITE "sha384ecdsa-sha384ecdsa-sha384ecdsa"
#define CA_CERT                                                                \
    "-----BEGIN CERTIFICATE-----"                                              \
    "MIICKDCCAa+gAwIBAgIQfCK36zeQtUB1+iAfHehTozAKBggqhkjOPQQDAzBvMQsw"         \
    "CQYDVQQGEwJDQTELMAkGA1UECAwCT04xETAPBgNVBAcMCFdhdGVybG9vMSMwIQYD"         \
    "VQQKDBpDb21tdW5pY2F0aW9uIFNlY3VyaXR5IExhYjEbMBkGA1UEAwwSKi5lbmcu"         \
    "dXdhdGVybG9vLmNhMB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowbzEL"         \
    "MAkGA1UEBhMCQ0ExCzAJBgNVBAgMAk9OMREwDwYDVQQHDAhXYXRlcmxvbzEjMCEG"         \
    "A1UECgwaQ29tbXVuaWNhdGlvbiBTZWN1cml0eSBMYWIxGzAZBgNVBAMMEiouZW5n"         \
    "LnV3YXRlcmxvby5jYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABCttQeJ7nzDWJSSq"         \
    "ikF4TjwnFn1DchpkOpibKq/S2XpNZjZlgEMRg/kILrJYeNLzaA7T61oZD6GqI6QJ"         \
    "LKWH/iDlinsI4JwtmYUVEL6HXkCr9NSlMRBD/NGxH1R0NYv17aMQMA4wDAYDVR0T"         \
    "BAUwAwEB/zAKBggqhkjOPQQDAwNnADBkAjAIoQroof2w3uVaRSfpDBuBKe6lUB/K"         \
    "CM017R1NzJZzg+3kVaFbED5ynsHdhtacSIgCMF6nbIidu8EXWEmzzyXZpIeHhLuQ"         \
    "O+fJ1AcQe1iu2EuYleWKNWd5uzvrBfH+uiyK2g=="                                 \
    "-----END CERTIFICATE-----"

#else
#error "duplicate root certificate header"
#endif

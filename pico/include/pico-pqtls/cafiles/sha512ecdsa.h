#ifndef PICO_CAFILE_H
#define PICO_CAFILE_H

#define AUTH_SUITE "sha512ecdsa-sha512ecdsa-sha512ecdsa"
#define CA_CERT                                                                \
    "-----BEGIN CERTIFICATE-----"                                              \
    "MIICdDCCAdWgAwIBAgIQaqHl7cPJTPZEHKnqKS8CGDAKBggqhkjOPQQDBDBvMQsw"         \
    "CQYDVQQGEwJDQTELMAkGA1UECAwCT04xETAPBgNVBAcMCFdhdGVybG9vMSMwIQYD"         \
    "VQQKDBpDb21tdW5pY2F0aW9uIFNlY3VyaXR5IExhYjEbMBkGA1UEAwwSKi5lbmcu"         \
    "dXdhdGVybG9vLmNhMB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowbzEL"         \
    "MAkGA1UEBhMCQ0ExCzAJBgNVBAgMAk9OMREwDwYDVQQHDAhXYXRlcmxvbzEjMCEG"         \
    "A1UECgwaQ29tbXVuaWNhdGlvbiBTZWN1cml0eSBMYWIxGzAZBgNVBAMMEiouZW5n"         \
    "LnV3YXRlcmxvby5jYTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAGggWYafJsxS"         \
    "pl3VZ35JRoSgbxEoIKN1pqzCMME2jRSvMY8/mMcHdlg1B68tcjl9GmSBnl4LdDk1"         \
    "ZHKYCdrSZMuPAYhVJY5XHs/CSn3cArlFxyiNADKAUXPYvmpOx1vihm3YseVpWbRm"         \
    "sVI6Jw+fg+hYdFfKrsHoAaWNl9i6TcoGXqdOoxAwDjAMBgNVHRMEBTADAQH/MAoG"         \
    "CCqGSM49BAMEA4GMADCBiAJCAaJRy4Fpmr7erGryGXdki0Iil34TLuogox1GK1jo"         \
    "TwVNVe0RTaAzoKrCMHXj2y0W37WkdKW5IAXhvUdH3GjMZodAAkIAiJNIu1inElmg"         \
    "lMUYZ8H1we0aspBUxhzY5aTioFoV1/HSLjYRi8TxjEacb6DD/hgCtUZVYBAQUtVG"         \
    "CyJPEW3bKqk="                                                             \
    "-----END CERTIFICATE-----"

#else
#error "duplicate root certificate header"
#endif

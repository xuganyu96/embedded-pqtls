#ifndef PICO_CAFILE_H
#define PICO_CAFILE_H

#define AUTH_SUITE "rsa2048-rsa2048-rsa2048"
#define CA_CERT                                                                \
    "-----BEGIN CERTIFICATE-----"                                              \
    "MIIDeDCCAmCgAwIBAgIQe627w6xXnaO9WP6Ltk/JxTANBgkqhkiG9w0BAQsFADBv"         \
    "MQswCQYDVQQGEwJDQTELMAkGA1UECAwCT04xETAPBgNVBAcMCFdhdGVybG9vMSMw"         \
    "IQYDVQQKDBpDb21tdW5pY2F0aW9uIFNlY3VyaXR5IExhYjEbMBkGA1UEAwwSKi5l"         \
    "bmcudXdhdGVybG9vLmNhMB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFow"         \
    "bzELMAkGA1UEBhMCQ0ExCzAJBgNVBAgMAk9OMREwDwYDVQQHDAhXYXRlcmxvbzEj"         \
    "MCEGA1UECgwaQ29tbXVuaWNhdGlvbiBTZWN1cml0eSBMYWIxGzAZBgNVBAMMEiou"         \
    "ZW5nLnV3YXRlcmxvby5jYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB"         \
    "AMVTaSAryefDt7AiBiZCmXrJOxqOPGB8+wDiQrwFmOsQxRAWYKcil+3hfzJ+/Tc5"         \
    "2X9UAVicqabqR9FIARyEOHNJj8aoyQh9cQDX9LN6nwidC3AHCT9fuc6YX0v1klwI"         \
    "DEJpetWHNQh6ydiJLl2lzArHQ2MrkV9HE2be1yhxPjv305s4adkezsvDehRNJEc0"         \
    "gp7kM+cv93VN4XcotaT9boZvENAZGajwEsPKtm+b1XY+8Cp0baJlaA+V2dMeXsL2"         \
    "hs8InF0OHIBEX9bie2KHShhBXYOZOJNT3Wgqa/qmZpFpECYA14S3VBl7M2M+RduB"         \
    "8QyqQL5QG/D272zpnJxgEj8CAwEAAaMQMA4wDAYDVR0TBAUwAwEB/zANBgkqhkiG"         \
    "9w0BAQsFAAOCAQEAl+SS96ICI1jIZ6Ghwk1WinYXXNuxcZ9gE5xKVDw88j+ZB7/D"         \
    "8EgYMq0QxS2gsf3de+pAjQcAPHHv49gJ+U0y22XB4x/iqRuiKr0BGnQfOv0C8WAQ"         \
    "x/pro/fyTDRT4BpTf64+pWdCBQ5DzuPx/rgAV0ySd97LatXaNH47UcNcYvh6WTIa"         \
    "dkJT1w6dbTOTT0v3C7knxL2198zqkST0HcuNOPWdYafQbngnfWOYDvAy2lWVCzTT"         \
    "57YTvx7aalC1tSdVQwYUJX9GboquY3JUvPSX81Hhjfru6WB6feYt9h4F6guLYGwl"         \
    "X2lahuDjPxD7N/Rr8cVQhi/apQsgB3RXBqEl+g=="                                 \
    "-----END CERTIFICATE-----"

#else
#error "duplicate root certificate header"
#endif

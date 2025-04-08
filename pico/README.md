# Embedded post-quantum TLS on Raspberry Pi Pico 2 W
The source code repository of firmwares to be tested on the Pico 2 W.

## Understanding TCP/IP stack
Goal:

```c
// my_tcp.h

typedef struct my_socket_t {
} my_socket_t;

my_socket_t my_socket();
int my_tcp_connect(my_socket_t sock, ...);
int my_tcp_close(my_socket_t sock);
int my_tcp_write(my_socket_t sock, const uint8_t *buf, size_t len);
int my_tcp_read(my_socket_t sock, uint8_t *buf, size_t len);
```

## Wifi parameters
Wifi parameters `WIFI_SSID` and `WIFI_PASSWORD` should be specified using environment variables (definitely not hardcoded in source code!). One good way is with `.env` file at project root.

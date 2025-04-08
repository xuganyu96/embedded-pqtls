#ifndef _UTILS_H
#define _UTILS_H
#include <stdint.h>
#include <pico/assert.h>

// Change to something else if needed
#define DEBUG_printf printf

/**
 * Perform a countdown
 */
void countdown_s(int dur);

/**
 * If Wifi connection is up, then turn on the LED and return 0
 * If the Wifi connection is down, attempt retries until success
 *
 * Calling this method will call cyw43_arch_poll()
 */
void ensure_wifi_connection_blocking(const char *ssid, const char *pw, uint32_t auth);
#endif

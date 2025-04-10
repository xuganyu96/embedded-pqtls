#ifndef _UTILS_H
#define _UTILS_H

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

// ANSI color codes
#ifdef USE_COLORED_LOGGING
#endif

// Macros for logging
#ifdef USE_COLORED_LOGGING
#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[1;31m"    // Bright Red
#define COLOR_YELLOW "\033[1;33m" // Bright Yellow
#define COLOR_BLUE "\033[1;34m"   // Bright Blue
#define COLOR_GREY "\033[1;37m"   // Light Grey
#define CRITICAL_printf(fmt, ...)                                              \
  printf(COLOR_RED "CRITICAL: " fmt COLOR_RESET, ##__VA_ARGS__)
#define WARNING_printf(fmt, ...)                                               \
  printf(COLOR_YELLOW "WARNING : " fmt COLOR_RESET, ##__VA_ARGS__)
#define INFO_printf(fmt, ...)                                                  \
  printf(COLOR_BLUE "INFO    : " fmt COLOR_RESET, ##__VA_ARGS__)
#define DEBUG_printf(fmt, ...)                                                 \
  printf(COLOR_GREY "DEBUG   : " fmt COLOR_RESET, ##__VA_ARGS__)
#else
#define CRITICAL_printf(fmt, ...) printf("CRITICAL: " fmt, ##__VA_ARGS__)
#define WARNING_printf(fmt, ...) printf("WARNING : " fmt, ##__VA_ARGS__)
#define INFO_printf(fmt, ...) printf("INFO    : " fmt, ##__VA_ARGS__)
#define DEBUG_printf(fmt, ...) printf("DEBUG   : " fmt, ##__VA_ARGS__)
#endif

void dump_bytes(const uint8_t *bytes, size_t len);

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
void ensure_wifi_connection_blocking(const char *ssid, const char *pw,
                                     uint32_t auth);
#endif

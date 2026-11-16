#ifndef HID_LAB_MBEDTLS_CONFIG_H
#define HID_LAB_MBEDTLS_CONFIG_H

#include <mbedtls/mbedtls_config.h>

/* Firmware uses Mbed TLS for authenticated GCM only. */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#undef MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME_DATE
#undef MBEDTLS_TIMING_C

#endif

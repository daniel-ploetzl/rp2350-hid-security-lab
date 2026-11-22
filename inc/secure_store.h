#ifndef SECURE_STORE_H
#define SECURE_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "flash_config.h"

/* Production loads and locks per-device key shares from Secure-only OTP.
 * The explicitly unprotected development profile instead loads its disposable
 * test key from a generated header so firmware tests need no OTP provisioning. */
bool secure_store_init(void);

/* Authenticates and decrypts one record. The physical flash address is bound
 * into the GCM AAD so a record cannot be copied to another reserved sector. */
bool secure_store_open(uint32_t flash_addr, const void *record,
                       void *plaintext, size_t plaintext_size);

void secure_store_clear(void *ptr, size_t len);

#endif

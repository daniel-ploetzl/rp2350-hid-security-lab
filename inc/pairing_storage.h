#ifndef PAIRING_STORAGE_H
#define PAIRING_STORAGE_H

#include <stdint.h>

/* TinyUSB callbacks expose these fixed files through the application MSC LUN. */
void pairing_storage_init(void);
void pairing_storage_new_session(void);
void pairing_storage_set_challenge(const uint8_t *challenge, uint16_t length);

#endif

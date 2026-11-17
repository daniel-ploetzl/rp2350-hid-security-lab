#ifndef PAIRING_H
#define PAIRING_H

#include <stdbool.h>
#include <stdint.h>

/* Pairing gates all HID reports until this connection proves host-key possession. */
void pairing_init(void);
void pairing_task(void);
bool pairing_is_authorised(void);
/* The storage layer exposes these fixed-width challenge and response records. */
void pairing_read_challenge(uint8_t *buffer, uint16_t length);
void pairing_submit_response(const uint8_t *buffer, uint16_t length);

/* RAM-backed MSC storage keeps challenge exchange independent of hidraw. */
void pairing_storage_init(void);
void pairing_storage_new_session(void);
void pairing_storage_set_challenge(const uint8_t *challenge, uint16_t length);

#endif

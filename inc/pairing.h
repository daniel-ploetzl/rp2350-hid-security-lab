#ifndef PAIRING_H
#define PAIRING_H

#include <stdbool.h>
#include <stdint.h>

/* One FAT sector. Byte arrays keep the wire layout independent of alignment. */
typedef struct {
    uint8_t version;
    uint8_t state;
    uint8_t verdict;
    uint8_t reserved;
    uint8_t attempts_le[4];
    uint8_t nonce[32];
    uint8_t response[64];
    uint8_t padding[408];
} pairing_status_t;

#define PROOF_ACCEPTED 1u
#define PROOF_REJECTED 2u
_Static_assert(sizeof(pairing_status_t) == 512u, "status must occupy one sector");

/* Pairing gates all HID reports until this connection proves host-key possession. */
void pairing_init(void);
void pairing_task(void);
bool pairing_is_authorised(void);
/* The storage layer exposes these fixed-width challenge and response records. */
void pairing_read_challenge(uint8_t *buffer, uint16_t length);
void pairing_submit_response(const uint8_t *buffer, uint16_t length);

/* RAM-backed MSC storage keeps challenge exchange independent of hidraw. */
void pairing_storage_set_status(uint8_t state, const uint8_t nonce[32],
                                const uint8_t *response, uint8_t verdict);
void pairing_storage_init(void);
void pairing_storage_new_session(void);
void pairing_storage_set_challenge(const uint8_t *challenge, uint16_t length);

#endif

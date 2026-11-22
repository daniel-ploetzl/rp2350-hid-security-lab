/* Exercise the status sector through the same callbacks as the USB stack. */
#include "pairing.h"
#include "tusb.h"
#include <assert.h>
#include <string.h>

int32_t tud_msc_read10_cb(uint8_t, uint32_t, uint32_t, void *, uint32_t);
int32_t tud_msc_write10_cb(uint8_t, uint32_t, uint32_t, uint8_t *, uint32_t);

void tud_msc_set_sense(uint8_t lun, uint8_t key, uint8_t code, uint8_t qualifier)
{
    (void)lun;
    (void)key;
    (void)code;
    (void)qualifier;
}

void pairing_submit_response(const uint8_t *data, uint16_t size)
{
    (void)data;
    (void)size;
    assert(false);
}

int main(void)
{
    uint8_t nonce[32] = {1u};
    uint8_t proof[64] = {2u};
    pairing_status_t status;
    pairing_storage_init();
    pairing_storage_new_session();
    pairing_storage_set_status(1u, nonce, proof, PROOF_REJECTED);
    pairing_storage_set_status(2u, nonce, proof, PROOF_ACCEPTED);
    assert(tud_msc_write10_cb(0, 5, 0, proof, sizeof proof) == -1);
    assert(tud_msc_read10_cb(0, 5, 0, &status, sizeof status) == sizeof status);
    assert(status.version == 1 && status.state == 2 && status.verdict == PROOF_ACCEPTED);
    assert(status.attempts_le[0] == 2 && memcmp(status.response, proof, sizeof proof) == 0);
    pairing_storage_new_session();
    nonce[0]++;
    pairing_storage_set_status(1u, nonce, NULL, 0);
    assert(tud_msc_read10_cb(0, 5, 0, &status, sizeof status) == sizeof status);
    assert(status.verdict == 0 && status.attempts_le[0] == 0 && status.nonce[0] == nonce[0]);
    return 0;
}

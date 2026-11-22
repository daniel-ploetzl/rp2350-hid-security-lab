/*
 * Authenticated configuration storage
 *
 * Imports RP2350 OTP key shares and opens AES-GCM protected records.
 */
#include "secure_store.h"
#include "flash_config.h"
#include <mbedtls/gcm.h>
#include <string.h>
#if HID_LAB_DEVELOPMENT_BUILD
#include "hid_lab_dev_aes_key.h"
#endif
#include "hardware/regs/addressmap.h"
#include "hardware/regs/otp.h"
#include "hardware/structs/otp.h"

static uint8_t s_credential_key[32];
static bool s_ready;

void secure_store_clear(void *ptr, size_t len)
{
    volatile uint8_t *p = ptr;
    while (len--)
        *p++ = 0;
}

static void record_aad(const secure_record_t *record, uint32_t flash_addr,
                       uint8_t aad[16])
{
    memcpy(aad, record, 12); /* authenticated envelope header */
    aad[12] = (uint8_t)flash_addr;
    aad[13] = (uint8_t)(flash_addr >> 8);
    aad[14] = (uint8_t)(flash_addr >> 16);
    aad[15] = (uint8_t)(flash_addr >> 24);
}

bool secure_store_init(void)
{
#if HID_LAB_DEVELOPMENT_BUILD
    /* Test only: this unprotected image embeds an extractable disposable key. */
    memcpy(s_credential_key, hid_lab_dev_aes_key, sizeof s_credential_key);
    s_ready = true;
    return true;
#elif !PICO_RP2350
    return false;
#else
    /* picotool's four-way AES key share occupies the first 64 data bytes of
     * two adjacent OTP pages. Pages are provisioned Secure-readable only. */
    otp_hw->debugen_lock = OTP_DEBUGEN_LOCK_BITS;
    const uint16_t *otp = (const uint16_t *)OTP_DATA_GUARDED_BASE;
    /* Keep the inverse-row gap between the two OTP data pages. picotool's
     * hardened boot decryptor uses this same four-way share representation. */
    uint8_t shares[192] = {0};
    uint32_t key_words[8];
    memcpy(shares, &otp[SECURE_CRED_KEY_PAGE * 0x40u], 64);
    memcpy(shares + 128, &otp[(SECURE_CRED_KEY_PAGE + 1u) * 0x40u], 64);

    const uint32_t *share_words = (const uint32_t *)shares;
    for (size_t i = 0; i < 8; i++)
    {
        size_t skip = (i / 4u) * 16u;
        key_words[i] = share_words[i * 4u + skip] ^
                       share_words[i * 4u + 1u + skip] ^
                       share_words[i * 4u + 2u + skip] ^
                       share_words[i * 4u + 3u + skip];
    }
    memcpy(s_credential_key, key_words, sizeof key_words);
    uint8_t key_or = 0;
    uint8_t key_and = 0xff;
    for (size_t i = 0; i < sizeof s_credential_key; i++)
    {
        key_or |= s_credential_key[i];
        key_and &= s_credential_key[i];
    }
    if (key_or == 0 || key_and == 0xff)
    {
        secure_store_clear(s_credential_key, sizeof s_credential_key);
        secure_store_clear(shares, sizeof shares);
        secure_store_clear(key_words, sizeof key_words);
        return false;
    }

    /* Stop further OTP reads from this application after key import. The key
     * remains only in SRAM for authenticated record operations. */
    otp_hw->sw_lock[SECURE_CRED_KEY_PAGE] = 0x0fu;
    otp_hw->sw_lock[SECURE_CRED_KEY_PAGE + 1u] = 0x0fu;
    secure_store_clear(shares, sizeof shares);
    secure_store_clear(key_words, sizeof key_words);
    s_ready = true;
    return true;
#endif
}

bool secure_store_open(uint32_t flash_addr, const void *record_ptr,
                       void *plaintext, size_t plaintext_size)
{
    if (plaintext == NULL || plaintext_size > sizeof(((secure_record_t *)0)->ciphertext))
        return false;
    secure_store_clear(plaintext, plaintext_size);
    if (!s_ready || record_ptr == NULL)
        return false;

    const secure_record_t *record = record_ptr;
    if (record->magic != SECURE_RECORD_MAGIC ||
        record->version != SECURE_RECORD_VERSION ||
        record->payload_len != plaintext_size)
        return false;

    uint8_t aad[16];
    record_aad(record, flash_addr, aad);
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                                s_credential_key, 256);
    if (rc == 0)
        rc = mbedtls_gcm_auth_decrypt(&gcm, plaintext_size,
                                      record->nonce, sizeof record->nonce,
                                      aad, sizeof aad,
                                      record->tag, sizeof record->tag,
                                      record->ciphertext, plaintext);
    mbedtls_gcm_free(&gcm);
    secure_store_clear(aad, sizeof aad);
    if (rc != 0)
    {
        secure_store_clear(plaintext, plaintext_size);
        return false;
    }
    return true;
}

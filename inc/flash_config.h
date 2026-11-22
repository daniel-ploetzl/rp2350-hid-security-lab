#ifndef FLASH_CONFIG_H
#define FLASH_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CONFIG_FLASH_XIP_BASE    0x10000000UL
#define CONFIG_FLASH_TOTAL_BYTES (4UL * 1024UL * 1024UL)
#define CONFIG_SECTOR_SIZE_BYTES 4096UL
#define CONFIG_FLASH_ADDR        (CONFIG_FLASH_XIP_BASE + CONFIG_FLASH_TOTAL_BYTES - CONFIG_SECTOR_SIZE_BYTES)
/* Bumped when the record layout changed to add period_s. A board still holding
 * the old two-field record now fails this check and falls back to defaults. */
#define CONFIG_MAGIC             0xCAFEF00EUL
#define CONFIG_HOURS_MIN         1UL
#define CONFIG_HOURS_MAX         24UL
#define CONFIG_DEFAULT_HOURS     24UL
/* Re-activation idle period, in seconds. 1 week is both the ceiling and the
 * default, so a board with no valid config restarts weekly. */
#define CONFIG_PERIOD_MIN_S      1UL
#define CONFIG_PERIOD_MAX_S      604800UL
#define CONFIG_DEFAULT_PERIOD_S  604800UL

/* Preserve the unused sector above the stored input sequence on existing boards. */
#define INPUT_SEQUENCE_FLASH_ADDR (CONFIG_FLASH_ADDR - 2UL * CONFIG_SECTOR_SIZE_BYTES)
#define INPUT_SEQUENCE_MAGIC        0x4C4F4749UL /* Retained for existing encrypted records. */
#define INPUT_SEQUENCE_VERSION      2UL
#define INPUT_SEQUENCE_LINE1_MAX    64
#define INPUT_SEQUENCE_LINE2_MAX    64
#define INPUT_SEQUENCE_ACTION_MAX   64
#define PAIRING_FLASH_ADDR       (INPUT_SEQUENCE_FLASH_ADDR - CONFIG_SECTOR_SIZE_BYTES)
#define PAIRING_MAGIC            0x50414952UL
#define PAIRING_VERSION          1UL
#define PAIRING_PUBLIC_KEY_BYTES 65UL
#define PAIRING_CHALLENGE_BYTES  32UL
#define PAIRING_SIGNATURE_PART_BYTES 32u
#define PAIRING_STATUS_UNPAIRED  0u
#define PAIRING_STATUS_PENDING   1u
#define PAIRING_STATUS_ALLOWED   2u
#define SECURE_RECORD_MAGIC      0x53454352UL /* "SECR" */
#define SECURE_RECORD_VERSION    1UL
#define SECURE_RECORD_NONCE_BYTES 12
#define SECURE_RECORD_TAG_BYTES  16
#define SECURE_CRED_KEY_PAGE     24UL

typedef struct {
    uint32_t magic;
    uint32_t hours;
    uint32_t period_s;
} pico_config_t;


/* Authenticated input sequence payload. The field sizes preserve the existing
 * encrypted record layout. Reserved aligns the CRC to four bytes. */
typedef struct {
    uint32_t magic;
    uint32_t version;
    char     line1[INPUT_SEQUENCE_LINE1_MAX + 1];
    char     line2[INPUT_SEQUENCE_LINE2_MAX + 1];
    char     action[INPUT_SEQUENCE_ACTION_MAX + 1];
    uint8_t  reserved[2];
    uint32_t crc;
} input_sequence_config_t;

/* P-256 host public key encrypted with the device record key. */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint8_t public_key[PAIRING_PUBLIC_KEY_BYTES];
    uint8_t reserved[3];
    uint32_t crc;
} pairing_config_t;

/* Fixed-size AES-GCM envelope shared by pairing and input sequence payloads. */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t payload_len;
    uint8_t  nonce[SECURE_RECORD_NONCE_BYTES];
    uint8_t  ciphertext[sizeof(input_sequence_config_t)];
    uint8_t  tag[SECURE_RECORD_TAG_BYTES];
    uint8_t  reserved[4];
} secure_record_t;

_Static_assert(sizeof(pico_config_t) == 12, "config layout changed, update write_config.c");
_Static_assert(sizeof(input_sequence_config_t) == 212, "input sequence layout changed, raise INPUT_SEQUENCE_VERSION");
_Static_assert(sizeof(pairing_config_t) == 80, "pairing layout changed, raise PAIRING_VERSION");
_Static_assert(sizeof(secure_record_t) == 256, "secure record must fit one UF2 payload");

static inline uint32_t config_read_hours(void)
{
    const pico_config_t *cfg = (const pico_config_t *) CONFIG_FLASH_ADDR;
    if (cfg->magic == CONFIG_MAGIC &&
        cfg->hours >= CONFIG_HOURS_MIN &&
        cfg->hours <= CONFIG_HOURS_MAX)
        return cfg->hours;
    return CONFIG_DEFAULT_HOURS;
}

/* Split from the read so the validation can be exercised on the host against a
 * crafted record, without a fixed flash address. */
static inline uint32_t config_period_s_at(const pico_config_t *cfg)
{
    if (cfg->magic == CONFIG_MAGIC &&
        cfg->period_s >= CONFIG_PERIOD_MIN_S &&
        cfg->period_s <= CONFIG_PERIOD_MAX_S)
        return cfg->period_s;
    return CONFIG_DEFAULT_PERIOD_S;
}

static inline uint32_t config_read_period_s(void)
{
    return config_period_s_at((const pico_config_t *) CONFIG_FLASH_ADDR);
}

/* Bitwise CRC-32. Shared with write_config so both sides compute the same value. */
static inline uint32_t creds_crc32(const void *data, size_t len)
{
    const uint8_t *bytes = data;
    uint32_t crc = 0xFFFFFFFFUL;

    for (size_t i = 0; i < len; i++)
    {
        crc ^= bytes[i];
        for (int bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ (0xEDB88320UL & (0u - (crc & 1u)));
    }
    return ~crc;
}


/* Validate the record before its sequence is copied into SRAM. */
static inline bool input_sequence_valid(const input_sequence_config_t *sequence)
{
    if (sequence->magic != INPUT_SEQUENCE_MAGIC ||
        sequence->version != INPUT_SEQUENCE_VERSION)
        return false;
    if (sequence->crc != creds_crc32(sequence, offsetof(input_sequence_config_t, crc)))
        return false;
    if (sequence->line1[0] == '\0' ||
        sequence->line1[INPUT_SEQUENCE_LINE1_MAX] != '\0' ||
        sequence->line2[INPUT_SEQUENCE_LINE2_MAX] != '\0' ||
        sequence->action[0] == '\0' ||
        sequence->action[INPUT_SEQUENCE_ACTION_MAX] != '\0')
        return false;
    return true;
}

static inline bool pairing_config_valid(const pairing_config_t *cfg)
{
    if (cfg->magic != PAIRING_MAGIC || cfg->version != PAIRING_VERSION)
        return false;
    if (cfg->crc != creds_crc32(cfg, offsetof(pairing_config_t, crc)))
        return false;
    return cfg->public_key[0] == 0x04u;
}

#endif

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

/* A sector of its own, storing an authenticated encrypted Wi-Fi record. */
#define CREDS_FLASH_ADDR         (CONFIG_FLASH_ADDR - CONFIG_SECTOR_SIZE_BYTES)
#define CREDS_MAGIC              0x57494649UL
#define CREDS_VERSION            1UL
#define CREDS_AUTH_WPA2          2UL
#define CREDS_AUTH_WPA3          3UL
#define CREDS_SSID_MAX           32
#define CREDS_KEY_MIN            8
#define CREDS_KEY_MAX            64

/* A sector below Wi-Fi holds the authenticated encrypted input sequence.
 * The preceding sector stores the authenticated host pairing public key. */
#define LOGIN_CREDS_FLASH_ADDR   (CREDS_FLASH_ADDR - CONFIG_SECTOR_SIZE_BYTES)
#define LOGIN_MAGIC              0x4C4F4749UL   /* "LOGI" */
#define LOGIN_VERSION            2UL
#define LOGIN_USER_MAX           64
#define LOGIN_PASS_MAX           64
#define LOGIN_COMMAND_MAX        64
#define PAIRING_FLASH_ADDR       (LOGIN_CREDS_FLASH_ADDR - CONFIG_SECTOR_SIZE_BYTES)
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

/* The arrays hold one extra byte for the terminating NUL. */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t auth;
    char     ssid[CREDS_SSID_MAX + 1];
    char     key[CREDS_KEY_MAX + 1];
    uint8_t  reserved[2];
    uint32_t crc;
} wifi_creds_t;

/* Plaintext input sequence payload. It is held in SRAM only after GCM authentication.
 * Magic, version, strings and CRC are stored here. Reserved aligns CRC to 4 bytes. */
typedef struct {
    uint32_t magic;
    uint32_t version;
    char     user[LOGIN_USER_MAX + 1];
    char     pass[LOGIN_PASS_MAX + 1];
    char     command[LOGIN_COMMAND_MAX + 1];
    uint8_t  reserved[2];
    uint32_t crc;
} login_creds_t;

/* P-256 host public key encrypted with the device record key. */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint8_t public_key[PAIRING_PUBLIC_KEY_BYTES];
    uint8_t reserved[3];
    uint32_t crc;
} pairing_config_t;

/* Fixed-size AES-GCM envelope shared by Wi-Fi and input sequence payloads. */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t payload_len;
    uint8_t  nonce[SECURE_RECORD_NONCE_BYTES];
    uint8_t  ciphertext[sizeof(login_creds_t)];
    uint8_t  tag[SECURE_RECORD_TAG_BYTES];
    uint8_t  reserved[4];
} secure_record_t;

_Static_assert(sizeof(pico_config_t) == 12, "config layout changed, update write_config.c");
_Static_assert(sizeof(wifi_creds_t) == 116, "credentials layout changed, raise CREDS_VERSION");
_Static_assert(sizeof(login_creds_t) == 212, "login layout changed, raise LOGIN_VERSION");
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

/* Validation split so encrypted records are checked only after authentication. */
static inline bool wifi_creds_valid(const wifi_creds_t *creds)
{
    if (creds->magic != CREDS_MAGIC || creds->version != CREDS_VERSION)
        return false;
    if (creds->crc != creds_crc32(creds, offsetof(wifi_creds_t, crc)))
        return false;
    if (creds->auth != CREDS_AUTH_WPA2 && creds->auth != CREDS_AUTH_WPA3)
        return false;
    if (creds->ssid[0] == '\0' || creds->ssid[CREDS_SSID_MAX] != '\0' ||
        creds->key[CREDS_KEY_MAX] != '\0')
        return false;
    return true;
}

/* Validation split out so it can run on the host against a crafted record.
 * Sequence values one and three must be present. Value two may be empty. */
static inline bool login_valid(const login_creds_t *lc)
{
    if (lc->magic != LOGIN_MAGIC || lc->version != LOGIN_VERSION)
        return false;
    if (lc->crc != creds_crc32(lc, offsetof(login_creds_t, crc)))
        return false;
    if (lc->user[0] == '\0' ||
        lc->user[LOGIN_USER_MAX] != '\0' ||
        lc->pass[LOGIN_PASS_MAX] != '\0' ||
        lc->command[0] == '\0' ||
        lc->command[LOGIN_COMMAND_MAX] != '\0')
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

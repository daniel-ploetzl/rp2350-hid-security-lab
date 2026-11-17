/* RAM-backed FAT12 media keeps the challenge exchange independent of hidraw. */
#include "pairing.h"
#include "tusb.h"
#include <string.h>

#define DISK_BLOCK_COUNT 128u
#define DISK_BLOCK_BYTES 512u
#define CHALLENGE_LBA 3u
#define RESPONSE_LBA 4u
#define CHALLENGE_BYTES 42u
#define RESPONSE_BYTES 64u

static uint8_t s_disk[DISK_BLOCK_COUNT][DISK_BLOCK_BYTES];
static uint64_t s_response_written;

static void set_directory_entry(uint8_t *entry, const char *name,
                                const char *extension, uint16_t cluster,
                                uint32_t size)
{
    memset(entry, 0, 32u);
    memcpy(entry, name, 8u);
    memcpy(entry + 8u, extension, 3u);
    entry[11] = 0x20u;
    entry[26] = (uint8_t)cluster;
    entry[27] = (uint8_t)(cluster >> 8);
    entry[28] = (uint8_t)size;
    entry[29] = (uint8_t)(size >> 8);
    entry[30] = (uint8_t)(size >> 16);
    entry[31] = (uint8_t)(size >> 24);
}

static void initialise_fat_volume(void)
{
    uint8_t *boot = s_disk[0];
    boot[0] = 0xEBu;
    boot[1] = 0x3Cu;
    boot[2] = 0x90u;
    memcpy(boot + 3u, "MSDOS5.0", 8u);
    boot[11] = 0x00u;
    boot[12] = 0x02u;
    boot[13] = 1u;
    boot[14] = 1u;
    boot[16] = 1u;
    boot[17] = 16u;
    boot[19] = DISK_BLOCK_COUNT;
    boot[21] = 0xF8u;
    boot[22] = 1u;
    boot[24] = 1u;
    boot[26] = 1u;
    boot[36] = 0x80u;
    boot[38] = 0x29u;
    boot[39] = 0x52u;
    boot[40] = 0x50u;
    boot[41] = 0x32u;
    boot[42] = 0x35u;
    memcpy(boot + 43u, "HIDPAIR    ", 11u);
    memcpy(boot + 54u, "FAT12   ", 8u);
    boot[510] = 0x55u;
    boot[511] = 0xAAu;

    s_disk[1][0] = 0xF8u;
    s_disk[1][1] = 0xFFu;
    s_disk[1][2] = 0xFFu;
    s_disk[1][3] = 0xFFu;
    s_disk[1][4] = 0xFFu;
    s_disk[1][5] = 0xFFu;

    memcpy(s_disk[2], "HIDPAIR    ", 11u);
    s_disk[2][11] = 0x08u;
    set_directory_entry(s_disk[2] + 32u, "CHALLENG", "BIN", 2u,
                        CHALLENGE_BYTES);
    set_directory_entry(s_disk[2] + 64u, "RESPONSE", "BIN", 3u,
                        RESPONSE_BYTES);
}

void pairing_storage_init(void)
{
    memset(s_disk, 0, sizeof s_disk);
    initialise_fat_volume();
    s_response_written = 0u;
}

void pairing_storage_new_session(void)
{
    memset(s_disk[RESPONSE_LBA], 0, DISK_BLOCK_BYTES);
    s_response_written = 0u;
}

void pairing_storage_set_challenge(const uint8_t *challenge, uint16_t length)
{
    if (challenge == NULL || length != CHALLENGE_BYTES)
        return;
    memset(s_disk[CHALLENGE_LBA], 0, DISK_BLOCK_BYTES);
    memcpy(s_disk[CHALLENGE_LBA], challenge, CHALLENGE_BYTES);
}

void tud_msc_inquiry_cb(uint8_t lun, uint8_t vendor_id[8],
                        uint8_t product_id[16], uint8_t product_rev[4])
{
    (void)lun;
    memcpy(vendor_id, "HID-LAB ", 8u);
    memcpy(product_id, "PAIRING DISK    ", 16u);
    memcpy(product_rev, "1.0 ", 4u);
}

bool tud_msc_test_unit_ready_cb(uint8_t lun)
{
    (void)lun;
    return true;
}

void tud_msc_capacity_cb(uint8_t lun, uint32_t *block_count,
                         uint16_t *block_size)
{
    (void)lun;
    *block_count = DISK_BLOCK_COUNT;
    *block_size = DISK_BLOCK_BYTES;
}

bool tud_msc_is_writable_cb(uint8_t lun)
{
    (void)lun;
    return true;
}

int32_t tud_msc_read10_cb(uint8_t lun, uint32_t lba, uint32_t offset,
                          void *buffer, uint32_t buffer_size)
{
    (void)lun;
    if (buffer == NULL || lba >= DISK_BLOCK_COUNT || offset >= DISK_BLOCK_BYTES ||
        buffer_size > DISK_BLOCK_BYTES - offset)
        return -1;
    memcpy(buffer, &s_disk[lba][offset], buffer_size);
    return (int32_t)buffer_size;
}

int32_t tud_msc_write10_cb(uint8_t lun, uint32_t lba, uint32_t offset,
                           uint8_t *buffer, uint32_t buffer_size)
{
    (void)lun;
    if (buffer == NULL || lba >= DISK_BLOCK_COUNT || offset >= DISK_BLOCK_BYTES ||
        buffer_size > DISK_BLOCK_BYTES - offset || lba == 0u || lba == CHALLENGE_LBA)
        return -1;
    memcpy(&s_disk[lba][offset], buffer, buffer_size);
    if (lba == RESPONSE_LBA)
    {
        uint32_t first = offset;
        uint32_t end = offset + buffer_size;
        if (end > RESPONSE_BYTES)
            end = RESPONSE_BYTES;
        for (uint32_t index = 0u; index < RESPONSE_BYTES; index++)
        {
            if (index >= first && index < end)
                s_response_written |= UINT64_C(1) << index;
        }
        if (s_response_written == UINT64_MAX)
            pairing_submit_response(s_disk[RESPONSE_LBA], RESPONSE_BYTES);
    }
    return (int32_t)buffer_size;
}

int32_t tud_msc_scsi_cb(uint8_t lun, uint8_t const command[16],
                        void *buffer, uint16_t buffer_size)
{
    (void)command;
    (void)buffer;
    (void)buffer_size;
    tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, 0x20u, 0x00u);
    return -1;
}

/* Create valid and reserved-sector UF2 samples for the host build checks. */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define BLOCK_BYTES 512u

static void put_le32(uint8_t *destination, uint32_t value)
{
    destination[0] = (uint8_t)value;
    destination[1] = (uint8_t)(value >> 8);
    destination[2] = (uint8_t)(value >> 16);
    destination[3] = (uint8_t)(value >> 24);
}

static void make_block(uint8_t block[BLOCK_BYTES], uint32_t flags,
                       uint32_t address, uint32_t number, uint32_t total,
                       uint32_t family, uint8_t fill)
{
    memset(block, 0, BLOCK_BYTES);
    put_le32(block, 0x0A324655u);
    put_le32(block + 4u, 0x9E5D5157u);
    put_le32(block + 8u, flags);
    put_le32(block + 12u, address);
    put_le32(block + 16u, 256u);
    put_le32(block + 20u, number);
    put_le32(block + 24u, total);
    put_le32(block + 28u, family);
    memset(block + 32u, fill, 256u);
    put_le32(block + 508u, 0x0AB16F30u);
}

static int write_sample(const char *path, uint32_t firmware_address)
{
    uint8_t e10[BLOCK_BYTES];
    uint8_t firmware[BLOCK_BYTES];
    make_block(e10, 0xA000u, 0x10FFFF00u, 0u, 2u, 0xE48BFF57u, 0xEFu);
    make_block(firmware, 0x2000u, firmware_address, 0u, 1u, 0xE48BFF59u, 0xA5u);
    FILE *file = fopen(path, "wb");
    if (file == NULL)
        return 1;
    bool saved = fwrite(e10, 1u, sizeof e10, file) == sizeof e10 &&
                 fwrite(firmware, 1u, sizeof firmware, file) == sizeof firmware;
    return fclose(file) == 0 && saved ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc != 3)
        return 2;
    uint32_t address = strcmp(argv[1], "valid") == 0 ? 0x10000000u :
                       strcmp(argv[1], "overlap") == 0 ? 0x103FC000u : 0u;
    if (address == 0u)
        return 2;
    return write_sample(argv[2], address);
}

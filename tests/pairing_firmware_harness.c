/* Host harness for the firmware pairing state machine. */
#include "pairing.h"
#include "flash_config.h"
#include "secure_store.h"
#include "pico/rand.h"
#include "pico/unique_id.h"
#include "tusb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_PUBLIC_KEY_BYTES 65u
#define TEST_CHALLENGE_BYTES 42u
#define TEST_RESPONSE_BYTES 64u
#define TEST_FILE_BYTES 128u

static uint8_t s_public_key[TEST_PUBLIC_KEY_BYTES];
static bool s_mounted;
static uint32_t s_random_word;

uint32_t get_rand_32(void)
{
    s_random_word++;
    return 0x01010100u + s_random_word;
}

void pico_get_unique_board_id(pico_unique_board_id_t *id_out)
{
    static const uint8_t board_id[PICO_UNIQUE_BOARD_ID_SIZE_BYTES] = {
        'B', 'O', 'A', 'R', 'D', '0', '0', '1'
    };
    memcpy(id_out->id, board_id, sizeof board_id);
}

bool tud_mounted(void)
{
    return s_mounted;
}

bool secure_store_open(uint32_t flash_addr, const void *record_ptr,
                       void *plaintext, size_t plaintext_size)
{
    (void)flash_addr;
    (void)record_ptr;
    if (plaintext == NULL || plaintext_size != sizeof(pairing_config_t))
        return false;

    pairing_config_t config = {0};
    config.magic = PAIRING_MAGIC;
    config.version = PAIRING_VERSION;
    memcpy(config.public_key, s_public_key, sizeof config.public_key);
    config.crc = creds_crc32(&config, offsetof(pairing_config_t, crc));
    memcpy(plaintext, &config, sizeof config);
    return true;
}

void secure_store_clear(void *ptr, size_t len)
{
    volatile uint8_t *bytes = ptr;
    while (len-- > 0u)
        *bytes++ = 0u;
}

void pairing_storage_init(void)
{
}

void pairing_storage_new_session(void)
{
}

void pairing_storage_set_challenge(const uint8_t *challenge, uint16_t length)
{
    (void)challenge;
    (void)length;
}

static bool read_file(const char *path, uint8_t *buffer, size_t capacity,
                      size_t *length)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
        return false;
    size_t count = fread(buffer, 1u, capacity, file);
    int extra = fgetc(file);
    bool valid = !ferror(file) && extra == EOF;
    if (fclose(file) != 0)
        valid = false;
    *length = count;
    return valid;
}

static bool load_public_key(const char *path)
{
    size_t length = 0u;
    return read_file(path, s_public_key, sizeof s_public_key, &length) &&
           length == sizeof s_public_key && s_public_key[0] == 0x04u;
}

static void reconnect(void)
{
    s_mounted = false;
    pairing_task();
    s_mounted = true;
    pairing_task();
}

int main(int argc, char **argv)
{
    if (argc != 4 || !load_public_key(argv[1]))
        return EXIT_FAILURE;
    pairing_init();
    s_mounted = true;
    pairing_task();

    if (strcmp(argv[3], "dump") == 0 ||
        strcmp(argv[3], "dump-reconnect") == 0)
    {
        if (strcmp(argv[3], "dump-reconnect") == 0)
            reconnect();
        uint8_t challenge[TEST_CHALLENGE_BYTES];
        pairing_read_challenge(challenge, sizeof challenge);
        return fwrite(challenge, 1u, sizeof challenge, stdout) == sizeof challenge
                   ? EXIT_SUCCESS
                   : EXIT_FAILURE;
    }

    if (strcmp(argv[3], "reconnect") == 0)
        reconnect();

    uint8_t response[TEST_FILE_BYTES];
    size_t response_length = 0u;
    if (!read_file(argv[2], response, sizeof response, &response_length))
        return EXIT_FAILURE;

    pairing_submit_response(response, (uint16_t)response_length);
    pairing_task();
    bool authorised = pairing_is_authorised();
    printf("%u\n", authorised ? 1u : 0u);
    secure_store_clear(response, sizeof response);
    return EXIT_SUCCESS;
}

void pairing_storage_set_status(uint8_t state, const uint8_t nonce[32],
                                const uint8_t *response, uint8_t verdict)
{
    (void)nonce;
    if (response != NULL && verdict != (state == PAIRING_STATUS_ALLOWED ? 1u : 2u))
        abort();
}

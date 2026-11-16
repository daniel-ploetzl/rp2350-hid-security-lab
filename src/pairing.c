/* Verify the mounted-volume response before allowing keyboard or mouse reports. */
#include "pairing.h"

#include "flash_config.h"
#include "secure_store.h"
#include "pairing_storage.h"

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/sha256.h"
#include "pico/rand.h"
#include "pico/unique_id.h"
#include "tusb.h"

#include <string.h>

#define PAIRING_MESSAGE_BYTES 56u

static const uint8_t s_domain[] = "HID-LAB-PAIR-v1";
static pairing_config_t s_config;
static uint8_t s_nonce[PAIRING_CHALLENGE_BYTES];
static uint8_t s_response[PAIRING_SIGNATURE_PART_BYTES * 2u];
static uint8_t s_board_id[8];
static uint8_t s_status;
static bool s_has_key;
static bool s_mounted;
static bool s_response_pending;

static void clear_session(void)
{
    secure_store_clear(s_nonce, sizeof s_nonce);
    secure_store_clear(s_response, sizeof s_response);
    s_response_pending = false;
    s_status = s_has_key ? PAIRING_STATUS_PENDING : PAIRING_STATUS_UNPAIRED;
}

static void create_challenge(void)
{
    for (size_t i = 0; i < sizeof s_nonce; i += sizeof(uint32_t))
    {
        uint32_t random_word = get_rand_32();
        memcpy(&s_nonce[i], &random_word, sizeof random_word);
    }
}

static bool verify_response(const uint8_t *response)
{
    if (!s_has_key)
        return false;

    uint8_t message[PAIRING_MESSAGE_BYTES];
    uint8_t digest[32];
    memcpy(message, s_domain, sizeof s_domain);
    memcpy(message + sizeof s_domain, s_board_id, sizeof s_board_id);
    memcpy(message + sizeof s_domain + sizeof s_board_id, s_nonce, sizeof s_nonce);
    if (mbedtls_sha256(message, sizeof message, digest, 0) != 0)
    {
        secure_store_clear(message, sizeof message);
        secure_store_clear(digest, sizeof digest);
        return false;
    }

    mbedtls_ecp_group group;
    mbedtls_ecp_point point;
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&point);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    int result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
    if (result == 0)
        result = mbedtls_ecp_point_read_binary(&group, &point,
                                               s_config.public_key,
                                               sizeof s_config.public_key);
    if (result == 0)
        result = mbedtls_mpi_read_binary(&r, response, PAIRING_SIGNATURE_PART_BYTES);
    if (result == 0)
        result = mbedtls_mpi_read_binary(&s, response + PAIRING_SIGNATURE_PART_BYTES,
                                         PAIRING_SIGNATURE_PART_BYTES);
    if (result == 0)
        result = mbedtls_ecdsa_verify(&group, digest, sizeof digest, &point, &r, &s);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&point);
    mbedtls_ecp_group_free(&group);
    secure_store_clear(message, sizeof message);
    secure_store_clear(digest, sizeof digest);
    return result == 0;
}

static void publish_challenge(void)
{
    uint8_t challenge[42];
    pairing_read_challenge(challenge, sizeof challenge);
    pairing_storage_set_challenge(challenge, sizeof challenge);
    secure_store_clear(challenge, sizeof challenge);
}

void pairing_init(void)
{
    pairing_storage_init();
    pico_unique_board_id_t board_id;
    pico_get_unique_board_id(&board_id);
    memcpy(s_board_id, board_id.id, sizeof s_board_id);
    s_has_key = secure_store_open(PAIRING_FLASH_ADDR,
                                  (const void *)PAIRING_FLASH_ADDR,
                                  &s_config, sizeof s_config) &&
                pairing_config_valid(&s_config);
    if (!s_has_key)
        secure_store_clear(&s_config, sizeof s_config);
    s_status = s_has_key ? PAIRING_STATUS_PENDING : PAIRING_STATUS_UNPAIRED;
}

void pairing_task(void)
{
    bool mounted = tud_mounted();
    if (!mounted)
    {
        if (s_mounted)
            clear_session();
        s_mounted = false;
        return;
    }
    if (!s_mounted)
    {
        create_challenge();
        s_status = s_has_key ? PAIRING_STATUS_PENDING : PAIRING_STATUS_UNPAIRED;
        pairing_storage_new_session();
        publish_challenge();
        s_mounted = true;
    }
    if (s_response_pending)
    {
        s_response_pending = false;
        if (verify_response(s_response))
        {
            s_status = PAIRING_STATUS_ALLOWED;
            publish_challenge();
        }
        secure_store_clear(s_response, sizeof s_response);
    }
}

bool pairing_is_authorised(void)
{
    return s_mounted && s_status == PAIRING_STATUS_ALLOWED;
}

void pairing_read_challenge(uint8_t *buffer, uint16_t length)
{
    if (buffer == NULL || length < 42u)
        return;
    memset(buffer, 0, 42u);
    buffer[0] = 1u;
    buffer[1] = s_status;
    memcpy(buffer + 2u, s_board_id, sizeof s_board_id);
    memcpy(buffer + 10u, s_nonce, sizeof s_nonce);
}

void pairing_submit_response(const uint8_t *buffer, uint16_t length)
{
    if (!s_mounted || !s_has_key || s_status != PAIRING_STATUS_PENDING ||
        buffer == NULL || length != sizeof s_response || s_response_pending)
        return;
    memcpy(s_response, buffer, sizeof s_response);
    s_response_pending = true;
}

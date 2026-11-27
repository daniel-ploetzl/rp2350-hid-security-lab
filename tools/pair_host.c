/* Sign a fresh board challenge through its mounted USB storage volume. */
#define _GNU_SOURCE
#include "../inc/pairing.h"
#include "../inc/flash_config.h"
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHALLENGE_BYTES 42u
#define SIGNATURE_BYTES 64u
#define MOUNT_ROWS_MAX 256u
#define MOUNT_LINE_BYTES 1024u
#define UF2_MAGIC0 0x0A324655u
#define UF2_MAGIC1 0x9E5D5157u
#define UF2_MAGIC_END 0x0AB16F30u
#define UF2_FAMILY_FLAG 0x00002000u
#define UF2_RP2350_FAMILY 0xE48BFF59u
#define UF2_PAYLOAD_BYTES 256u
#define UF2_DATA_BYTES 476u
#ifndef HID_LAB_BOOT_VOLUME_ROOT
#define HID_LAB_BOOT_VOLUME_ROOT "/media"
#endif

typedef struct __attribute__((packed)) {
    uint32_t magic0;
    uint32_t magic1;
    uint32_t flags;
    uint32_t target;
    uint32_t payload_size;
    uint32_t block_number;
    uint32_t block_count;
    uint32_t family;
    uint8_t data[UF2_DATA_BYTES];
    uint32_t magic_end;
} enrolment_uf2_t;

_Static_assert(sizeof(enrolment_uf2_t) == 512u, "UF2 block size changed");

static const char s_challenge_name[] = "CHALLENG.BIN";
static const char s_response_name[] = "RESPONSE.BIN";
static const uint8_t s_domain[] = "HID-LAB-PAIR-v1";

static void clear_bytes(void *buffer, size_t length)
{
    volatile uint8_t *bytes = buffer;
    while (length-- > 0u)
        *bytes++ = 0u;
}

static void write_le32(void *destination, uint32_t value)
{
    uint8_t *bytes = destination;
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static bool read_full(int fd, uint8_t *buffer, size_t length)
{
    size_t offset = 0u;
    while (offset < length)
    {
        ssize_t count = read(fd, buffer + offset, length - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return false;
        offset += (size_t)count;
    }
    return true;
}

static bool write_full_at(int fd, const uint8_t *buffer, size_t length)
{
    size_t offset = 0u;
    while (offset < length)
    {
        ssize_t count = pwrite(fd, buffer + offset, length - offset, (off_t)offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return false;
        offset += (size_t)count;
    }
    return fsync(fd) == 0;
}

static bool decode_mount_field(const char *input, char *output, size_t capacity)
{
    size_t used = 0u;
    for (size_t index = 0u; input[index] != '\0'; index++)
    {
        char value = input[index];
        if (value == '\\' && input[index + 1u] >= '0' && input[index + 1u] <= '7' &&
            input[index + 2u] >= '0' && input[index + 2u] <= '7' &&
            input[index + 3u] >= '0' && input[index + 3u] <= '7')
        {
            value = (char)(((input[index + 1u] - '0') << 6) |
                           ((input[index + 2u] - '0') << 3) |
                           (input[index + 3u] - '0'));
            index += 3u;
        }
        if (used + 1u >= capacity)
            return false;
        output[used++] = value;
    }
    output[used] = '\0';
    return true;
}

static bool read_challenge(int directory_fd, uint8_t challenge[CHALLENGE_BYTES])
{
    int fd = openat(directory_fd, s_challenge_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    struct stat info;
    bool valid = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
                 info.st_size == (off_t)CHALLENGE_BYTES && read_full(fd, challenge,
                                                                     CHALLENGE_BYTES);
    close(fd);
    return valid && challenge[0] == 1u && challenge[1] == 1u;
}

static bool sign_challenge(EVP_PKEY *key, const uint8_t challenge[CHALLENGE_BYTES],
                           uint8_t signature[SIGNATURE_BYTES])
{
    uint8_t message[sizeof s_domain + 8u + 32u];
    uint8_t der[80];
    size_t der_length = sizeof der;
    memcpy(message, s_domain, sizeof s_domain);
    memcpy(message + sizeof s_domain, challenge + 2u, 40u);
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    bool valid = context != NULL && EVP_DigestSignInit(context, NULL, EVP_sha256(),
                                                       NULL, key) == 1 &&
                 EVP_DigestSign(context, der, &der_length, message,
                                sizeof message) == 1;
    if (context != NULL)
        EVP_MD_CTX_free(context);
    if (valid)
    {
        const unsigned char *cursor = der;
        ECDSA_SIG *decoded = d2i_ECDSA_SIG(NULL, &cursor, (long)der_length);
        if (decoded == NULL || cursor != der + der_length)
            valid = false;
        else
        {
            const BIGNUM *r = NULL;
            const BIGNUM *s = NULL;
            ECDSA_SIG_get0(decoded, &r, &s);
            valid = BN_bn2binpad(r, signature, 32) == 32 &&
                    BN_bn2binpad(s, signature + 32u, 32) == 32;
            ECDSA_SIG_free(decoded);
        }
    }
    clear_bytes(message, sizeof message);
    clear_bytes(der, sizeof der);
    return valid;
}

static bool submit_response(int directory_fd, const uint8_t signature[SIGNATURE_BYTES])
{
    int fd = openat(directory_fd, s_response_name,
                    O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    struct stat info;
    bool valid = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
                 info.st_size == (off_t)SIGNATURE_BYTES &&
                 write_full_at(fd, signature, SIGNATURE_BYTES);
    close(fd);
    return valid;
}

static EVP_PKEY *load_private_key(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return NULL;
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        (info.st_mode & 077u) != 0u)
    {
        close(fd);
        return NULL;
    }
    BIO *bio = BIO_new_fd(fd, BIO_CLOSE);
    if (bio == NULL)
    {
        close(fd);
        return NULL;
    }
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (key == NULL || EVP_PKEY_base_id(key) != EVP_PKEY_EC)
    {
        EVP_PKEY_free(key);
        return NULL;
    }
    char group[80];
    size_t group_length = 0u;
    if (EVP_PKEY_get_group_name(key, group, sizeof group, &group_length) != 1 ||
        strcmp(group, "prime256v1") != 0)
    {
        EVP_PKEY_free(key);
        return NULL;
    }
    return key;
}

static bool read_device_key(const char *path, uint8_t key[32])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    struct stat info;
    bool valid = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
                 (info.st_mode & 077u) == 0u && info.st_size == 32 &&
                 read_full(fd, key, 32u);
    close(fd);
    return valid;
}

static bool make_pairing_record(EVP_PKEY *host_key, const uint8_t aes_key[32],
                                secure_record_t *record)
{
    pairing_config_t plain = {0};
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    bool valid = EVP_PKEY_get_bn_param(host_key, OSSL_PKEY_PARAM_EC_PUB_X, &x) == 1 &&
                 EVP_PKEY_get_bn_param(host_key, OSSL_PKEY_PARAM_EC_PUB_Y, &y) == 1;
    if (valid)
    {
        plain.public_key[0] = 0x04u;
        valid = BN_bn2binpad(x, plain.public_key + 1u, 32) == 32 &&
                BN_bn2binpad(y, plain.public_key + 33u, 32) == 32;
    }
    BN_free(x);
    BN_free(y);
    if (!valid)
        return false;
    write_le32(&plain.magic, PAIRING_MAGIC);
    write_le32(&plain.version, PAIRING_VERSION);
    write_le32(&plain.crc, creds_crc32(&plain, offsetof(pairing_config_t, crc)));
    memset(record, 0, sizeof *record);
    write_le32(&record->magic, SECURE_RECORD_MAGIC);
    write_le32(&record->version, SECURE_RECORD_VERSION);
    write_le32(&record->payload_len, sizeof plain);
    uint8_t aad[16];
    memcpy(aad, record, 12u);
    write_le32(aad + 12u, PAIRING_FLASH_ADDR);
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    int output_bytes = 0;
    int final_bytes = 0;
    valid = context != NULL && RAND_bytes(record->nonce, sizeof record->nonce) == 1 &&
            EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                                sizeof record->nonce, NULL) == 1 &&
            EVP_EncryptInit_ex(context, NULL, NULL, aes_key, record->nonce) == 1 &&
            EVP_EncryptUpdate(context, NULL, &output_bytes, aad, sizeof aad) == 1 &&
            EVP_EncryptUpdate(context, record->ciphertext, &output_bytes,
                              (const uint8_t *)&plain, sizeof plain) == 1 &&
            EVP_EncryptFinal_ex(context, record->ciphertext + output_bytes,
                                &final_bytes) == 1 &&
            (size_t)(output_bytes + final_bytes) == sizeof plain &&
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG,
                                sizeof record->tag, record->tag) == 1;
    EVP_CIPHER_CTX_free(context);
    clear_bytes(&plain, sizeof plain);
    clear_bytes(aad, sizeof aad);
    return valid;
}

static bool write_enrolment_uf2(const char *mount_path, const secure_record_t *record)
{
    const char *user = getenv("USER");
    char default_mount[MOUNT_LINE_BYTES];
    if (mount_path == NULL)
    {
        int mount_length = user == NULL ? -1 : snprintf(default_mount,
                sizeof default_mount, "%s/%s/RP2350",
                HID_LAB_BOOT_VOLUME_ROOT, user);
        if (mount_length < 0 || (size_t)mount_length >= sizeof default_mount)
            return false;
        mount_path = default_mount;
    }
    char path[MOUNT_LINE_BYTES];
    int path_length = snprintf(path, sizeof path, "%s/pico_hid_cfg.uf2", mount_path);
    if (path_length < 0 || (size_t)path_length >= sizeof path)
        return false;
    enrolment_uf2_t block = {0};
    block.magic0 = UF2_MAGIC0;
    block.magic1 = UF2_MAGIC1;
    block.flags = UF2_FAMILY_FLAG;
    block.target = PAIRING_FLASH_ADDR;
    block.payload_size = UF2_PAYLOAD_BYTES;
    block.block_count = 1u;
    block.family = UF2_RP2350_FAMILY;
    block.magic_end = UF2_MAGIC_END;
    memcpy(block.data, record, sizeof *record);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || fchmod(fd, 0600) != 0)
    {
        if (fd >= 0)
            close(fd);
        clear_bytes(&block, sizeof block);
        return false;
    }
    bool written = write_full_at(fd, (const uint8_t *)&block, sizeof block);
    bool closed = close(fd) == 0;
    clear_bytes(&block, sizeof block);
    return written && closed;
}

static int enrol_host(const char *private_path, const char *aes_path,
                      const char *mount_path, bool clear_record)
{
    EVP_PKEY *host_key = NULL;
    uint8_t aes_key[32] = {0};
    secure_record_t record = {0};
    bool valid = true;
    if (!clear_record)
    {
        host_key = load_private_key(private_path);
        valid = host_key != NULL && read_device_key(aes_path, aes_key) &&
                make_pairing_record(host_key, aes_key, &record);
    }
    valid = valid && write_enrolment_uf2(mount_path, &record);
    EVP_PKEY_free(host_key);
    clear_bytes(aes_key, sizeof aes_key);
    clear_bytes(&record, sizeof record);
    if (!valid)
    {
        fprintf(stderr, "Pairing enrolment failed. Check the key files and BOOTSEL mount.\n");
        return EXIT_FAILURE;
    }
    puts(clear_record ? "Pairing enrolment cleared" : "Pairing key written to BOOTSEL");
    return EXIT_SUCCESS;
}

/* Direct reads bypass cached FAT data. A matching receipt identifies this proof. */
static void log_verdict(int directory_fd, const uint8_t *nonce, const uint8_t *signature)
{
    int fd = openat(directory_fd, "STATUS.BIN", O_RDONLY | O_DIRECT | O_NOFOLLOW |
                                                O_CLOEXEC | O_NONBLOCK);
    struct stat info;
    if (fd < 0)
        return;
    if (fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_size == (off_t)sizeof(pairing_status_t))
    {
        _Alignas(4096) pairing_status_t report;
        const struct timespec interval = {.tv_nsec = 50000000};
        for (unsigned attempt = 0; attempt < 10u; attempt++)
        {
            if (pread(fd, &report, sizeof report, 0) != (ssize_t)sizeof report)
                break;
            if (report.version == 1u &&
                memcmp(report.nonce, nonce, sizeof report.nonce) == 0 &&
                memcmp(report.response, signature, sizeof report.response) == 0)
            {
                if (report.verdict == PROOF_ACCEPTED && report.state == 2u)
                    puts("Board reports pairing proof accepted");
                else if (report.verdict == PROOF_REJECTED && report.state == 1u)
                    puts("Board reports pairing proof rejected");
                break;
            }
            nanosleep(&interval, NULL);
        }
    }
    close(fd);
}

static bool exchange_at_mount(const char *mount_path, EVP_PKEY *key)
{
    int directory_fd = open(mount_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0)
        return false;
    uint8_t challenge[CHALLENGE_BYTES];
    uint8_t signature[SIGNATURE_BYTES];
    bool valid = read_challenge(directory_fd, challenge) &&
                 sign_challenge(key, challenge, signature) &&
                 submit_response(directory_fd, signature);
    if (valid)
        log_verdict(directory_fd, challenge + 10u, signature);
    clear_bytes(challenge, sizeof challenge);
    clear_bytes(signature, sizeof signature);
    close(directory_fd);
    return valid;
}

static bool find_mount(const char *requested, EVP_PKEY *key)
{
    if (requested != NULL)
        return exchange_at_mount(requested, key);
    FILE *mounts = fopen("/proc/mounts", "r");
    if (mounts == NULL)
        return false;
    char line[MOUNT_LINE_BYTES];
    char source[MOUNT_LINE_BYTES];
    char encoded_path[MOUNT_LINE_BYTES];
    char file_system[64];
    char decoded_path[MOUNT_LINE_BYTES];
    bool submitted = false;
    for (size_t rows = 0u; rows < MOUNT_ROWS_MAX &&
         fgets(line, sizeof line, mounts) != NULL; rows++)
    {
        if (sscanf(line, "%1023s %1023s %63s", source, encoded_path,
                   file_system) != 3)
            continue;
        if (strcmp(file_system, "vfat") != 0 && strcmp(file_system, "msdos") != 0 &&
            strcmp(file_system, "fat") != 0)
            continue;
        if (!decode_mount_field(encoded_path, decoded_path, sizeof decoded_path))
            continue;
        if (exchange_at_mount(decoded_path, key))
        {
            submitted = true;
            break;
        }
    }
    fclose(mounts);
    return submitted;
}

static int usage(const char *program)
{
    fprintf(stderr, "Usage: %s --key PRIVATE_KEY [--mount HIDPAIR_PATH]\n", program);
    fprintf(stderr, "       %s --enrol --key PRIVATE_KEY --aes-key AES_KEY [--boot-mount RP2350_PATH]\n", program);
    fprintf(stderr, "       %s --clear-enrolment [--boot-mount RP2350_PATH]\n", program);
    return 2;
}

int main(int argc, char **argv)
{
    if (argc > 1 && (strcmp(argv[1], "--enrol") == 0 ||
                     strcmp(argv[1], "--clear-enrolment") == 0))
    {
        bool clear_record = strcmp(argv[1], "--clear-enrolment") == 0;
        const char *key_path = NULL;
        const char *aes_path = NULL;
        const char *boot_mount = NULL;
        for (int index = 2; index < argc; index++)
        {
            if (strcmp(argv[index], "--key") == 0 && index + 1 < argc)
                key_path = argv[++index];
            else if (strcmp(argv[index], "--aes-key") == 0 && index + 1 < argc)
                aes_path = argv[++index];
            else if (strcmp(argv[index], "--boot-mount") == 0 && index + 1 < argc)
                boot_mount = argv[++index];
            else
                return usage(argv[0]);
        }
        if ((!clear_record && (key_path == NULL || aes_path == NULL)) ||
            (clear_record && (key_path != NULL || aes_path != NULL)))
            return usage(argv[0]);
        return enrol_host(key_path, aes_path, boot_mount, clear_record);
    }
    const char *key_path = NULL;
    const char *mount_path = NULL;
    for (int index = 1; index < argc; index++)
    {
        if (strcmp(argv[index], "--key") == 0 && index + 1 < argc)
            key_path = argv[++index];
        else if (strcmp(argv[index], "--mount") == 0 && index + 1 < argc)
            mount_path = argv[++index];
        else
            return usage(argv[0]);
    }
    if (key_path == NULL)
        return usage(argv[0]);
    EVP_PKEY *key = load_private_key(key_path);
    if (key == NULL)
    {
        fprintf(stderr, "Pairing failed: host key must be a protected P-256 private key\n");
        return EXIT_FAILURE;
    }
    bool submitted = find_mount(mount_path, key);
    EVP_PKEY_free(key);
    if (submitted)
        puts("Submitted pairing proof through the mounted USB volume");
    return submitted || mount_path == NULL ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* Sign a fresh board challenge through its mounted USB storage volume. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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

static const char s_challenge_name[] = "CHALLENG.BIN";
static const char s_response_name[] = "RESPONSE.BIN";
static const uint8_t s_domain[] = "HID-LAB-PAIR-v1";

static void clear_bytes(void *buffer, size_t length)
{
    volatile uint8_t *bytes = buffer;
    while (length-- > 0u)
        *bytes++ = 0u;
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
    fprintf(stderr, "Usage: %s --key PRIVATE_KEY [--mount MOUNT_PATH]\n", program);
    return 2;
}

int main(int argc, char **argv)
{
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

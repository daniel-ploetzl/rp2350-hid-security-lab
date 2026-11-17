/*
 *  Host-side tool to write firmware settings and protected input records as UF2
 *  directly to the RP2350 BOOTSEL mount point.
 *
 * CONFIG LAYOUT IN FLASH (last 4KB sector, offset 0x3FF000):
 *   [0..3]   magic    = 0xCAFEF00E  (little-endian u32)
 *   [4..7]   hours    = N           (little-endian u32)
 *   [8..11]  period_s = N           (little-endian u32, re-activation gap)
 *
 * WI-FI SETTINGS LAYOUT IN FLASH (sector before it, offset 0x3FE000):
 *   encrypted secure_record_t, carrying a wifi_creds_t payload.
 *
 * INPUT SEQUENCE LAYOUT IN FLASH (sector before that, offset 0x3FD000):
 *   encrypted secure_record_t, carrying a login_creds_t payload.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "flash_config.h"
#include "hid_keymap.h"

/* ── UF2 constants ───────────────────────── */
#define UF2_MAGIC_START0   0x0A324655UL
#define UF2_MAGIC_START1   0x9E5D5157UL
#define UF2_MAGIC_END      0x0AB16F30UL
#define UF2_FLAG_FAMILY_ID 0x00002000UL
#define UF2_FAMILY_RP2350  0xE48BFF59UL
#define UF2_PAYLOAD_SIZE   256
#define UF2_DATA_SIZE      476

typedef struct __attribute__((packed)) {
    uint32_t magic0;
    uint32_t magic1;
    uint32_t flags;
    uint32_t target_addr;
    uint32_t payload_size;
    uint32_t block_no;
    uint32_t total_blocks;
    uint32_t family_id;
    uint8_t  data[UF2_DATA_SIZE];
    uint32_t magic_end;
} uf2_block_t;

_Static_assert(sizeof(uf2_block_t) == 512, "UF2 blocks must be exactly 512 bytes");
_Static_assert(sizeof(wifi_creds_t) <= UF2_PAYLOAD_SIZE, "credentials must fit one UF2 block");
_Static_assert(sizeof(login_creds_t) <= UF2_PAYLOAD_SIZE, "input sequence must fit one UF2 block");
_Static_assert(sizeof(pairing_config_t) <= UF2_PAYLOAD_SIZE, "pairing record must fit one UF2 block");
_Static_assert(sizeof(secure_record_t) == UF2_PAYLOAD_SIZE, "encrypted record must fill one UF2 payload");

static void write_le32(void *dest, uint32_t v)
{
    uint8_t *buf = dest;

    buf[0] = v;
    buf[1] = v >> 8;
    buf[2] = v >> 16;
    buf[3] = v >> 24;
}

/* Keep credentials from lingering in compiler-visible stack buffers. */
static void secure_clear(void *ptr, size_t len)
{
    volatile uint8_t *p = ptr;
    while (len--)
        *p++ = 0;
}

static void build_block(uf2_block_t *b, uint32_t addr, const void *payload, size_t len)
{
    memset(b, 0, sizeof(*b));
    b->magic0 = UF2_MAGIC_START0;
    b->magic1 = UF2_MAGIC_START1;
    b->flags  = UF2_FLAG_FAMILY_ID;
    b->target_addr = addr;
    b->payload_size = UF2_PAYLOAD_SIZE;
    b->block_no = 0;
    b->total_blocks = 1;
    b->family_id = UF2_FAMILY_RP2350;
    b->magic_end = UF2_MAGIC_END;
    memcpy(b->data, payload, len);
}

static int write_uf2(uint32_t addr, const void *payload, size_t len)
{
    const char *user = getenv("USER");
    if (!user)
        return (fprintf(stderr, "Error: USER environment variable not set\n"), 1);

    uf2_block_t block;
    build_block(&block, addr, payload, len);

    char path[512];
    snprintf(path, sizeof(path), "/media/%s/RP2350/pico_hid_cfg.uf2", user);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0 && fchmod(fd, 0600) != 0)
    {
        int saved_errno = errno;
        close(fd);
        secure_clear(&block, sizeof(block));
        return (fprintf(stderr, "Failed to secure %s: %s\n", path, strerror(saved_errno)), 1);
    }
    FILE *f = fd >= 0 ? fdopen(fd, "wb") : NULL;
    if (!f)
    {
        int saved_errno = errno;
        if (fd >= 0)
            close(fd);
        secure_clear(&block, sizeof(block));
        return (fprintf(stderr, "Failed to open %s: %s\n", path, strerror(saved_errno)), 1);
    }

    if (fwrite(&block, 1, sizeof(block), f) != sizeof(block))
    {
        fprintf(stderr, "Write failed: %s\n", strerror(errno));
        fclose(f);
        secure_clear(&block, sizeof(block));
        return 1;
    }

    fclose(f);
    printf("UF2 written to %s\n", path);
    secure_clear(&block, sizeof(block));
    return 0;
}

/* Hidden standard input keeps stored sequence text out of shell history,
 * argv and the terminal display. */
static int read_hidden_line(char *buf, size_t size, const char *prompt)
{
    struct termios normal;
    struct termios hidden;
    int is_terminal = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &normal) == 0;

    if (is_terminal)
    {
        fputs(prompt, stderr);
        hidden = normal;
        hidden.c_lflag &= ~(tcflag_t)ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0)
        {
            fputc('\n', stderr);
            return -1;
        }
    }

    char *line = fgets(buf, (int)size, stdin);

    if (is_terminal)
    {
        int restore_failed = tcsetattr(STDIN_FILENO, TCSAFLUSH, &normal) != 0;
        fputc('\n', stderr);
        if (restore_failed)
            return -1;
    }
    if (!line)
        return -1;

    buf[strcspn(buf, "\r\n")] = '\0';
    return 0;
}

/* Accepts seconds or an integer with a single unit suffix s m h d w. */
static int parse_period_s(const char *arg, uint32_t *out)
{
    char *end = NULL;
    long long value = strtoll(arg, &end, 10);

    /* Reject out-of-range before the multiply, so it cannot overflow. */
    if (end == arg || value <= 0 || value > (long long)CONFIG_PERIOD_MAX_S)
        return -1;

    unsigned long long mult = 1;
    if (*end != '\0')
    {
        if (end[1] != '\0')
            return -1;
        switch (*end)
        {
            case 's': mult = 1;      break;
            case 'm': mult = 60;     break;
            case 'h': mult = 3600;   break;
            case 'd': mult = 86400;  break;
            case 'w': mult = 604800; break;
            default:  return -1;
        }
    }

    unsigned long long secs = (unsigned long long)value * mult;
    if (secs < CONFIG_PERIOD_MIN_S || secs > CONFIG_PERIOD_MAX_S)
        return -1;

    *out = (uint32_t)secs;
    return 0;
}

/* The config sector holds both fields, so every write sets the run window and
 * the re-activation period together. period_arg may be NULL, which keeps the
 * one-week default. */
static int write_run_config(const char *hours_arg, const char *period_arg)
{
    char *end = NULL;
    long hours = strtol(hours_arg, &end, 10);

    if (*end != '\0' || hours < (long)CONFIG_HOURS_MIN || hours > (long)CONFIG_HOURS_MAX)
        return (fprintf(stderr, "Error: hours must be %ld-%ld (got %ld)\n",
                        (long)CONFIG_HOURS_MIN, (long)CONFIG_HOURS_MAX, hours), 1);

    uint32_t period_s = CONFIG_DEFAULT_PERIOD_S;
    if (period_arg != NULL && parse_period_s(period_arg, &period_s) != 0)
        return (fprintf(stderr, "Error: period must be 1-%lu s, optional suffix s/m/h/d/w (got %s)\n",
                        (unsigned long)CONFIG_PERIOD_MAX_S, period_arg), 1);

    uint8_t cfg[12];
    write_le32(cfg,     CONFIG_MAGIC);
    write_le32(cfg + 4, (uint32_t)hours);
    write_le32(cfg + 8, period_s);

    if (write_uf2(CONFIG_FLASH_ADDR, cfg, sizeof(cfg)) != 0)
        return 1;
    printf("Configured run window %ld h, re-activation period %lu s\n",
           hours, (unsigned long)period_s);
    return 0;
}

static int read_device_key(const char *path, uint8_t key[32]);
static int seal_record(uint32_t addr, const void *plain, size_t plain_len,
                       const uint8_t key[32], secure_record_t *record);

static int write_credentials(const char *auth_name, const char *ssid, const char *key_path)
{
    uint32_t auth;

    if (strcmp(auth_name, "wpa2") == 0)
        auth = CREDS_AUTH_WPA2;
    else if (strcmp(auth_name, "wpa3") == 0)
        auth = CREDS_AUTH_WPA3;
    else
        return (fprintf(stderr, "Error: security mode must be wpa2 or wpa3\n"), 1);

    size_t ssid_len = strlen(ssid);
    if (ssid_len == 0 || ssid_len > CREDS_SSID_MAX)
        return (fprintf(stderr, "Error: SSID must be 1-%d bytes\n", CREDS_SSID_MAX), 1);

    /* Two spare bytes: a longer line then reads as too long, not as a cut-off password. */
    char key[CREDS_KEY_MAX + 3];
    if (read_hidden_line(key, sizeof(key), "Wi-Fi password: ") != 0)
    {
        secure_clear(key, sizeof(key));
        return (fprintf(stderr, "Error: no password on standard input\n"), 1);
    }

    size_t key_len = strlen(key);
    if (key_len < CREDS_KEY_MIN || key_len > CREDS_KEY_MAX)
    {
        secure_clear(key, sizeof(key));
        return (fprintf(stderr, "Error: password must be %d-%d bytes\n",
                        CREDS_KEY_MIN, CREDS_KEY_MAX), 1);
    }

    uint8_t crypto_key[32] = {0};
    if (read_device_key(key_path, crypto_key) != 0)
    {
        secure_clear(key, sizeof key);
        secure_clear(crypto_key, sizeof crypto_key);
        return 1;
    }

    /* Zeroed first, so unused bytes have a stable CRC inside the encrypted payload. */
    wifi_creds_t creds;
    memset(&creds, 0, sizeof(creds));
    write_le32(&creds.magic, CREDS_MAGIC);
    write_le32(&creds.version, CREDS_VERSION);
    write_le32(&creds.auth, auth);
    memcpy(creds.ssid, ssid, ssid_len);
    memcpy(creds.key, key, key_len);
    write_le32(&creds.crc, creds_crc32(&creds, offsetof(wifi_creds_t, crc)));

    secure_record_t sealed;
    if (seal_record(CREDS_FLASH_ADDR, &creds, sizeof creds,
                    crypto_key, &sealed) != 0)
    {
        secure_clear(key, sizeof key);
        secure_clear(crypto_key, sizeof crypto_key);
        secure_clear(&creds, sizeof creds);
        return (fprintf(stderr, "Error: could not encrypt Wi-Fi record\n"), 1);
    }
    if (write_uf2(CREDS_FLASH_ADDR, &sealed, sizeof sealed) != 0)
    {
        secure_clear(key, sizeof(key));
        secure_clear(crypto_key, sizeof crypto_key);
        secure_clear(&creds, sizeof(creds));
        secure_clear(&sealed, sizeof sealed);
        return 1;
    }
    printf("Stored credentials for %s\n", ssid);
    secure_clear(key, sizeof(key));
    secure_clear(crypto_key, sizeof crypto_key);
    secure_clear(&creds, sizeof(creds));
    secure_clear(&sealed, sizeof sealed);
    return 0;
}

/* The bootrom erases a sector before its first write, so this removes the old record. */
static int clear_credentials(void)
{
    const uint8_t blank[sizeof(secure_record_t)] = {0};

    if (write_uf2(CREDS_FLASH_ADDR, blank, sizeof(blank)) != 0)
        return 1;
    printf("Credentials cleared\n");
    return 0;
}

/* Rejects a field with any character the DE layout cannot type, so the device
 * is never asked to type something it has no key for. */
static int check_typeable(const char *what, const char *s)
{
    for (size_t i = 0; s[i] != '\0'; i++)
    {
        uint8_t usage;
        uint8_t mod;
        if (!hid_key_for(s[i], &usage, &mod))
            return (fprintf(stderr, "Error: %s contains a character that cannot be typed on the DE layout\n",
                            what), 1);
    }
    return 0;
}

static int read_device_key(const char *path, uint8_t key[32])
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
    {
        fprintf(stderr, "Error: cannot open per-device key file: %s\n", strerror(errno));
        return -1;
    }
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || (info.st_mode & 077) != 0)
    {
        close(fd);
        fprintf(stderr, "Error: AES key file must be a regular file with owner-only permissions\n");
        return -1;
    }
    size_t got = 0;
    while (got < 32)
    {
        ssize_t n = read(fd, key + got, 32 - got);
        if (n <= 0)
        {
            close(fd);
            secure_clear(key, 32);
            fprintf(stderr, "Error: AES key file must contain exactly 32 bytes\n");
            return -1;
        }
        got += (size_t)n;
    }
    uint8_t extra;
    ssize_t n = read(fd, &extra, 1);
    close(fd);
    if (n != 0)
    {
        secure_clear(key, 32);
        fprintf(stderr, "Error: AES key file must contain exactly 32 bytes\n");
        return -1;
    }
    return 0;
}

static int seal_record(uint32_t addr, const void *plain, size_t plain_len,
                       const uint8_t key[32], secure_record_t *record)
{
    if (plain_len > sizeof record->ciphertext)
        return -1;
    memset(record, 0, sizeof(*record));
    write_le32(&record->magic, SECURE_RECORD_MAGIC);
    write_le32(&record->version, SECURE_RECORD_VERSION);
    write_le32(&record->payload_len, (uint32_t)plain_len);
    if (RAND_bytes(record->nonce, sizeof record->nonce) != 1)
        return -1;

    uint8_t aad[16];
    memcpy(aad, record, 12);
    write_le32(aad + 12, addr);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return -1;
    int out_len = 0;
    int final_len = 0;
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 sizeof record->nonce, NULL) == 1 &&
             EVP_EncryptInit_ex(ctx, NULL, NULL, key, record->nonce) == 1 &&
             EVP_EncryptUpdate(ctx, NULL, &out_len, aad, sizeof aad) == 1 &&
             EVP_EncryptUpdate(ctx, record->ciphertext, &out_len,
                               (const uint8_t *)plain, (int)plain_len) == 1 &&
             EVP_EncryptFinal_ex(ctx, record->ciphertext + out_len, &final_len) == 1 &&
             (size_t)(out_len + final_len) == plain_len &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                 sizeof record->tag, record->tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    secure_clear(aad, sizeof aad);
    return ok ? 0 : -1;
}

static int write_login(const char *key_path)
{
    char user[LOGIN_USER_MAX + 3] = {0};
    char pass[LOGIN_PASS_MAX + 3] = {0};
    char command[LOGIN_COMMAND_MAX + 3] = {0};
    uint8_t key[32] = {0};
    login_creds_t plain;
    secure_record_t sealed;
    memset(&plain, 0, sizeof plain);
    memset(&sealed, 0, sizeof sealed);

    int result = 1;
    if (read_hidden_line(user, sizeof user, "Input sequence line 1: ") != 0)
        goto no_sequence_line_1;
    user[strcspn(user, "\r\n")] = '\0';
    size_t ulen = strlen(user);
    if (ulen == 0 || ulen > LOGIN_USER_MAX)
    {
        fprintf(stderr, "Error: sequence line 1 must be 1-%d bytes\n", LOGIN_USER_MAX);
        goto done;
    }
    if (check_typeable("sequence line 1", user) != 0)
        goto done;

    if (read_hidden_line(pass, sizeof pass, "Input sequence line 2: ") != 0)
        goto no_sequence_line_2;
    pass[strcspn(pass, "\r\n")] = '\0';
    size_t plen = strlen(pass);
    if (plen > LOGIN_PASS_MAX)
    {
        fprintf(stderr, "Error: sequence line 2 must be at most %d bytes\n", LOGIN_PASS_MAX);
        goto done;
    }
    if (check_typeable("sequence line 2", pass) != 0)
        goto done;

    if (read_hidden_line(command, sizeof command, "Input sequence line 3: ") != 0)
        goto no_command;
    command[strcspn(command, "\r\n")] = '\0';
    size_t command_len = strlen(command);
    if (command_len == 0 || command_len > LOGIN_COMMAND_MAX)
    {
        fprintf(stderr, "Error: command must be 1-%d bytes\n", LOGIN_COMMAND_MAX);
        goto done;
    }
    if (check_typeable("sequence line 3", command) != 0)
        goto done;

    if (read_device_key(key_path, key) != 0)
    {
        goto done;
    }

    write_le32(&plain.magic, LOGIN_MAGIC);
    write_le32(&plain.version, LOGIN_VERSION);
    memcpy(plain.user, user, ulen);
    memcpy(plain.pass, pass, plen);
    memcpy(plain.command, command, command_len);
    write_le32(&plain.crc, creds_crc32(&plain, offsetof(login_creds_t, crc)));
    if (seal_record(LOGIN_CREDS_FLASH_ADDR, &plain, sizeof plain,
                    key, &sealed) != 0)
    {
        fprintf(stderr, "Error: could not encrypt input sequence record\n");
        goto done;
    }
    if (write_uf2(LOGIN_CREDS_FLASH_ADDR, &sealed, sizeof sealed) != 0)
        goto done;
    puts("Stored encrypted input sequence");
    result = 0;
    goto done;

no_sequence_line_1:
    fprintf(stderr, "Error: missing sequence line 1 on standard input\n");
    goto done;
no_sequence_line_2:
    fprintf(stderr, "Error: missing sequence line 2 on standard input\n");
    goto done;
no_command:
    fprintf(stderr, "Error: missing sequence line 3 on standard input\n");
done:
    secure_clear(user, sizeof user);
    secure_clear(pass, sizeof pass);
    secure_clear(command, sizeof command);
    secure_clear(key, sizeof key);
    secure_clear(&plain, sizeof plain);
    secure_clear(&sealed, sizeof sealed);
    return result;
}

static int read_host_public_key(const char *path, uint8_t public_key[PAIRING_PUBLIC_KEY_BYTES])
{
    BIO *input = BIO_new_file(path, "r");
    if (input == NULL)
    {
        fprintf(stderr, "Error: cannot open host public key file\n");
        return -1;
    }
    EVP_PKEY *key = PEM_read_bio_PUBKEY(input, NULL, NULL, NULL);
    BIO_free(input);
    if (key == NULL || EVP_PKEY_is_a(key, "EC") != 1)
    {
        EVP_PKEY_free(key);
        fprintf(stderr, "Error: host key must be a PEM encoded P-256 public key\n");
        return -1;
    }

    char group[80] = {0};
    size_t group_length = 0;
    int valid_group = EVP_PKEY_get_group_name(key, group, sizeof group,
                                             &group_length) == 1 &&
                      (strcmp(group, "prime256v1") == 0 ||
                       strcmp(group, "secp256r1") == 0);
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int valid_key = valid_group && EVP_PKEY_get_bits(key) == 256 &&
                    EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &x) == 1 &&
                    EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &y) == 1;
    if (valid_key)
    {
        public_key[0] = 0x04u;
        valid_key = BN_bn2binpad(x, public_key + 1, 32) == 32 &&
                    BN_bn2binpad(y, public_key + 33, 32) == 32;
    }
    BN_free(x);
    BN_free(y);
    EVP_PKEY_free(key);
    secure_clear(group, sizeof group);
    if (!valid_key)
    {
        secure_clear(public_key, PAIRING_PUBLIC_KEY_BYTES);
        fprintf(stderr, "Error: host public key is not an uncompressed P-256 point\n");
        return -1;
    }
    return 0;
}

static int write_host_pairing(const char *public_path, const char *key_path)
{
    uint8_t aes_key[32] = {0};
    pairing_config_t plain;
    secure_record_t sealed;
    memset(&plain, 0, sizeof plain);
    memset(&sealed, 0, sizeof sealed);
    int result = 1;

    if (read_host_public_key(public_path, plain.public_key) != 0 ||
        read_device_key(key_path, aes_key) != 0)
        goto done;
    write_le32(&plain.magic, PAIRING_MAGIC);
    write_le32(&plain.version, PAIRING_VERSION);
    write_le32(&plain.crc, creds_crc32(&plain, offsetof(pairing_config_t, crc)));
    if (seal_record(PAIRING_FLASH_ADDR, &plain, sizeof plain,
                    aes_key, &sealed) != 0)
    {
        fprintf(stderr, "Error: could not encrypt host pairing record\n");
        goto done;
    }
    if (write_uf2(PAIRING_FLASH_ADDR, &sealed, sizeof sealed) != 0)
        goto done;
    puts("Stored encrypted host pairing key");
    result = 0;

done:
    secure_clear(aes_key, sizeof aes_key);
    secure_clear(&plain, sizeof plain);
    secure_clear(&sealed, sizeof sealed);
    return result;
}

static int clear_host_pairing(void)
{
    const uint8_t blank[sizeof(secure_record_t)] = {0};
    if (write_uf2(PAIRING_FLASH_ADDR, blank, sizeof blank) != 0)
        return 1;
    puts("Host pairing cleared");
    return 0;
}

static int clear_login(void)
{
    const uint8_t blank[sizeof(secure_record_t)] = {0};

    if (write_uf2(LOGIN_CREDS_FLASH_ADDR, blank, sizeof(blank)) != 0)
        return 1;
    printf("Stored input sequence cleared\n");
    return 0;
}

int main(int ac, char **av)
{
    if (ac == 2 && strcmp(av[1], "--wifi-clear") == 0)
        return clear_credentials();
    if (ac == 2 && strcmp(av[1], "--login-clear") == 0)
        return clear_login();
    if (ac == 2 && strcmp(av[1], "--pair-clear") == 0)
        return clear_host_pairing();
    if (ac == 5 && strcmp(av[1], "--wifi") == 0)
        return write_credentials(av[2], av[3], av[4]);
    if (ac == 3 && strcmp(av[1], "--login") == 0)
        return write_login(av[2]);
    if (ac == 4 && strcmp(av[1], "--pair-host") == 0)
        return write_host_pairing(av[2], av[3]);
    if ((ac == 2 || ac == 3) && av[1][0] != '-')
        return write_run_config(av[1], ac == 3 ? av[2] : NULL);

    fprintf(stderr, "Usage: %s <hours> [period]    period e.g. 3600, 30m, 1h, 1d, 7d. Default 7d\n", av[0]);
    fprintf(stderr, "       %s --wifi <wpa2|wpa3> <ssid> <aes-key-file>   (password from hidden standard input)\n", av[0]);
    fprintf(stderr, "       %s --wifi-clear\n", av[0]);
    fprintf(stderr, "       %s --login <aes-key-file>      (three hidden input sequence lines)\n", av[0]);
    fprintf(stderr, "       %s --login-clear\n", av[0]);
    fprintf(stderr, "       %s --pair-host <host-public.pem> <aes-key-file>\n", av[0]);
    fprintf(stderr, "       %s --pair-clear\n", av[0]);
    return 1;
}

/*
 *  Host-side tool to write firmware settings and protected input records as UF2
 *  directly to the RP2350 BOOTSEL mount point.
 *
 * CONFIG LAYOUT IN FLASH (last 4KB sector, offset 0x3FF000):
 *   [0..3]   magic    = 0xCAFEF00E  (little-endian u32)
 *   [4..7]   hours    = N           (little-endian u32)
 *   [8..11]  period_s = N           (little-endian u32, re-activation gap)
 *
 * INPUT SEQUENCE LAYOUT IN FLASH (sector before that, offset 0x3FD000):
 *   encrypted secure_record_t, carrying an input_sequence_config_t payload.
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
#include <openssl/evp.h>
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
#ifndef HID_LAB_BOOT_VOLUME_ROOT
#define HID_LAB_BOOT_VOLUME_ROOT "/media"
#endif

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

typedef struct {
    uint32_t address;
    const void *payload;
    size_t length;
} uf2_record_t;

_Static_assert(sizeof(uf2_block_t) == 512, "UF2 blocks must be exactly 512 bytes");
_Static_assert(sizeof(input_sequence_config_t) <= UF2_PAYLOAD_SIZE, "input sequence must fit one UF2 block");
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

static void build_block(uf2_block_t *b, const uf2_record_t *record,
                        uint32_t number, uint32_t total)
{
    memset(b, 0, sizeof(*b));
    b->magic0 = UF2_MAGIC_START0;
    b->magic1 = UF2_MAGIC_START1;
    b->flags  = UF2_FLAG_FAMILY_ID;
    b->target_addr = record->address;
    b->payload_size = UF2_PAYLOAD_SIZE;
    b->block_no = number;
    b->total_blocks = total;
    b->family_id = UF2_FAMILY_RP2350;
    b->magic_end = UF2_MAGIC_END;
    memcpy(b->data, record->payload, record->length);
}

static int write_uf2(const uf2_record_t *records, size_t count)
{
    if (records == NULL || count == 0u || count > 2u)
        return 1;
    const char *user = getenv("USER");
    if (!user)
        return (fprintf(stderr, "Error: USER environment variable not set\n"), 1);

    uf2_block_t block = {0};
    char path[512];
    snprintf(path, sizeof(path), "%s/%s/RP2350/pico_hid_cfg.uf2",
             HID_LAB_BOOT_VOLUME_ROOT, user);

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

    for (size_t index = 0u; index < count; index++)
    {
        build_block(&block, &records[index], (uint32_t)index, (uint32_t)count);
        if (fwrite(&block, 1u, sizeof block, f) != sizeof block)
        {
            fprintf(stderr, "Write failed: %s\n", strerror(errno));
            fclose(f);
            secure_clear(&block, sizeof block);
            return 1;
        }
    }

    if (fclose(f) != 0)
    {
        int saved_errno = errno;
        secure_clear(&block, sizeof(block));
        return (fprintf(stderr, "Failed to finish writing %s: %s\n",
                        path, strerror(saved_errno)), 1);
    }
    printf("UF2 written to %s\n", path);
    secure_clear(&block, sizeof block);
    return 0;
}

static int write_single_uf2(uint32_t address, const void *payload, size_t length)
{
    const uf2_record_t record = { address, payload, length };
    return write_uf2(&record, 1u);
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
static int prepare_run_config(const char *hours_arg, const char *period_arg,
                              uint8_t cfg[12], uint32_t *hours_out,
                              uint32_t *period_out)
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

    write_le32(cfg,     CONFIG_MAGIC);
    write_le32(cfg + 4, (uint32_t)hours);
    write_le32(cfg + 8, period_s);
    *hours_out = (uint32_t)hours;
    *period_out = period_s;
    return 0;
}

/* Reject unsupported characters before storing the sequence. */
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

static int prepare_input_sequence(const char *key_path, secure_record_t *sealed)
{
    char line1[INPUT_SEQUENCE_LINE1_MAX + 3] = {0};
    char line2[INPUT_SEQUENCE_LINE2_MAX + 3] = {0};
    char action[INPUT_SEQUENCE_ACTION_MAX + 3] = {0};
    uint8_t key[32] = {0};
    input_sequence_config_t plain;
    memset(&plain, 0, sizeof plain);
    memset(sealed, 0, sizeof *sealed);

    int result = 1;
    if (read_hidden_line(line1, sizeof line1, "Input sequence line 1: ") != 0)
        goto no_sequence_line_1;
    line1[strcspn(line1, "\r\n")] = '\0';
    size_t line1_len = strlen(line1);
    if (line1_len == 0 || line1_len > INPUT_SEQUENCE_LINE1_MAX)
    {
        fprintf(stderr, "Error: sequence line 1 must be 1-%d bytes\n", INPUT_SEQUENCE_LINE1_MAX);
        goto done;
    }
    if (check_typeable("sequence line 1", line1) != 0)
        goto done;

    if (read_hidden_line(line2, sizeof line2, "Input sequence line 2: ") != 0)
        goto no_sequence_line_2;
    line2[strcspn(line2, "\r\n")] = '\0';
    size_t line2_len = strlen(line2);
    if (line2_len > INPUT_SEQUENCE_LINE2_MAX)
    {
        fprintf(stderr, "Error: sequence line 2 must be at most %d bytes\n", INPUT_SEQUENCE_LINE2_MAX);
        goto done;
    }
    if (check_typeable("sequence line 2", line2) != 0)
        goto done;

    if (read_hidden_line(action, sizeof action, "Input sequence action: ") != 0)
        goto no_action;
    action[strcspn(action, "\r\n")] = '\0';
    size_t action_len = strlen(action);
    if (action_len == 0 || action_len > INPUT_SEQUENCE_ACTION_MAX)
    {
        fprintf(stderr, "Error: sequence action must be 1-%d bytes\n", INPUT_SEQUENCE_ACTION_MAX);
        goto done;
    }
    if (check_typeable("sequence action", action) != 0)
        goto done;

    if (read_device_key(key_path, key) != 0)
    {
        goto done;
    }

    write_le32(&plain.magic, INPUT_SEQUENCE_MAGIC);
    write_le32(&plain.version, INPUT_SEQUENCE_VERSION);
    memcpy(plain.line1, line1, line1_len);
    memcpy(plain.line2, line2, line2_len);
    memcpy(plain.action, action, action_len);
    write_le32(&plain.crc, creds_crc32(&plain, offsetof(input_sequence_config_t, crc)));
    if (seal_record(INPUT_SEQUENCE_FLASH_ADDR, &plain, sizeof plain,
                    key, sealed) != 0)
    {
        fprintf(stderr, "Error: could not encrypt input sequence record\n");
        goto done;
    }
    result = 0;
    goto done;

no_sequence_line_1:
    fprintf(stderr, "Error: missing sequence line 1 on standard input\n");
    goto done;
no_sequence_line_2:
    fprintf(stderr, "Error: missing sequence line 2 on standard input\n");
    goto done;
no_action:
    fprintf(stderr, "Error: missing sequence action on standard input\n");
done:
    secure_clear(line1, sizeof line1);
    secure_clear(line2, sizeof line2);
    secure_clear(action, sizeof action);
    secure_clear(key, sizeof key);
    secure_clear(&plain, sizeof plain);
    if (result != 0)
        secure_clear(sealed, sizeof *sealed);
    return result;
}

static int write_configuration(const char *hours_arg, const char *period_arg,
                               const char *sequence_key)
{
    uint8_t config[12] = {0};
    uint32_t hours = 0u;
    uint32_t period = 0u;
    secure_record_t sequence = {0};
    uf2_record_t records[2];
    size_t count = 0u;
    int result = 1;

    if (hours_arg != NULL)
    {
        if (prepare_run_config(hours_arg, period_arg, config, &hours, &period) != 0)
            goto done;
        records[count++] = (uf2_record_t){ CONFIG_FLASH_ADDR, config, sizeof config };
    }
    if (sequence_key != NULL)
    {
        if (prepare_input_sequence(sequence_key, &sequence) != 0)
            goto done;
        records[count++] = (uf2_record_t){ INPUT_SEQUENCE_FLASH_ADDR, &sequence, sizeof sequence };
    }
    if (count == 0u || write_uf2(records, count) != 0)
        goto done;
    if (hours_arg != NULL)
        printf("Configured run window %lu h, re-activation period %lu s\n",
               (unsigned long)hours, (unsigned long)period);
    if (sequence_key != NULL)
        puts("Stored encrypted input sequence");
    result = 0;

done:
    secure_clear(config, sizeof config);
    secure_clear(&sequence, sizeof sequence);
    return result;
}

static int clear_input_sequence(void)
{
    const uint8_t blank[sizeof(secure_record_t)] = {0};

    if (write_single_uf2(INPUT_SEQUENCE_FLASH_ADDR, blank, sizeof(blank)) != 0)
        return 1;
    printf("Stored input sequence cleared\n");
    return 0;
}

int main(int ac, char **av)
{
    if (ac == 2 && strcmp(av[1], "--sequence-clear") == 0)
        return clear_input_sequence();
    if (ac == 3 && strcmp(av[1], "--sequence") == 0)
        return write_configuration(NULL, NULL, av[2]);
    if (ac == 4 && av[1][0] != '-' && strcmp(av[2], "--sequence") == 0)
        return write_configuration(av[1], NULL, av[3]);
    if (ac == 5 && av[1][0] != '-' && strcmp(av[3], "--sequence") == 0)
        return write_configuration(av[1], av[2], av[4]);
    if ((ac == 2 || ac == 3) && av[1][0] != '-')
        return write_configuration(av[1], ac == 3 ? av[2] : NULL, NULL);

    fprintf(stderr, "Usage: %s <hours> [period] [--sequence <aes-key-file>]\n", av[0]);
    fprintf(stderr, "       %s --sequence <aes-key-file>\n", av[0]);
    fprintf(stderr, "       %s --sequence-clear\n", av[0]);
    return 1;
}

/* Host build checks for key headers, OTP JSON and firmware UF2 files. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define AES_KEY_BYTES 32u
#define UF2_BLOCK_BYTES 512u
#define UF2_PAYLOAD_MAX 476u
#define UF2_MAGIC0 0x0A324655u
#define UF2_MAGIC1 0x9E5D5157u
#define UF2_MAGIC_END 0x0AB16F30u
#define UF2_FLAG_FAMILY 0x00002000u
#define UF2_FLAG_EXTENSION 0x00008000u
#define UF2_FLASH_BASE 0x10000000u
#define UF2_PAIRING_SECTOR 0x103FC000u
#define UF2_RP2350_FAMILY 0xE48BFF59u
#define UF2_ABSOLUTE_FAMILY 0xE48BFF57u
#define UF2_ABSOLUTE_ADDR 0x10FFFF00u
#define JSON_BYTES_MAX (1024u * 1024u)
#define JSON_TOKENS_MAX 8192u
#define JSON_DEPTH_MAX 32u
#define JSON_EDITS_MAX 32u
#define JSON_EDIT_TEXT_MAX 512u

typedef enum { JSON_OBJECT, JSON_ARRAY, JSON_STRING, JSON_ATOM } json_type_t;
typedef struct {
    json_type_t type;
    size_t start;
    size_t end;
    size_t first_child;
    size_t next;
} json_token_t;
typedef struct {
    size_t start;
    size_t end;
    size_t text_len;
    char text[JSON_EDIT_TEXT_MAX];
} json_edit_t;

static char s_json[JSON_BYTES_MAX + 1u];
static char s_output[JSON_BYTES_MAX + 1u];
static json_token_t s_tokens[JSON_TOKENS_MAX];
static json_edit_t s_edits[JSON_EDITS_MAX];
static size_t s_token_count;
static size_t s_edit_count;
static size_t s_json_len;

static void secure_bzero(void *pointer, size_t length);

static void print_error(const char *message)
{
    fprintf(stderr, "Error: %s\n", message);
}

static bool read_exact_file(const char *path, uint8_t *buffer, size_t size)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
        return false;
    size_t count = fread(buffer, 1u, size, file);
    int extra = fgetc(file);
    bool valid = count == size && extra == EOF && !ferror(file);
    if (fclose(file) != 0)
        valid = false;
    return valid;
}

static int format_key_header(const uint8_t key[AES_KEY_BYTES],
                             char *header, size_t capacity, size_t *length)
{
    static const char prefix[] =
        "/* Generated for the unprotected development profile only. */\n"
        "#ifndef HID_LAB_DEV_AES_KEY_H\n"
        "#define HID_LAB_DEV_AES_KEY_H\n"
        "#include <stdint.h>\n"
        "static const uint8_t hid_lab_dev_aes_key[32] = {";
    size_t used = sizeof prefix - 1u;
    if (used >= capacity)
        return -1;
    memcpy(header, prefix, used);
    for (size_t index = 0u; index < AES_KEY_BYTES; index++)
    {
        int written = snprintf(header + used, capacity - used,
                               "%s0x%02Xu", index == 0u ? "" : ", ", key[index]);
        if (written < 0 || (size_t)written >= capacity - used)
            return -1;
        used += (size_t)written;
    }
    static const char suffix[] = "};\n#endif\n";
    if (sizeof suffix - 1u >= capacity - used)
        return -1;
    memcpy(header + used, suffix, sizeof suffix - 1u);
    used += sizeof suffix - 1u;
    *length = used;
    return 0;
}

static int embed_key(const char *key_path, const char *header_path)
{
    uint8_t key[AES_KEY_BYTES];
    char header[1024];
    size_t header_len = 0u;
    if (!read_exact_file(key_path, key, sizeof key))
    {
        print_error("development AES key must be exactly 32 bytes");
        return 1;
    }
    if (format_key_header(key, header, sizeof header, &header_len) != 0)
    {
        secure_bzero(key, sizeof key);
        print_error("could not format development key header");
        return 1;
    }
    int fd = open(header_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || fchmod(fd, 0600) != 0)
    {
        if (fd >= 0)
            close(fd);
        secure_bzero(key, sizeof key);
        print_error("could not create owner only development key header");
        return 1;
    }
    size_t written = 0u;
    while (written < header_len)
    {
        ssize_t result = write(fd, header + written, header_len - written);
        if (result <= 0)
        {
            close(fd);
            secure_bzero(key, sizeof key);
            print_error("could not write development key header");
            return 1;
        }
        written += (size_t)result;
    }
    int result = close(fd);
    secure_bzero(key, sizeof key);
    return result == 0 ? 0 : 1;
}

static int verify_key_header(const char *key_path, const char *header_path)
{
    uint8_t key[AES_KEY_BYTES];
    char expected[1024];
    char actual[1024];
    size_t expected_len = 0u;
    if (!read_exact_file(key_path, key, sizeof key))
    {
        print_error("development AES key must be exactly 32 bytes");
        return 1;
    }
    if (format_key_header(key, expected, sizeof expected, &expected_len) != 0)
    {
        secure_bzero(key, sizeof key);
        return 1;
    }
    struct stat info;
    if (stat(header_path, &info) != 0 || (info.st_mode & 0777u) != 0600u ||
        !read_exact_file(header_path, (uint8_t *)actual, expected_len) ||
        memcmp(expected, actual, expected_len) != 0)
    {
        secure_bzero(key, sizeof key);
        print_error("generated development key header does not match key file");
        return 1;
    }
    secure_bzero(key, sizeof key);
    puts("Development key header matches the selected AES key");
    return 0;
}

static uint32_t read_le32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static int verify_uf2(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
    {
        print_error("could not open firmware UF2");
        return 1;
    }
    if (fseek(file, 0L, SEEK_END) != 0)
    {
        fclose(file);
        print_error("could not inspect firmware UF2 size");
        return 1;
    }
    long byte_count = ftell(file);
    if (byte_count <= 0 || (byte_count % (long)UF2_BLOCK_BYTES) != 0 ||
        fseek(file, 0L, SEEK_SET) != 0)
    {
        fclose(file);
        print_error("invalid UF2 length");
        return 1;
    }
    uint32_t block_count = (uint32_t)(byte_count / (long)UF2_BLOCK_BYTES);
    uint8_t block[UF2_BLOCK_BYTES];
    for (uint32_t index = 0u; index < block_count; index++)
    {
        if (fread(block, 1u, sizeof block, file) != sizeof block)
        {
            fclose(file);
            print_error("truncated UF2 block");
            return 1;
        }
        uint32_t flags = read_le32(block + 8u);
        uint32_t target = read_le32(block + 12u);
        uint32_t payload = read_le32(block + 16u);
        uint32_t number = read_le32(block + 20u);
        uint32_t total = read_le32(block + 24u);
        uint32_t family = read_le32(block + 28u);
        if (read_le32(block) != UF2_MAGIC0 || read_le32(block + 4u) != UF2_MAGIC1 ||
            read_le32(block + 508u) != UF2_MAGIC_END)
        {
            fclose(file);
            print_error("invalid UF2 block marker");
            return 1;
        }
        if (payload == 0u || payload > UF2_PAYLOAD_MAX)
        {
            fclose(file);
            print_error("invalid UF2 payload length");
            return 1;
        }
        bool e10 = index == 0u && flags == (UF2_FLAG_FAMILY | UF2_FLAG_EXTENSION) &&
                   target == UF2_ABSOLUTE_ADDR && payload == 256u && number == 0u &&
                   total == 2u && family == UF2_ABSOLUTE_FAMILY;
        if (e10)
        {
            for (size_t byte = 32u; byte < 32u + payload; byte++)
            {
                if (block[byte] != 0xEFu)
                    e10 = false;
            }
        }
        if (e10)
            continue;
        if (flags != UF2_FLAG_FAMILY || family != UF2_RP2350_FAMILY ||
            total != block_count - 1u || target < UF2_FLASH_BASE ||
            target > UINT32_MAX - payload || target + payload > UF2_PAIRING_SECTOR)
        {
            fclose(file);
            print_error("firmware UF2 block overlaps or misses firmware flash");
            return 1;
        }
    }
    if (fclose(file) != 0)
        return 1;
    return 0;
}

static void secure_bzero(void *pointer, size_t length)
{
    volatile uint8_t *bytes = pointer;
    while (length-- > 0u)
        *bytes++ = 0u;
}

static bool json_space(char value)
{
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

static void json_skip_space(size_t *position)
{
    while (*position < s_json_len && json_space(s_json[*position]))
        (*position)++;
}

static size_t json_add_token(json_type_t type, size_t start)
{
    if (s_token_count >= JSON_TOKENS_MAX)
        return SIZE_MAX;
    size_t index = s_token_count++;
    s_tokens[index].type = type;
    s_tokens[index].start = start;
    s_tokens[index].end = 0u;
    s_tokens[index].first_child = SIZE_MAX;
    s_tokens[index].next = SIZE_MAX;
    return index;
}

static bool json_parse_string(size_t *position, size_t *token)
{
    if (s_json[*position] != '"')
        return false;
    size_t start = (*position)++;
    *token = json_add_token(JSON_STRING, start);
    if (*token == SIZE_MAX)
        return false;
    while (*position < s_json_len)
    {
        char value = s_json[(*position)++];
        if (value == '"')
        {
            s_tokens[*token].end = *position;
            return true;
        }
        if (value == '\\')
        {
            if (*position >= s_json_len)
                return false;
            (*position)++;
        }
        else if ((unsigned char)value < 0x20u)
        {
            return false;
        }
    }
    return false;
}

static bool json_parse_value(size_t *position, size_t parent, size_t depth,
                             size_t *value_token);

static bool json_add_child(size_t parent, size_t child)
{
    if (parent == SIZE_MAX)
        return true;
    size_t previous = s_tokens[parent].first_child;
    if (previous == SIZE_MAX)
    {
        s_tokens[parent].first_child = child;
        return true;
    }
    while (s_tokens[previous].next != SIZE_MAX)
        previous = s_tokens[previous].next;
    s_tokens[previous].next = child;
    return true;
}

static bool json_parse_container(size_t *position, size_t parent, size_t depth,
                                 size_t *container_token, char close)
{
    char open = s_json[*position];
    json_type_t type = open == '{' ? JSON_OBJECT : JSON_ARRAY;
    size_t container = json_add_token(type, *position);
    if (container == SIZE_MAX || depth >= JSON_DEPTH_MAX)
        return false;
    json_add_child(parent, container);
    *container_token = container;
    (*position)++;
    json_skip_space(position);
    if (*position < s_json_len && s_json[*position] == close)
    {
        (*position)++;
        s_tokens[container].end = *position;
        return true;
    }
    for (;;)
    {
        if (type == JSON_OBJECT)
        {
            size_t key;
            if (*position >= s_json_len || !json_parse_string(position, &key))
                return false;
            json_add_child(container, key);
            json_skip_space(position);
            if (*position >= s_json_len || s_json[*position] != ':')
                return false;
            (*position)++;
            json_skip_space(position);
        }
        size_t child;
        if (!json_parse_value(position, container, depth + 1u, &child))
            return false;
        json_skip_space(position);
        if (*position >= s_json_len)
            return false;
        if (s_json[*position] == close)
        {
            (*position)++;
            s_tokens[container].end = *position;
            return true;
        }
        if (s_json[*position] != ',')
            return false;
        (*position)++;
        json_skip_space(position);
    }
}

static bool json_parse_value(size_t *position, size_t parent, size_t depth,
                             size_t *value_token)
{
    json_skip_space(position);
    if (*position >= s_json_len)
        return false;
    if (s_json[*position] == '{' || s_json[*position] == '[')
    {
        char close = s_json[*position] == '{' ? '}' : ']';
        return json_parse_container(position, parent, depth, value_token, close);
    }
    if (s_json[*position] == '"')
    {
        if (!json_parse_string(position, value_token))
            return false;
        return json_add_child(parent, *value_token);
    }
    size_t start = *position;
    while (*position < s_json_len && s_json[*position] != ',' &&
           s_json[*position] != '}' && s_json[*position] != ']' &&
           !json_space(s_json[*position]))
        (*position)++;
    if (*position == start)
        return false;
    *value_token = json_add_token(JSON_ATOM, start);
    if (*value_token == SIZE_MAX)
        return false;
    s_tokens[*value_token].end = *position;
    return json_add_child(parent, *value_token);
}

static bool json_parse_document(size_t *root)
{
    size_t position = 0u;
    s_token_count = 0u;
    json_skip_space(&position);
    if (position >= s_json_len || s_json[position] != '{')
        return false;
    if (!json_parse_value(&position, SIZE_MAX, 0u, root))
        return false;
    json_skip_space(&position);
    return position == s_json_len && s_tokens[*root].type == JSON_OBJECT;
}

static bool json_key_equals(size_t token, const char *key)
{
    size_t length = strlen(key);
    return s_tokens[token].type == JSON_STRING &&
           s_tokens[token].end - s_tokens[token].start == length + 2u &&
           memcmp(s_json + s_tokens[token].start + 1u, key, length) == 0;
}

static size_t json_find_property(size_t object, const char *key)
{
    for (size_t token = s_tokens[object].first_child; token != SIZE_MAX;)
    {
        size_t value = s_tokens[token].next;
        if (value == SIZE_MAX)
            return SIZE_MAX;
        if (json_key_equals(token, key))
            return value;
        token = s_tokens[value].next;
    }
    return SIZE_MAX;
}

static bool json_token_is(size_t token, const char *value)
{
    size_t length = strlen(value);
    return token != SIZE_MAX && s_tokens[token].end - s_tokens[token].start == length &&
           memcmp(s_json + s_tokens[token].start, value, length) == 0;
}

static bool json_add_edit(size_t start, size_t end, const char *text)
{
    if (s_edit_count >= JSON_EDITS_MAX)
        return false;
    size_t length = strlen(text);
    if (length >= JSON_EDIT_TEXT_MAX)
        return false;
    json_edit_t *edit = &s_edits[s_edit_count++];
    edit->start = start;
    edit->end = end;
    edit->text_len = length;
    memcpy(edit->text, text, length);
    return true;
}

static bool json_set_property(size_t object, const char *key, const char *value,
                              bool allow_null)
{
    size_t current = json_find_property(object, key);
    if (current != SIZE_MAX)
    {
        if (allow_null && !json_token_is(current, "null") &&
            !json_token_is(current, "\"0x3d3d3d\""))
        {
            print_error("refusing an unexpected OTP access policy");
            return false;
        }
        return json_add_edit(s_tokens[current].start, s_tokens[current].end, value);
    }
    char insertion[JSON_EDIT_TEXT_MAX];
    bool has_children = s_tokens[object].first_child != SIZE_MAX;
    size_t insertion_position = s_tokens[object].end - 1u;
    for (size_t index = 0u; index < s_edit_count; index++)
    {
        if (s_edits[index].start == insertion_position &&
            s_edits[index].end == insertion_position)
        {
            size_t previous_length = s_edits[index].text_len;
            int appended = snprintf(s_edits[index].text + previous_length,
                                    sizeof s_edits[index].text - previous_length,
                                    ", \"%s\":%s", key, value);
            if (appended < 0 || (size_t)appended >=
                sizeof s_edits[index].text - previous_length)
                return false;
            s_edits[index].text_len += (size_t)appended;
            return true;
        }
    }
    int written = snprintf(insertion, sizeof insertion, "%s\"%s\":%s",
                           has_children ? ", " : "", key, value);
    if (written < 0 || (size_t)written >= sizeof insertion)
        return false;
    return json_add_edit(insertion_position, insertion_position, insertion);
}

static int compare_edits_descending(const void *left, const void *right)
{
    const json_edit_t *a = left;
    const json_edit_t *b = right;
    if (a->start < b->start)
        return 1;
    if (a->start > b->start)
        return -1;
    return 0;
}

static bool json_apply_edits(void)
{
    qsort(s_edits, s_edit_count, sizeof s_edits[0], compare_edits_descending);
    size_t length = s_json_len;
    memcpy(s_output, s_json, s_json_len + 1u);
    for (size_t index = 0u; index < s_edit_count; index++)
    {
        json_edit_t *edit = &s_edits[index];
        size_t removed = edit->end - edit->start;
        if (length - removed + edit->text_len > JSON_BYTES_MAX)
            return false;
        memmove(s_output + edit->start + edit->text_len,
                s_output + edit->end, length - edit->end + 1u);
        memcpy(s_output + edit->start, edit->text, edit->text_len);
        length = length - removed + edit->text_len;
    }
    s_json_len = length;
    return true;
}

static bool json_add_object_properties(size_t root, const char *object_key,
                                       const char *properties)
{
    size_t object = json_find_property(root, object_key);
    if (object != SIZE_MAX)
    {
        if (s_tokens[object].type != JSON_OBJECT)
            return false;
        (void)properties;
        return true;
    }
    char value[JSON_EDIT_TEXT_MAX];
    int written = snprintf(value, sizeof value, "{%s}", properties);
    if (written < 0 || (size_t)written >= sizeof value)
        return false;
    return json_set_property(root, object_key, value, false);
}

static bool json_prepare_otp(void)
{
    size_t root;
    if (!json_parse_document(&root))
    {
        print_error("invalid OTP JSON document");
        return false;
    }
    static const char *sources[4] = {"29:0", "29:32", "30:0", "30:32"};
    static const char *targets[4] = {"24:0", "24:32", "25:0", "25:32"};
    for (size_t index = 0u; index < 4u; index++)
    {
        size_t source = json_find_property(root, sources[index]);
        if (source == SIZE_MAX)
        {
            print_error("missing required OTP key share row");
            return false;
        }
        char value[JSON_EDIT_TEXT_MAX];
        size_t length = s_tokens[source].end - s_tokens[source].start;
        if (length >= sizeof value)
            return false;
        memcpy(value, s_json + s_tokens[source].start, length);
        value[length] = '\0';
        if (!json_set_property(root, targets[index], value, false))
            return false;
    }
    if (!json_set_property(root, "PAGE24_LOCK1", "\"0x3d3d3d\"", true) ||
        !json_set_property(root, "PAGE25_LOCK1", "\"0x3d3d3d\"", true))
        return false;
    size_t crit1 = json_find_property(root, "crit1");
    if (crit1 == SIZE_MAX)
    {
        if (!json_add_object_properties(root, "crit1",
              "\"debug_disable\":1,\"secure_debug_disable\":1,"
              "\"glitch_detector_enable\":1,\"glitch_detector_sens\":3,"
              "\"secure_boot_enable\":1"))
            return false;
    }
    else
    {
        if (s_tokens[crit1].type != JSON_OBJECT ||
            !json_set_property(crit1, "debug_disable", "1", false) ||
            !json_set_property(crit1, "secure_debug_disable", "1", false) ||
            !json_set_property(crit1, "glitch_detector_enable", "1", false) ||
            !json_set_property(crit1, "glitch_detector_sens", "3", false) ||
            !json_set_property(crit1, "secure_boot_enable", "1", false))
            return false;
    }
    size_t boot_flags1 = json_find_property(root, "boot_flags1");
    if (boot_flags1 == SIZE_MAX)
    {
        if (!json_add_object_properties(root, "boot_flags1", "\"key_invalid\":254"))
            return false;
    }
    else if (s_tokens[boot_flags1].type != JSON_OBJECT ||
             !json_set_property(boot_flags1, "key_invalid", "254", false))
    {
        return false;
    }
    return json_apply_edits();
}

static int extend_otp(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
    {
        print_error("could not open OTP JSON file");
        return 1;
    }
    s_json_len = fread(s_json, 1u, JSON_BYTES_MAX, file);
    bool valid = !ferror(file) && fgetc(file) == EOF;
    if (fclose(file) != 0)
        valid = false;
    if (!valid)
    {
        print_error("OTP JSON is too large or unreadable");
        return 1;
    }
    s_json[s_json_len] = '\0';
    s_edit_count = 0u;
    if (!json_prepare_otp())
        return 1;
    char temporary[4096];
    int count = snprintf(temporary, sizeof temporary, "%s.tmp.%ld", path, (long)getpid());
    if (count < 0 || (size_t)count >= sizeof temporary)
        return 1;
    struct stat info;
    mode_t mode = stat(path, &info) == 0 ? info.st_mode & 0777u : 0600u;
    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0)
        return 1;
    size_t written = 0u;
    while (written < s_json_len)
    {
        ssize_t result = write(fd, s_output + written, s_json_len - written);
        if (result <= 0)
        {
            close(fd);
            unlink(temporary);
            return 1;
        }
        written += (size_t)result;
    }
    bool saved = fsync(fd) == 0 && close(fd) == 0 && rename(temporary, path) == 0;
    if (!saved)
    {
        unlink(temporary);
        print_error("could not replace OTP JSON file");
        return 1;
    }
    return 0;
}

static int usage(const char *program)
{
    fprintf(stderr, "Usage: %s embed-key KEY_FILE HEADER_FILE\n", program);
    fprintf(stderr, "       %s verify-key KEY_FILE HEADER_FILE\n", program);
    fprintf(stderr, "       %s verify-uf2 FIRMWARE_UF2\n", program);
    fprintf(stderr, "       %s extend-otp OTP_JSON\n", program);
    return 2;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return usage(argv[0]);
    if (strcmp(argv[1], "embed-key") == 0 && argc == 4)
        return embed_key(argv[2], argv[3]);
    if (strcmp(argv[1], "verify-key") == 0 && argc == 4)
        return verify_key_header(argv[2], argv[3]);
    if (strcmp(argv[1], "verify-uf2") == 0 && argc == 3)
        return verify_uf2(argv[2]);
    if (strcmp(argv[1], "extend-otp") == 0 && argc == 3)
        return extend_otp(argv[2]);
    return usage(argv[0]);
}

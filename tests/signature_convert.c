/* Convert OpenSSL DER ECDSA signatures to the firmware's fixed width format. */
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define DER_BYTES_MAX 80u
#define SIGNATURE_BYTES 64u
#define SIGNATURE_PART_BYTES 32u

static bool read_der_signature(const char *path, uint8_t der[DER_BYTES_MAX],
                               size_t *der_length)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
        return false;
    *der_length = fread(der, 1u, DER_BYTES_MAX, file);
    bool valid = !ferror(file) && fgetc(file) == EOF;
    if (fclose(file) != 0)
        valid = false;
    return valid && *der_length > 0u;
}

static bool convert_signature(const uint8_t *der, size_t der_length,
                              uint8_t raw[SIGNATURE_BYTES])
{
    const unsigned char *cursor = der;
    ECDSA_SIG *signature = d2i_ECDSA_SIG(NULL, &cursor, (long)der_length);
    if (signature == NULL || cursor != der + der_length)
    {
        ECDSA_SIG_free(signature);
        return false;
    }
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    ECDSA_SIG_get0(signature, &r, &s);
    bool valid = BN_bn2binpad(r, raw, SIGNATURE_PART_BYTES) ==
                     (int)SIGNATURE_PART_BYTES &&
                 BN_bn2binpad(s, raw + SIGNATURE_PART_BYTES,
                              SIGNATURE_PART_BYTES) == (int)SIGNATURE_PART_BYTES;
    ECDSA_SIG_free(signature);
    return valid;
}

static bool write_raw_signature(const char *path,
                                const uint8_t raw[SIGNATURE_BYTES])
{
    FILE *file = fopen(path, "wb");
    if (file == NULL)
        return false;
    bool valid = fwrite(raw, 1u, SIGNATURE_BYTES, file) == SIGNATURE_BYTES;
    if (fclose(file) != 0)
        valid = false;
    return valid;
}

int main(int argc, char **argv)
{
    uint8_t der[DER_BYTES_MAX];
    uint8_t raw[SIGNATURE_BYTES];
    size_t der_length = 0u;
    if (argc != 3 || !read_der_signature(argv[1], der, &der_length) ||
        !convert_signature(der, der_length, raw) ||
        !write_raw_signature(argv[2], raw))
        return 1;
    return 0;
}

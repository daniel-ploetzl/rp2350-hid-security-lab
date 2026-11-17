#!/usr/bin/env python3
"""Generate a private build header for the explicitly unsecure test profile."""

import os
import sys
from pathlib import Path


KEY_BYTES = 32


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: embed_dev_aes_key.py KEY_FILE OUTPUT_HEADER")

    key = Path(sys.argv[1]).read_bytes()
    if len(key) != KEY_BYTES:
        raise SystemExit("development AES key must be exactly 32 bytes")

    values = ", ".join(f"0x{value:02X}u" for value in key)
    header = (
        "/* Generated for the unprotected development profile only. */\n"
        "#ifndef HID_LAB_DEV_AES_KEY_H\n"
        "#define HID_LAB_DEV_AES_KEY_H\n"
        "#include <stdint.h>\n"
        f"static const uint8_t hid_lab_dev_aes_key[{KEY_BYTES}] = {{{values}}};\n"
        "#endif\n"
    )
    output = Path(sys.argv[2])
    output.write_text(header, encoding="ascii")
    os.chmod(output, 0o600)


if __name__ == "__main__":
    main()

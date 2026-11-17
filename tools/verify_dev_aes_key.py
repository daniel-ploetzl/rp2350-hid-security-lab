#!/usr/bin/env python3
"""Check that a development header embeds the selected AES key exactly."""

import re
import sys
from pathlib import Path


KEY_BYTES = 32
ARRAY_PATTERN = re.compile(
    r"static const uint8_t hid_lab_dev_aes_key\[32\] = \{([^}]*)\};",
    re.DOTALL,
)
BYTE_PATTERN = re.compile(r"0x([0-9a-fA-F]{2})u")


def embedded_key(header_path):
    header = Path(header_path).read_text(encoding="ascii")
    match = ARRAY_PATTERN.search(header)
    if match is None:
        raise ValueError("development key array is missing")
    values = BYTE_PATTERN.findall(match.group(1))
    residue = BYTE_PATTERN.sub("", match.group(1))
    residue = residue.replace(",", "").strip()
    if len(values) != KEY_BYTES or residue:
        raise ValueError("development key array has an invalid format")
    return bytes(int(value, 16) for value in values)


def main():
    if len(sys.argv) != 3:
        print("usage: verify_dev_aes_key.py KEY_FILE HEADER_FILE", file=sys.stderr)
        return 2
    try:
        key = Path(sys.argv[1]).read_bytes()
        if len(key) != KEY_BYTES:
            raise ValueError("development AES key must be exactly 32 bytes")
        if key != embedded_key(sys.argv[2]):
            raise ValueError("generated development key header does not match key file")
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print("Development key header matches the selected AES key")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

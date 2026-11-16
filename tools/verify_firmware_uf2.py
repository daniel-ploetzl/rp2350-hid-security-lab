#!/usr/bin/env python3
"""Reject firmware UF2 blocks outside the firmware flash region."""

import struct
import sys
from pathlib import Path

MAGIC0 = 0x0A324655
MAGIC1 = 0x9E5D5157
MAGIC_END = 0x0AB16F30
FLAG_FAMILY_ID = 0x00002000
FLAG_EXTENSION = 0x00008000
FLASH_BASE = 0x10000000
PAIRING_SECTOR = 0x103FC000
RP2350_ARM_S_FAMILY = 0xE48BFF59
ABSOLUTE_FAMILY = 0xE48BFF57
ABSOLUTE_BLOCK_ADDR = 0x10FFFF00
BLOCK_BYTES = 512


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <firmware.uf2>", file=sys.stderr)
        return 2
    data = Path(sys.argv[1]).read_bytes()
    if not data or len(data) % BLOCK_BYTES:
        raise SystemExit("invalid UF2 length")
    block_count = len(data) // BLOCK_BYTES
    for block_index, offset in enumerate(range(0, len(data), BLOCK_BYTES)):
        block = data[offset:offset + BLOCK_BYTES]
        magic0, magic1, flags, target, payload, block_num, total_blocks, family = struct.unpack_from("<8I", block)
        end_magic = struct.unpack_from("<I", block, 508)[0]
        if (magic0, magic1, end_magic) != (MAGIC0, MAGIC1, MAGIC_END):
            raise SystemExit(f"invalid UF2 block at byte {offset}")
        if payload == 0 or payload > 476:
            raise SystemExit(f"invalid UF2 payload length at block {block_index}")
        if (block_index == 0 and flags == FLAG_FAMILY_ID | FLAG_EXTENSION and
                target == ABSOLUTE_BLOCK_ADDR and payload == 256 and block_num == 0 and
                total_blocks == 2 and family == ABSOLUTE_FAMILY and
                block[32:32 + payload] == b"\xef" * payload):
            continue
        if flags != FLAG_FAMILY_ID or family != RP2350_ARM_S_FAMILY:
            raise SystemExit(f"unexpected UF2 block type at block {block_index}")
        if total_blocks != block_count - 1 or target < FLASH_BASE or target + payload > PAIRING_SECTOR:
            raise SystemExit(f"firmware UF2 block at 0x{target:08x} overlaps or misses firmware flash")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

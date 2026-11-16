#!/usr/bin/env python3
"""Add a Secure-readable copy of picotool's AES key shares for record crypto.

The SDK boot decryptor locks its own key pages after loading the SRAM image.
This duplicates the shares into an adjacent application key slot. The slot is
marked Secure-readable only and the firmware software-locks it after import.
"""

import copy
import json
import sys
from pathlib import Path

SOURCE_PAGE = 29
TARGET_PAGE = 24


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <otp-json>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    otp = json.loads(path.read_text())
    for row in range(2):
        source = f"{SOURCE_PAGE + row}:0"
        target = f"{TARGET_PAGE + row}:0"
        source_inverse = f"{SOURCE_PAGE + row}:32"
        target_inverse = f"{TARGET_PAGE + row}:32"
        for key in (source, source_inverse):
            if key not in otp:
                raise SystemExit(f"Missing required key share row {key}")
        # Rebuilds can generate fresh boot key shares, so refresh the reserved
        # application rows from the shares emitted during this build.
        otp[target] = copy.deepcopy(otp[source])
        otp[target_inverse] = copy.deepcopy(otp[source_inverse])

    for page in (TARGET_PAGE, TARGET_PAGE + 1):
        lock = f"PAGE{page}_LOCK1"
        existing = otp.get(lock)
        if existing not in (None, "0x3d3d3d"):
            raise SystemExit(f"Refusing unexpected OTP access policy {lock}={existing}")
        otp[lock] = "0x3d3d3d"  # Secure read only with no Bootrom or Non-secure access.

    # The SDK's signing step already sets secure_boot_enable and key_valid.
    # Close the debug paths and enable the on-chip glitch detector for the
    # physical-access research profile. Keep only the generated signing key valid.
    crit1 = otp.setdefault("crit1", {})
    crit1["debug_disable"] = 1
    crit1["secure_debug_disable"] = 1
    crit1["glitch_detector_enable"] = 1
    crit1["glitch_detector_sens"] = 3
    crit1["secure_boot_enable"] = 1
    boot_flags1 = otp.setdefault("boot_flags1", {})
    boot_flags1["key_invalid"] = 0xFE

    path.write_text(json.dumps(otp, indent=4) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

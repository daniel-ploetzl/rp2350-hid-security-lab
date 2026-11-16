import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFY_SCRIPT = ROOT / "tools" / "verify_firmware_uf2.py"
OTP_SCRIPT = ROOT / "tools" / "extend_otp_for_credentials.py"
DEV_KEY_SCRIPT = ROOT / "tools" / "embed_dev_aes_key.py"
VERIFY_DEV_KEY_SCRIPT = ROOT / "tools" / "verify_dev_aes_key.py"
MAGIC0 = 0x0A324655
MAGIC1 = 0x9E5D5157
MAGIC_END = 0x0AB16F30
FLAG_FAMILY = 0x2000
FLAG_EXTENSION = 0x8000
FLASH_BASE = 0x10000000
PAIRING_SECTOR = 0x103FC000
RP2350_ARM_S = 0xE48BFF59
ABSOLUTE_FAMILY = 0xE48BFF57
ABSOLUTE_ADDR = 0x10FFFF00


def make_block(flags, target, payload, block_num, total, family, fill):
    block = bytearray(512)
    struct.pack_into("<8I", block, 0, MAGIC0, MAGIC1, flags, target,
                     payload, block_num, total, family)
    block[32:32 + payload] = bytes([fill]) * payload
    struct.pack_into("<I", block, 508, MAGIC_END)
    return block


def make_e10_block():
    return make_block(FLAG_FAMILY | FLAG_EXTENSION, ABSOLUTE_ADDR, 256,
                      0, 2, ABSOLUTE_FAMILY, 0xEF)


def make_firmware_block(target, family=RP2350_ARM_S):
    return make_block(FLAG_FAMILY, target, 256, 0, 1, family, 0xA5)


class BuildHelperTests(unittest.TestCase):
    def test_uf2_guard_accepts_e10_marker_and_firmware(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firmware.uf2"
            path.write_bytes(make_e10_block() + make_firmware_block(FLASH_BASE))
            result = subprocess.run([sys.executable, str(VERIFY_SCRIPT), str(path)])
        self.assertEqual(result.returncode, 0)

    def test_uf2_guard_rejects_reserved_sector_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firmware.uf2"
            path.write_bytes(make_e10_block() + make_firmware_block(PAIRING_SECTOR))
            result = subprocess.run([sys.executable, str(VERIFY_SCRIPT), str(path)],
                                    capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("overlaps", result.stderr)

    def test_otp_helper_refreshes_reserved_key_share_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "otp.json"
            otp = {}
            for page in (29, 30):
                otp[f"{page}:0"] = f"share-{page}-a"
                otp[f"{page}:32"] = f"share-{page}-b"
            path.write_text(json.dumps(otp))
            subprocess.run([sys.executable, str(OTP_SCRIPT), str(path)], check=True)
            first = json.loads(path.read_text())
            for page in (29, 30):
                otp[f"{page}:0"] = f"fresh-{page}-a"
                otp[f"{page}:32"] = f"fresh-{page}-b"
            path.write_text(json.dumps(otp))
            subprocess.run([sys.executable, str(OTP_SCRIPT), str(path)], check=True)
            second = json.loads(path.read_text())
        self.assertEqual(second["24:0"], "fresh-29-a")
        self.assertEqual(second["24:32"], "fresh-29-b")
        self.assertEqual(second["25:0"], "fresh-30-a")
        self.assertEqual(second["25:32"], "fresh-30-b")
        self.assertEqual(second["PAGE24_LOCK1"], "0x3d3d3d")
        self.assertEqual(second["PAGE25_LOCK1"], "0x3d3d3d")

    def test_development_key_header_requires_32_bytes_and_is_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "test-aes.bin"
            header_path = Path(directory) / "hid_lab_dev_aes_key.h"
            key_path.write_bytes(bytes(range(32)))
            subprocess.run([sys.executable, str(DEV_KEY_SCRIPT), str(key_path),
                            str(header_path)], check=True)
            self.assertEqual(header_path.stat().st_mode & 0o777, 0o600)
            self.assertIn("0x00u, 0x01u", header_path.read_text())
            result = subprocess.run(
                [sys.executable, str(VERIFY_DEV_KEY_SCRIPT), str(key_path),
                 str(header_path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn("matches", result.stdout)
            key_path.write_bytes(bytes(reversed(range(32))))
            result = subprocess.run(
                [sys.executable, str(VERIFY_DEV_KEY_SCRIPT), str(key_path),
                 str(header_path)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match", result.stderr)
            key_path.write_bytes(bytes(31))
            result = subprocess.run([sys.executable, str(DEV_KEY_SCRIPT), str(key_path),
                                     str(header_path)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly 32 bytes", result.stderr)


if __name__ == "__main__":
    unittest.main()

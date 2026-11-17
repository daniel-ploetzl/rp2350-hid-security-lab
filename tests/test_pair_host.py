import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import pair_host


class HostPairingTests(unittest.TestCase):
    def test_rootless_poll_is_quiet_when_volume_is_absent(self):
        with patch("pair_host.candidate_mounts", return_value=[]):
            self.assertEqual(pair_host.find_challenge_mount(None), (None, None))

    def test_signature_binds_board_and_fresh_nonce(self):
        with tempfile.TemporaryDirectory() as directory:
            private_key = Path(directory) / "host-private.pem"
            public_key = Path(directory) / "host-public.pem"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                 "ec_paramgen_curve:prime256v1", "-out", str(private_key)],
                check=True,
                capture_output=True,
            )
            os.chmod(private_key, 0o600)
            subprocess.run(
                ["openssl", "pkey", "-in", str(private_key), "-pubout",
                 "-out", str(public_key)],
                check=True,
                capture_output=True,
            )
            challenge = bytearray(pair_host.CHALLENGE_BYTES)
            challenge[0] = pair_host.PROTOCOL_VERSION
            challenge[1] = pair_host.STATUS_PENDING
            challenge[2:10] = b"board-id"
            challenge[10:42] = bytes(range(32))
            raw_signature = pair_host.sign_challenge(str(private_key), challenge)
            signature = pair_host.raw_signature_to_der(raw_signature)
            message = pair_host.PAIRING_DOMAIN + b"board-id" + bytes(range(32))
            signature_path = Path(directory) / "signature.der"
            signature_path.write_bytes(signature)
            verified = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(public_key),
                 "-signature", str(signature_path)],
                input=message,
                capture_output=True,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr.decode())
            replay = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(public_key),
                 "-signature", str(signature_path)],
                input=pair_host.PAIRING_DOMAIN + b"other-id" + bytes(range(32)),
                capture_output=True,
            )
            self.assertNotEqual(replay.returncode, 0)
            self.assertEqual(len(raw_signature), pair_host.SIGNATURE_BYTES)

    def test_mount_exchange_reads_challenge_and_writes_response(self):
        with tempfile.TemporaryDirectory() as directory:
            mount = Path(directory)
            challenge = bytes((pair_host.PROTOCOL_VERSION, pair_host.STATUS_PENDING)) + b"b" * 8 + b"n" * 32
            (mount / pair_host.CHALLENGE_NAME).write_bytes(challenge)
            (mount / pair_host.RESPONSE_NAME).write_bytes(bytes(pair_host.SIGNATURE_BYTES))
            with patch("pair_host.candidate_mounts", return_value=[directory]):
                found_mount, found_challenge = pair_host.find_challenge_mount(None)
            self.assertEqual(found_mount, directory)
            self.assertEqual(found_challenge, challenge)
            response = bytes(range(pair_host.SIGNATURE_BYTES))
            pair_host.write_response(directory, response)
            self.assertEqual((mount / pair_host.RESPONSE_NAME).read_bytes(), response)


if __name__ == "__main__":
    unittest.main()

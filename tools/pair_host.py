#!/usr/bin/env python3
"""Answer a board pairing challenge through its mounted USB volume."""

import argparse
import os
import re
import stat
import subprocess
import sys


OPENSSL_PATH = "/usr/bin/openssl"
CHALLENGE_NAME = "CHALLENG.BIN"
RESPONSE_NAME = "RESPONSE.BIN"
CHALLENGE_BYTES = 42
SIGNATURE_BYTES = 64
PROTOCOL_VERSION = 1
STATUS_PENDING = 1
MAX_SIGNATURE_BYTES = 72
MAX_MOUNT_LINES = 256
PAIRING_DOMAIN = b"HID-LAB-PAIR-v1\0"


def sign_message(key_path, message):
    key_info = os.stat(key_path, follow_symlinks=False)
    if not stat.S_ISREG(key_info.st_mode) or key_info.st_mode & 0o077:
        raise ValueError("host signing key must be a regular owner only file")
    result = subprocess.run(
        [OPENSSL_PATH, "dgst", "-sha256", "-sign", key_path],
        input=message,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
    )
    if result.returncode != 0 or not 8 <= len(result.stdout) <= MAX_SIGNATURE_BYTES:
        raise RuntimeError("OpenSSL could not sign the pairing challenge")
    return result.stdout


def der_signature_to_raw(signature):
    if len(signature) < 8 or signature[0] != 0x30 or signature[1] + 2 != len(signature):
        raise RuntimeError("OpenSSL returned an invalid DER signature")
    if signature[2] != 0x02:
        raise RuntimeError("OpenSSL returned an invalid DER integer")
    r_length = signature[3]
    r_start = 4
    s_marker = r_start + r_length
    if s_marker + 2 > len(signature) or signature[s_marker] != 0x02:
        raise RuntimeError("OpenSSL returned an invalid DER integer")
    s_length = signature[s_marker + 1]
    s_start = s_marker + 2
    if s_start + s_length != len(signature):
        raise RuntimeError("OpenSSL returned an invalid DER signature")
    r = signature[r_start:s_marker]
    s = signature[s_start:]
    while len(r) > 32 and r[0] == 0:
        r = r[1:]
    while len(s) > 32 and s[0] == 0:
        s = s[1:]
    if not 1 <= len(r) <= 32 or not 1 <= len(s) <= 32:
        raise RuntimeError("OpenSSL returned an out of range signature integer")
    return bytes(32 - len(r)) + r + bytes(32 - len(s)) + s


def raw_signature_to_der(signature):
    if len(signature) != SIGNATURE_BYTES:
        raise ValueError("raw signature must contain 64 bytes")
    integers = []
    for start in (0, 32):
        value = signature[start:start + 32].lstrip(b"\0") or b"\0"
        if value[0] & 0x80:
            value = b"\0" + value
        integers.append(b"\x02" + bytes((len(value),)) + value)
    content = b"".join(integers)
    return b"\x30" + bytes((len(content),)) + content


def unescape_mount_path(path):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), path)


def candidate_mounts(requested_mount):
    if requested_mount:
        return [requested_mount]
    mounts = []
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as mount_file:
            for index, line in enumerate(mount_file):
                if index >= MAX_MOUNT_LINES:
                    break
                fields = line.split()
                if len(fields) >= 3 and fields[2] in ("vfat", "msdos", "fat"):
                    mounts.append(unescape_mount_path(fields[1]))
    except OSError:
        return []
    return mounts


def read_challenge(mount_path):
    challenge_path = os.path.join(mount_path, CHALLENGE_NAME)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(challenge_path, flags)
    try:
        file_info = os.fstat(fd)
        if not stat.S_ISREG(file_info.st_mode) or file_info.st_size != CHALLENGE_BYTES:
            return None
        challenge = os.read(fd, CHALLENGE_BYTES)
    finally:
        os.close(fd)
    if len(challenge) != CHALLENGE_BYTES or challenge[0] != PROTOCOL_VERSION:
        return None
    return challenge


def find_challenge_mount(requested_mount):
    for mount_path in candidate_mounts(requested_mount):
        try:
            challenge = read_challenge(mount_path)
        except OSError:
            continue
        if challenge is not None:
            return mount_path, challenge
    return None, None


def sign_challenge(key_path, challenge):
    if len(challenge) != CHALLENGE_BYTES or challenge[0] != PROTOCOL_VERSION:
        raise ValueError("unexpected pairing challenge format")
    if challenge[1] != STATUS_PENDING:
        return None
    message = PAIRING_DOMAIN + challenge[2:10] + challenge[10:42]
    return der_signature_to_raw(sign_message(key_path, message))


def write_response(mount_path, signature):
    if len(signature) != SIGNATURE_BYTES:
        raise ValueError("pairing response must contain 64 bytes")
    response_path = os.path.join(mount_path, RESPONSE_NAME)
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(response_path, flags)
    try:
        file_info = os.fstat(fd)
        if not stat.S_ISREG(file_info.st_mode) or file_info.st_size != SIGNATURE_BYTES:
            raise ValueError("pairing response file has an unexpected size")
        written = os.pwrite(fd, signature, 0)
        if written != SIGNATURE_BYTES:
            raise OSError("pairing response write was incomplete")
        os.fsync(fd)
    finally:
        os.close(fd)


def authorise_mount(mount_path, challenge, key_path):
    signature = sign_challenge(key_path, challenge)
    if signature is None:
        return False
    write_response(mount_path, signature)
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True)
    parser.add_argument("--mount")
    args = parser.parse_args()
    mount_path, challenge = find_challenge_mount(args.mount)
    if mount_path is None:
        return
    if authorise_mount(mount_path, challenge, args.key):
        print("Submitted pairing proof through the mounted USB volume")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"Pairing failed: {error}", file=sys.stderr)
        raise SystemExit(1)

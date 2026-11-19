# RP2350 HID Security Lab

An RP2350 firmware research project for analysing USB HID behaviour, host authorisation and secure embedded design on the Raspberry Pi Pico 2 and Pico 2 W.

This portfolio project demonstrates RP2350 firmware engineering through USB HID report modelling, a cryptographic host authorisation protocol and protected configuration storage. Its purpose is to explore how embedded security features interact with device behaviour and host software.

## What it demonstrates

- Cooperative, non-blocking firmware with independent keyboard and mouse state machines
- Composite USB HID with keyboard, mouse and a RAM-backed pairing volume
- Fresh challenge and signature based host authorisation before HID reports are released
- AES-GCM encrypted configuration records and RP2350 secure boot and OTP integration
- C firmware, configuration writer, host utilities and firmware pairing tests

## Security boundary

Host authorisation gates simulated HID reports on proof of possession of an enrolled key. It does not conceal reports from the authorised host or a USB capture device. Decrypted input data and cryptographic key material exist in device memory at runtime. Development builds use recoverable test keys and must never contain real secrets or be provisioned as production devices.

## Build and test

The firmware requires the Raspberry Pi Pico SDK with RP2350 support, CMake and the ARM GCC toolchain. Secure builds also require protected signing, AES and IV key files. Host tools require a C compiler and OpenSSL. Project code and tests are written in C and Bash. The Pico SDK uses Python internally for its build support. See [EXPLAINED.md](EXPLAINED.md) for key handling, development pairing, provisioning limits and host setup.

```sh
cmake -S . -B build \
  -DHID_LAB_SIGNING_KEY=/secure/path/signing.pem \
  -DHID_LAB_AES_KEY=/secure/path/device-aes.bin \
  -DHID_LAB_IV_SALT=/secure/path/device-iv.bin
cmake --build build -j2
bash tests/run_tests.sh
```

The host suite compiles the firmware pairing module against the Pico SDK's Mbed TLS sources and stubs USB, OTP storage and board identity. It exercises rejection and acceptance paths without hardware or OTP programming. CI firmware artifacts use disposable keys and are for build verification only.

## Repository map

- `src/` firmware and the C configuration writer
- `inc/` firmware interfaces and configuration definitions
- `tools/` C build helpers and the Linux pairing agent
- `systemd/user/` optional rootless host pairing timer
- `tests/` host-side tests

## Scope

This is a security design and research prototype. Its threat model, limitations, setup instructions and implementation notes are documented in [EXPLAINED.md](EXPLAINED.md).

# RP2350 HID Security Lab

Embedded security research firmware for the Raspberry Pi Pico 2 and Pico 2 W. The firmware controls USB keyboard and mouse output by requiring proof that the host holds an enrolled private key. Authorisation lasts for one USB connection.

## Engineering

The board exposes a composite USB device with keyboard, mouse and mass storage interfaces. A FAT volume held in RAM carries the pairing challenge and response. A Linux process exchanges these records through ordinary file operations under the user's account. The agent records the board’s verdict in the local user journal. Pairing requires only USB and access to the mounted volume.

A cooperative firmware loop services TinyUSB, advances the pairing state machine and schedules input. Both the stored input sequence and simulated activity depend on the same authorisation decision. Disconnecting clears the session before the board issues another challenge. [Firmware main loop](src/main.c)

## Security

**Host authorisation.** The host signs a protocol identifier, the board identifier and a fresh 32 byte nonce using ECDSA on P-256 with SHA-256. The firmware verifies the signature against the enrolled public key. Binding the signature to both the board and its current nonce prevents a recorded response from authorising a later session. [Pairing verifier](src/pairing.c)

**Firmware and configuration integrity.** The secure build signs and encrypts the firmware image for a board provisioned with matching OTP keys. Configuration records use AES-GCM. At startup the firmware imports key shares from OTP and locks the source pages against further reads. Development images embed a recoverable test key. [Protected storage](src/secure_store.c)

**Trust boundary.** A copied host private key grants the same authority as the original. Once the firmware releases keyboard reports, the receiving host or a USB capture device can observe the keystrokes.

## Verification

The host harness compiles the firmware verifier with the Pico SDK's Mbed TLS sources. It substitutes deterministic board identity, randomness and USB connection state to exercise valid signatures, incorrect keys, altered challenges and replay after reconnect. CI also builds the secure image for both boards and checks that UF2 payloads stay below the reserved configuration sectors.

Set `PICO_SDK_PATH` to a Pico SDK checkout with its submodules. With Bash, a host C compiler and OpenSSL development files installed, run the suite from the repository root.

```bash
bash tests/run_tests.sh
```

For key backup, build profiles and hardware verification, see the [design and hardware guide](EXPLAINED.md).

# hid-lab: USB HID Behaviour Simulation Lab (Raspberry Pi Pico 2 / Pico 2 W)

## Overview

This project implements a composite USB Human Interface Device (HID) behaviour simulator on Raspberry Pi Pico 2 and Pico 2 W. Wi-Fi is available on the Pico 2 W only.
It generates time-driven, non-deterministic keyboard and mouse activity for research and educational analysis of:

- USB HID behaviour modelling
- host-side classification and heuristic detection
- embedded scheduling under non-blocking timing constraints

Current development focuses on RP2350 security design and research: authenticated encrypted settings, signed and encrypted SRAM boot, per-device OTP key handling and cryptographic host pairing.

---

## Engineering properties

- **Cooperative non-blocking scheduling:** one main loop with no RTOS, threads or sleeping, so USB and Wi-Fi are serviced on every pass
- **Single-writer mouse report:** only `mouse_flush()` transmits, so movement or scrolling cannot clear a held button
- **Checked HID sends:** a state machine advances only once its report is queued, so a busy endpoint cannot lose a release
- **Build-time flash layout checks:** the secure UF2 is checked against all reserved flash sectors and record sizes are asserted
- **Authenticated encrypted settings:** Wi-Fi and stored input sequence records use AES-256-GCM. Invalid tags mean no join or no input sequence
- **RP2350 secure boot:** the firmware UF2 is signed and encrypted, then decrypted into SRAM at boot. Per-device AES key shares are protected by OTP access controls
- **Host pairing gate:** the board releases no keyboard or mouse reports until an enrolled host proves possession of its P-256 signing key for a fresh board challenge over the mounted USB volume

---

## Architecture

### Firmware (device-side)

- `src/main.c`
  Cooperative scheduler:
  - runs TinyUSB device task (`tud_task()`)
  - drives the active then idle re-activation cycle
  - dispatches behaviour subsystems

- `src/input_tasks.c`
  Behaviour engine implementing independent state machines for HID actions.

- `src/reactivation.c`
  Re-activation timer: the active then idle duty cycle that repeats for ever.

- `src/login.c`
  Input sequence typist: starts at boot and each later re-activation, typing the stored input sequence, waiting 15 seconds, then typing its final command before HID activity starts.

- `src/wifi_manager.c` (Pico 2 W only)
  Non-blocking station state machine: connect, monitor link, reconnect with backoff.

- `src/usb_descriptors.c`
  USB descriptor definitions for the composite device:
  - pairing mass storage interface
  - keyboard interface
  - mouse interface

- `src/pairing.c`
  Holds HID output until the enrolled host signs the fresh per-connection challenge.

- `src/pairing_storage.c`
  Provides a small FAT12 volume containing fixed challenge and response files.

### Shared configuration

- `inc/flash_config.h`
  Flash layout definitions and configuration read/validation logic.

- `src/secure_store.c`
  Imports and software-locks the Secure-only OTP key shares, then authenticates and decrypts reserved-sector records.

- `inc/hid_keymap.h`
  ASCII to HID key-code map for the German QWERTZ layout, shared by the firmware and `write_config`.

### Host utility

- `src/write_config.c`
  Host-side tool that generates a UF2 payload to write the run time, encrypted Wi-Fi, stored input sequence or encrypted host pairing record into reserved flash sectors.

- `tools/pair_host.py`
  Rootless Linux agent that reads and answers the challenge through the auto mounted USB volume.

---

## Execution Model

The firmware is based on a **cooperative, non-preemptive scheduling loop**:

- `tud_task()` must be called continuously for USB stack progress
- `wifi_manager_task()` services the radio through `cyw43_arch_poll()` from the same loop, with no background thread or interrupt
- `reactivation_update()` advances the active then idle cycle and signals the start of each active window
- `input_tasks_run(active)` executes all HID behaviour logic
- timing is derived from a monotonic millisecond clock:
  `to_ms_since_boot(get_absolute_time())`

### Re-activation cycle

Activity repeats on a fixed cycle rather than running once. The device is active for the configured window, idle for the period, then active again with no end.

- the active window length is the stored `hours` value
- the idle period is read from the flash config in seconds. It ranges from 1 second to 1 week and defaults to 1 week
- the first window opens at boot
- each window begins with a one-shot edge that runs the login and post-login command sequence before activity starts
- the timer keeps each phase well under the 49.7-day clock wrap, so the rollover does not disturb the cadence

### Constraint model

- No blocking delays (`sleep`, busy-wait loops) in behaviour logic
- Elapsed-time checks use wrap-safe modular subtraction on timestamps. Each re-activation phase is bounded well under the 49.7-day clock wrap, so the cycle keeps its cadence across a rollover
- USB stack responsiveness is preserved at all times

---

## Behaviour Model

Input generation is implemented as independent time-based state machines:

- mouse movement bursts
- mouse click events
- keyboard key presses
- typing bursts
- scroll events
- window switching sequences (ALT+TAB)

### Timing model

- intervals are bounded random values (uniform distribution unless otherwise stated)
- randomness is sourced from `pico_rand`, a PRNG seeded from several entropy sources on the RP2350, the hardware TRNG among them
- each subsystem operates independently (no global synchronisation)

### Report model

A HID report carries the full current state of the device, so overlapping subsystems must not each transmit their own report.

- the mouse uses a single-writer flush. `click_task` owns the button level whilst `move_task` and `scroll_task` write transient deltas. Only `mouse_flush()` transmits, so movement or scrolling cannot clear a held button
- the keyboard subsystems transmit directly, one activity at a time in practice given the interval spacing
- every send checks its return value and advances its state machine only once the report is queued, so a busy endpoint never drops one half of a press or release pair

---

## USB HID Model

The device is implemented as a composite USB device with a pairing storage interface and a HID interface:

- The storage interface exposes a small RAM-backed FAT12 volume for the challenge and response files
- Report ID 1: keyboard
- Report ID 2: mouse

### Descriptor constraints

- Control endpoint size: 64 bytes (`CFG_TUD_ENDPOINT0_SIZE`)
- HID interrupt buffer size: 16 bytes (`CFG_TUD_HID_EP_BUFSIZE`)
- Polling interval: 5 ms (HID `bInterval`)

---

## Flash Layout and Safety

Pico 2 and Pico 2 W flash map (4 MB):

- Firmware region: `0x10000000 .. 0x103FCFFF` (`0x003FD000` bytes)
- Reserved encrypted login sector: `0x103FD000 .. 0x103FDFFF`
- Reserved encrypted Wi-Fi sector: `0x103FE000 .. 0x103FEFFF`
- Reserved config sector: `0x103FF000 .. 0x103FFFFF` (last 4 KB sector)

### Safety invariant

The encrypted firmware image must end before the reserved sectors. Secure builds link the executable for SRAM and package its encrypted image at the start of flash. They check the generated UF2 block addresses before accepting the build.

Enforced at build time:

- the SRAM linker limit bounds executable size. A post-build UF2 inspection rejects any firmware block at or above `LOGIN_CREDS_FLASH_ADDR`
- `_Static_assert`s in `inc/flash_config.h` fail both the firmware and host builds if record layouts change
- `PICO_BOARD` defaults to `pico2_w` and CMake configuration fails for any non-RP2350 platform

The checks exist because the layout is defined in two places, `CMakeLists.txt` and `inc/flash_config.h`. Without them, either side could change and the build would still succeed.

Limits of this protection:

- secure firmware executes from SRAM. The generated encrypted UF2 is separately checked against the flash reservation
- writing only to the reserved sectors is a convention, not a restriction. `write_config` is the only writer in this repository, but nothing stops another UF2 or a flash API call from changing them

---

## Wi-Fi

Built when the board has a CYW43 radio. On a Pico 2 the same API compiles to inline stubs.

- `wifi_manager_task()` runs from the main loop and never blocks, so a network failure cannot delay USB or HID behaviour
- a failed join or missing DHCP lease within 30 s retries after 2 s. The delay doubles to 60 s. A wrong password retries at 60 s
- DHCP and DNS are provided by lwIP, which is configured for UDP only in `inc/lwipopts.h`
- the status LED is on the radio chip, so it needs the radio to start. Solid means online or no network configured, blinking means not online yet (including joined with no DHCP lease) and off means the run has finished

### Wi-Fi settings

Wi-Fi settings are not built into the firmware. Connect the board in BOOTSEL mode and store them in its dedicated flash sector:

```bash
./write_config --wifi wpa2 "your-network" /secure/path/device-aes.bin
```

The tool reads the Wi-Fi password from hidden standard input. It reads the per-device AES key from the named owner-only 32-byte file. Only that file's path appears in argv. Use `wpa3` for WPA3-Personal. There is no automatic fallback between the two.

The sector survives firmware updates, so this is needed once per board. Without a valid record the firmware makes no connection attempt. To remove the Wi-Fi settings from a board:

```bash
./write_config --wifi-clear
```

The Wi-Fi and input sequence records are AES-256-GCM ciphertext in flash. The key is not stored in plaintext there. Four-way key shares are Secure-readable in OTP and the firmware imports them into SRAM after encrypted, signed boot. OTP provisioning disables debug and enables the glitch detector. This protects records against offline flash reads and unauthorised firmware. It is not an absolute physical attack guarantee. The firmware must decrypt the sequence in SRAM and send it as ordinary USB HID keystrokes. A bus capture can observe those keystrokes. Runtime data encryption uses the SDK's Mbed TLS AES-GCM implementation. The SDK warns that software AES may expose power or timing side channels.

---

## Configuration System

Flash layout (12 bytes total):

```c
typedef struct {
    uint32_t magic;
    uint32_t hours;
    uint32_t period_s;
} pico_config_t;
```

### Validation rules:

- `magic == 0xCAFEF00E`
- `hours` in `[1, 24]`, the length of each active window in the re-activation cycle
- `period_s` in `[1, 604800]`, the idle gap in seconds, up to 1 week

Each field falls back to its default if the record is invalid.

### Fallback behaviour:

If validation fails (erased flash, corruption or invalid values):

  - firmware uses `CONFIG_DEFAULT_HOURS`
  - system behaviour remains deterministic

### Design note

  The magic value is a **struct validity marker**, not a security mechanism.
  No cryptographic integrity protection is (yet) implemented.

---

## Host Configuration Writer

### Build

```bash
gcc src/write_config.c -Iinc -lcrypto -o write_config
```

### Usage

```bash
./write_config <hours> [period]
./write_config --wifi <wpa2|wpa3> <ssid> <aes-key-file>
./write_config --wifi-clear
./write_config --login <aes-key-file>
./write_config --login-clear
```

### Output

Generates a UF2 payload that writes one record into its reserved flash sector. The config write sets the run window and re-activation period together because they share a sector. Wi-Fi settings and the stored input sequence live in separate sectors. Change each record on its own. `period` accepts seconds or an integer with an `s`, `m`, `h`, `d` or `w` suffix. For example, `7d` means 1 week and is the default.

### Encrypted records

Wi-Fi and stored input sequence payloads are sealed into fixed 256-byte AES-256-GCM records. The nonce, record header and target flash address are authenticated. A modified or relocated record fails closed. The writer reads a per-device AES key from a regular owner-only file. It encrypts the record on the host and writes ciphertext only. The encrypted firmware imports four-way key shares from Secure-only OTP, reconstructs the key in SRAM and software-locks those OTP pages.

`--login` reads the stored input sequence as three hidden stdin lines. Enter the first two sequence values followed by the final command. The AES key is read from an owner-only 32-byte file. No sequence value appears in argv, shell history or terminal echo. All three lines are encrypted together. The CRC inside the encrypted payload is only an additional format check.

---

## Stored input sequence

Before typing the stored input sequence, the device waits for the HID endpoint to remain ready for 2 seconds. This gives the host input layer time to initialise. USB servicing continues during this wait. The separate 15 second wait follows the sequence's first two lines.

At boot, the device waits for the paired host agent to answer a fresh challenge. Only after successful verification does it authenticate and decrypt the input sequence record into short-lived SRAM, type the first two lines, wait 15 seconds for the host session, then type the final command. The sequence runs again at each later re-activation. Run `./write_config --login /secure/path/device-aes.bin` and enter the three lines at its hidden prompts.

The application exposes a small RAM-backed FAT12 volume named `HIDPAIR`. `CHALLENG.BIN` contains the protocol version, status, board identifier and a 32-byte nonce. The host agent signs the domain-separated message `HID-LAB-PAIR-v1`, the board identifier and nonce, then writes the 64-byte P-256 signature to `RESPONSE.BIN`. The device verifies the signature using the encrypted public key record. A new TRNG-seeded nonce is made for each USB connection, so a captured response cannot authorise a later connection. An unpaired or unauthorised host receives no simulated keyboard or mouse reports.

Pairing does not hide keystrokes from the authorised host. Its host agent can access the enrolled signing key and the host receives ordinary USB keyboard reports. The host key is a software PEM file with user only permissions. A TPM-backed signer would reduce private key extraction from the host and is a future extension.

- the stored input sequence lives in its own flash sector, written once per board with `--login`, so a run-time or Wi-Fi change never erases it. Without a valid record the device types nothing and goes straight to activity
- the typist is non-blocking: it sends one key report per loop pass and advances only when the report is accepted, so it never stalls USB
- every key down is followed by its release, so the host sees each character once and nothing auto-repeats
- the final command is stored as the third line of the input sequence and typed only after the 15-second host-session wait, followed by Return
- the host layout is German QWERTZ. The device sends positional key codes. It sends `z` as the physical key US keyboards label `Y`. Symbols such as `@` and `{ [ ] }` use AltGr. Characters reached only through a dead key (`^` and accents) cannot be typed. Non-ASCII characters such as umlauts, `ß` and `€` are also rejected when the sequence is stored
- sequence values are read from hidden standard input. Host plaintext buffers are cleared after the ciphertext UF2 is written
- the ciphertext records are protected against offline flash reading and tampering. The decrypted sequence and AES key exist briefly or persistently in SRAM while needed for typing and Wi-Fi reconnects

---

## Build System

### Requirements

- Raspberry Pi Pico SDK (2.2.0 or newer, with RP2350 encryption support)
- CMake >= 3.13
- ARM GCC toolchain
- OpenSSL development headers and library for the host writer
- OpenSSL CLI and systemd user services on Linux for the host pairing agent

### Build

```bash
bash -e <<'BASH'
umask 077
install -d -m 0700 /secure/path/hid-lab-keys
test ! -e /secure/path/hid-lab-keys/signing.pem
test ! -e /secure/path/hid-lab-keys/device-aes.bin
test ! -e /secure/path/hid-lab-keys/device-iv.bin
openssl ecparam -name secp256k1 -genkey -out /secure/path/hid-lab-keys/signing.pem
openssl rand -out /secure/path/hid-lab-keys/device-aes.bin 32
openssl rand -out /secure/path/hid-lab-keys/device-iv.bin 16
BASH
```

Generate these keys once and keep the same files for every firmware rebuild and device record update. The `test` commands make the example stop instead of silently replacing an existing key. Before programming OTP, make an encrypted backup of all three keys on offline storage. For example, replace `ENCRYPTED_BACKUP` with the mounted name of an encrypted removable drive:

```bash
bash -e -o pipefail <<'BASH'
tar -C /secure/path/hid-lab-keys -cf - signing.pem device-aes.bin device-iv.bin |
  openssl enc -aes-256-cbc -salt -pbkdf2 \
    -out /media/$USER/ENCRYPTED_BACKUP/hid-lab-keys.tar.enc
BASH
```

OpenSSL prompts for a backup passphrase. Verify that the encrypted archive can be read before provisioning. Losing these keys can make the provisioned board unable to boot or decrypt its records. Do not run the key generation commands again for an ordinary firmware update.

```bash
cmake -S . -B build \
  -DHID_LAB_SIGNING_KEY=/secure/path/hid-lab-keys/signing.pem \
  -DHID_LAB_AES_KEY=/secure/path/hid-lab-keys/device-aes.bin \
  -DHID_LAB_IV_SALT=/secure/path/hid-lab-keys/device-iv.bin
cmake --build build -j"$(nproc)"
```

The build emits `build/hid_lab.otp.json` with secure-boot settings, debug disabled, the glitch detector enabled at the highest OTP sensitivity, image-decryption key material and a Secure-only copy of the per-device key shares. Programming OTP with `picotool otp load` is irreversible. Review the generated file and keep the signing and AES keys backed up before provisioning a board. The build does not program OTP.

An unprovisioned board cannot boot this secure image. It needs the matching OTP keys for secure boot and record decryption. Verification builds made with disposable keys are not deployable. Do not provision their OTP files.

### Development USB Pairing Test

The development profile uses the SDK RP2350 Secure platform but skips image signing and encryption. On a blank board with secure boot unset, the ROM accepts the ordinary UF2 image without OTP provisioning. The profile does not create or program OTP data. It embeds a disposable AES key in the image so encrypted record handling and P-256 host pairing can be tested. CMake verifies that the generated key header matches the selected key file and stops configuration if they differ. Anyone with the UF2 can recover this test key. Do not store real input sequences or secrets on a development board.

```bash
bash -e <<'BASH'
umask 077
install -d -m 0700 "$HOME/.config/hid-lab"
test ! -e "$HOME/.config/hid-lab/dev-aes.bin"
test ! -e "$HOME/.config/hid-lab/host-private.pem"
openssl rand -out "$HOME/.config/hid-lab/dev-aes.bin" 32
openssl ecparam -name prime256v1 -genkey -noout \
  -out "$HOME/.config/hid-lab/host-private.pem"
openssl pkey -in "$HOME/.config/hid-lab/host-private.pem" -pubout \
  -out "$HOME/.config/hid-lab/host-public.pem"
BASH
```

The AES key and host private key are created directly in persistent owner only storage. Keep the same files across rebuilds and reconnects. Do not put either key in `/tmp`. Before enrolling the host public key, make an encrypted backup of both keys on offline storage. A VeraCrypt container stored on a separate USB drive is suitable. Unlock and mount it, then replace `ENCRYPTED_BACKUP` with its mounted name, for example `VERACRYPT`. The OpenSSL command below encrypts the archive separately as well. `/media/dp/HIDPAIR` is the board volume and is not a backup destination.

```bash
bash -e -o pipefail <<'BASH'
tar -C "$HOME/.config/hid-lab" -cf - dev-aes.bin host-private.pem |
  openssl enc -aes-256-cbc -salt -pbkdf2 \
    -out /media/$USER/ENCRYPTED_BACKUP/hid-lab-development-keys.tar.enc
BASH
```

OpenSSL prompts for a backup passphrase. Verify the encrypted archive and confirm that the backed up private key matches the public key before enrolment:

```bash
bash -e -o pipefail <<'BASH'
openssl enc -d -aes-256-cbc -pbkdf2 \
  -in /media/$USER/ENCRYPTED_BACKUP/hid-lab-development-keys.tar.enc |
  tar -xOf - host-private.pem |
  openssl pkey -pubout -out "$HOME/.config/hid-lab/host-backup-public.pem"
cmp "$HOME/.config/hid-lab/host-public.pem" \
  "$HOME/.config/hid-lab/host-backup-public.pem"
printf 'Backup verified: host private key matches the public key.\n'
BASH
```

Expected result is `Backup verified: host private key matches the public key.` and exit status `0`. `cmp` prints nothing when the files match. Do not proceed with enrolment unless `cmp` succeeds. The `test` commands above prevent accidental replacement of existing test keys. If either key already exists, keep it and skip key generation. Build using the persistent development AES key:

```bash
cmake -S . -B /tmp/hid-lab-dev-build \
  -DPICO_BOARD=pico2_w \
  -DHID_LAB_DEVELOPMENT_BUILD=ON \
  -DHID_LAB_DEV_AES_KEY="$HOME/.config/hid-lab/dev-aes.bin"
cmake --build /tmp/hid-lab-dev-build -j2
gcc -D_GNU_SOURCE -std=c11 -Wall -Wextra -Werror \
  src/write_config.c -Iinc -lcrypto -o write_config
```

Put the test board in BOOTSEL mode and copy `/tmp/hid-lab-dev-build/hid_lab.uf2` to `/media/$USER/RP2350/`. After it reboots into the application, enter BOOTSEL mode again and run `./write_config --pair-host "$HOME/.config/hid-lab/host-public.pem" "$HOME/.config/hid-lab/dev-aes.bin"`. This writes the encrypted pairing record to the BOOTSEL drive and the board reboots to the application.

Wait for the host to mount the `HIDPAIR` volume. Find the mount path with `lsblk -o LABEL,FSTYPE,MOUNTPOINTS | rg HIDPAIR`, then submit the proof:

```bash
unshare --user --map-root-user python3 tools/pair_host.py \
  --key "$HOME/.config/hid-lab/host-private.pem" \
  --mount /path/to/HIDPAIR
```

The agent should report that it submitted the proof. The development board LED remains off before pairing and turns on after the signature is accepted. The board then starts simulated HID activity. Use an isolated test host because the HID reports will reach the focused application. This profile has no firmware authenticity check, no encrypted firmware and no OTP protection.

The pairing test above does not store or type the three-line input sequence. Those lines are a separate feature: username, password and final command. To test that feature on the development board, return to BOOTSEL and run `./write_config --login "$HOME/.config/hid-lab/dev-aes.bin"`, then enter three harmless dummy lines at the hidden prompts. The record is AES-GCM encrypted, but the development key is recoverable from the UF2. After the board reboots, focus a text editor and pair again. The board types the first two lines, waits 15 seconds, then types the final line and Return. Do not use a terminal or real secrets for this test.

The firmware uses Mbed TLS for authenticated GCM decryption only. Its project configuration disables host entropy and clock support, which the firmware does not use. The UF2 range check recognises picotool's RP2350 E10 absolute marker and checks every firmware payload against the reserved settings sectors. The OTP helper refreshes the application key shares from the current signed image so later builds can generate new shares safely.

Use one build directory per board. For a Pico 2 without Wi-Fi:

```bash
cmake -S . -B build-pico2 -DPICO_BOARD=pico2 \
  -DHID_LAB_SIGNING_KEY=/secure/path/signing.pem \
  -DHID_LAB_AES_KEY=/secure/path/device-aes.bin \
  -DHID_LAB_IV_SALT=/secure/path/device-iv.bin
cmake --build build-pico2 -j"$(nproc)"
```

`PICO_BOARD` defaults to `pico2_w`. `cmake --build` works regardless of whether CMake selected Ninja or Unix Makefiles. An existing build directory keeps the board it was configured with, so a build directory created for another board fails until it is removed.

### Outputs

- .uf2 firmware image
- .elf executable
- .bin raw binary

### Tests

Run `python3 -m unittest discover -s tests -v` to check development key generation and header matching, the UF2 guard, OTP share refresh, signature binding and mounted volume file exchange. The tests use temporary files and do not access a board or program OTP.

### Rootless Host Pairing Setup

Create a user only host key pair. Keep the private key on the authorised host and transfer only the public key to the board.

```bash
bash -e <<'BASH'
umask 077
install -d -m 0700 "$HOME/.config/hid-lab"
test ! -e "$HOME/.config/hid-lab/host-private.pem"
openssl ecparam -name prime256v1 -genkey -noout \
  -out "$HOME/.config/hid-lab/host-private.pem"
openssl pkey -in "$HOME/.config/hid-lab/host-private.pem" -pubout \
  -out "$HOME/.config/hid-lab/host-public.pem"
BASH
```

Before enrolment, create and verify an encrypted offline backup of `host-private.pem` as shown in the development test section. Keep the private key at this path for the lifetime of the pairing. With the board in BOOTSEL mode, enrol the public key using the same per-device AES key used for the encrypted records:

```bash
./write_config --pair-host "$HOME/.config/hid-lab/host-public.pem" /secure/path/device-aes.bin
```

After the board has matching permanent secure boot keys provisioned, install the agent, user service, timer and private key without `sudo`:

```bash
install -D -m 0755 tools/pair_host.py "$HOME/.local/libexec/hid-lab/pair_host.py"
install -D -m 0644 systemd/user/hid-lab-pair.service "$HOME/.config/systemd/user/hid-lab-pair.service"
install -D -m 0644 systemd/user/hid-lab-pair.timer "$HOME/.config/systemd/user/hid-lab-pair.timer"
systemctl --user daemon-reload
systemctl --user enable --now hid-lab-pair.timer
```

The user timer checks mounted FAT volumes every two seconds without udev rules or access to `/dev/hidraw`. The service runs with `PrivateUsers=yes`. The target host automatically mounts the application volume for the user, so the pairing agent exchanges files as an ordinary user. To pair before desktop login, the user manager must be running at boot with lingering enabled and the automount must be available to that user. To move pairing to another host, clear the board record with `./write_config --pair-clear` and enrol that host's public key. Do not use a disposable build key or provision a disposable OTP file on a real board.

If the host private key is lost, restore the original from its encrypted backup. A newly generated host key will not match the public key stored on the board. If the original cannot be restored, enrol the replacement public key through BOOTSEL using the existing device AES key. Do not expect the timer to pair until the board record has been replaced.

---

## Verification

Device behaviour is observed host-side on Linux.

- `sudo evtest` on the keyboard and mouse event nodes shows the raw event stream. The invariant: every key or button down has a matching up before the next unrelated event and ALT is released cleanly after each ALT+TAB.
- `sudo usbhid-dump -m 2e8a:0003 -e stream` shows raw reports. During a click hold the mouse button field stays set whilst only the delta bytes vary.

---

## Known issues

| Severity | Location | Issue |
|---|---|---|
| Low | `src/usb_descriptors.c` | Product ID `0x0003` belongs to the RP2040 USB boot mode. |
| Risk | `src/wifi_manager.c` | Worst-case main loop time with Wi-Fi has not been measured against the 5 ms HID interval. |
| Risk | `src/secure_store.c` | Runtime AES-GCM uses software Mbed TLS. Key material exists in SRAM and may be exposed by sufficiently capable power, timing or invasive attacks. |
| Risk | `tools/pair_host.py` | The prototype host signing key is a software PEM file. Root only permissions protect against ordinary users, not a determined physical attacker with access to the host. |
| Risk | `src/pairing.c` | Pairing gates reports on unrecognised hosts but cannot hide keyboard reports from the authorised host or a USB capture device. |
| Low | `src/input_tasks.c` | After a long idle, each behaviour whose timer has already elapsed fires once on the first active pass, a brief catch-up at the start of a window. |
| Risk | `inc/hid_keymap.h` | The DE QWERTZ map is from the layout spec and is not yet verified against a real German host. Store a known credential and check the typed characters before relying on it. |

---

## Disclaimer

This project is intended for embedded systems research and educational analysis of USB HID behaviour and host-side detection mechanisms.

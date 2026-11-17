# RP2350 HID Security Lab explained

This guide explains the RP2350 HID Security Lab firmware, host tools and research design. It is kept alongside the project so reviewers can follow the implementation and reproduce the development workflow.

## Reading order

| Order | File | What it teaches |
|---|---|---|
| 1 | `src/main.c` | Startup order and the main loop |
| 2 | `src/input_tasks.c` | How non-blocking state machines work |
| 3 | `inc/reactivation.h`, `src/reactivation.c` | The active then idle duty cycle |
| 4 | `inc/login.h`, `src/login.c`, `inc/hid_keymap.h` | Stored input sequence state machine |
| 5 | `src/usb_descriptors.c`, `inc/tusb_config.h`, `src/pairing.c`, `src/pairing_storage.c` | USB storage pairing and HID reports |
| 6 | `inc/flash_config.h`, `src/write_config.c` | Storing settings in flash |
| 7 | `inc/wifi_manager.h`, `src/wifi_manager.c` | Connecting and reconnecting |
| 8 | `inc/lwipopts.h`, `CMakeLists.txt` | How the build configures all of this |

## The big idea

The firmware is one loop that never waits:

```text
board_init()
secure_store_init()      import and lock OTP key shares
wifi_manager_init()      may block, runs before USB starts
tusb_init()
read the active window length from flash
    reactivation_init()      first window opens at boot
    input_tasks_init()
    pairing_init()           load the encrypted host public key

while (1):
    tud_task()               keep USB alive
    wifi_manager_task()      keep the network alive
    reactivation_update()    advance the active then idle cycle
    pairing_task()           verify a fresh host signature
    login_task()             type the configured sequence after authorisation
    work out active          true while inside an active window
    update the LED
    input_tasks_run(active)  run HID behaviour only after authorisation
```

There is no operating system. Instead of sleeping, code records a time and returns, then checks that time on a later pass:

```c
// Blocking: USB dies during the wait
press(); sleep_ms(100); release();

// Non-blocking: USB keeps running
if (state == IDLE) { press(); release_at = now + 100; state = DOWN; }
else if (now >= release_at) { release(); state = IDLE; }
```

This is the most important pattern in the project. Almost every design decision follows from it.

## HID behaviour

Each activity is a small state machine with random timing:

| Activity | Interval | What it does |
|---|---|---|
| Mouse movement | 8 to 20 s | Moves 1 to 4 units on both axes |
| Left click | 30 to 90 s | Holds for 80 to 180 ms |
| Safe key | 20 to 60 s | Presses one non-typing key |
| Text burst | 2 to 5 min | 3 to 8 home-row keys |
| Scroll burst | 1 to 3 min | 3 to 10 wheel ticks |
| Window switch | 3 to 7 min | ALT+TAB, 1 to 3 times |

**Why the mouse has a shared struct:** a mouse report holds the buttons and the movement together. If movement sent its own report during a click, it would say "no buttons pressed" and end the click. Tasks edit shared state. Only `mouse_flush()` transmits.

**Why sends are checked:** the USB endpoint holds one report at a time. If a release were lost, the host would see a stuck key. So a state machine advances only after its report is queued.

**Why ending a run takes care:** a run could end mid-click, so `release_all_inputs()` sends explicit releases before going quiet.

**Why the run cycles:** the device is active for the configured window, then idle for the period, then active again with no end. The old permanent-expiry latch is gone. Wrap safety moved into the re-activation timer, which keeps each phase shorter than the 49.7 day clock wrap and measures elapsed time with modular subtraction. See the Re-activation section below.

**Why `HID_ASSERT` exists:** the default Release build defines `NDEBUG`, which removes the standard `assert()`. `HID_ASSERT` stays in the flashed image and halts the firmware through `panic()`.

## Re-activation

The device no longer runs once and stops. It repeats a duty cycle for ever: active for a window, idle for a period, then active again. The window length is the stored `hours` value. That setting now means how long each active window lasts rather than a total lifetime. The idle gap is read from the same flash config in seconds. It can range from 1 second to 1 week and defaults to 1 week. Change it with a small `write_config` run without rebuilding.

```text
boot ─> ACTIVE (hours) ─> IDLE (period) ─> ACTIVE (hours) ─> IDLE ...
         ^ input sequence edge                       ^ input sequence edge
```

| Property | How |
|---|---|
| First window at boot | `reactivation_init()` back-dates the idle phase by one period, so the first `reactivation_update()` opens a window at once |
| Initial sequence after authorisation | `login_begin()` starts once after `pairing_is_authorised()` succeeds, so no sequence is typed before the host proof |
| One later sequence per active window | `reactivation_update()` returns true on the single pass each later window opens, which restarts the stored input sequence |
| Idle behaviour | `input_tasks_run(false)` releases every held key and button on each idle pass, so nothing is left pressed between windows |
| Wrap safety | each phase is capped well under the 49.7 day clock wrap. Elapsed time uses modular subtraction so the cadence holds across the rollover |

**Why it is a separate module:** keeping the cycle in `reactivation.c` makes it a pure function of its state and the current time, so it is tested on a PC with a fake clock. The firmware and the test run the same code. The test steps the clock across the 32-bit rollover and checks the cadence never drifts.

**The input sequence edge now owns startup input.** It types the stored input sequence, waits 15 seconds for the desktop session to become usable, then types the final command and Return. Normal simulated input is held off until that whole sequence completes.

## USB

The device presents a mass storage interface alongside keyboard and mouse HID. The application provides a small RAM backed FAT12 volume named HIDPAIR with fixed CHALLENG.BIN and RESPONSE.BIN files. The challenge contains protocol version, status, board identifier and a fresh 32 byte nonce. The host signs the domain separated message HID-LAB-PAIR-v1, board identifier and nonce, then writes the 64 byte P-256 signature to RESPONSE.BIN.

## Flash and configuration

```text
0x10000000 +----------------------+
           | firmware             |  linker limit: 0x3FC000 bytes
0x103FC000 +----------------------+
           | host pairing (4 KB)  |  AES-256-GCM encrypted P-256 public key
0x103FD000 +----------------------+
           | login (4 KB)         |  AES-256-GCM encrypted input sequence record
0x103FE000 +----------------------+
           | Wi-Fi creds (4 KB)   |  AES-256-GCM encrypted Wi-Fi record
0x103FF000 +----------------------+
           | config sector (4 KB) |  magic + hours + period
0x103FFFFF +----------------------+
```

The encrypted firmware image is loaded into SRAM. It verifies and decrypts settings only after importing the OTP key shares into SRAM and locking their pages. Each field is validated on its own. An invalid magic value or hours value falls back to the 24-hour default. An invalid period falls back to 1 week.

**Why separate sectors:** a sector is the smallest unit flash can erase. The bootrom erases one before writing to it. Sharing a sector would mean changing one setting erases another. Each record gets its own sector. The run time, encrypted Wi-Fi record, encrypted input sequence record and encrypted host pairing record are written independently. Flashing new firmware leaves all four alone, so settings survive updates.

The layout is defined in `flash_config.h` and `CMakeLists.txt`. Record-size assertions and a post-build UF2 address check stop the build if the layouts disagree or the firmware overlaps reserved sectors.

The secure executable is linked for SRAM. A post-build check rejects any encrypted firmware UF2 block that reaches the reserved host pairing sector.

## Wi-Fi

The stack has three layers. `wifi_manager.c` decides when to connect. lwIP handles the network protocols. The cyw43 driver talks to the radio.

```text
OFF ──> JOINING ──> UP
          ^  |       |
          |  v       v
          BACKOFF <──┘
```

| Event | Response |
|---|---|
| Join fails | Retry after 2 s, doubling up to 60 s |
| Wrong password | Retry every 60 s |
| No DHCP lease | Time out after 30 s, then retry |
| Link lost | Leave, wait, rejoin |
| Connected | Reset the delay to 2 s |

**Poll mode:** the SDK's `pico_cyw43_arch_lwip_poll` adds no thread or radio interrupt. All network work runs inside `cyw43_arch_poll()`, so there is no locking to get right.

**Blocking calls:** `cyw43_arch_wifi_connect_timeout_ms()` is never used, because it would stall `tud_task()`. Joining is asynchronous. The status is checked each pass.

**Both boards:** on a Pico 2, `wifi_manager.h` replaces every function with an empty inline stub. So `main.c` needs no board conditional. Both boards use the signed, encrypted SRAM boot profile.

**Status LED on the Pico 2 W:**

| LED | Meaning |
|---|---|
| Solid | Online or no network configured |
| Blinking | Not online yet, including joined without an address |
| Off | Run finished |

**Security mode:** the record stores WPA2 or WPA3 explicitly, with no fallback from WPA3 to WPA2. A fallback would let an attacker force the weaker mode.

## Protected configuration records

Wi-Fi and stored input sequence payloads are encrypted on the host before the UF2 is written. Configuration values are read from hidden standard input. The writer reads the per-device AES key from an owner-only file.

```bash
./write_config --wifi wpa2 "your-network" /secure/path/device-aes.bin    # asks for the password
./write_config --wifi-clear                  # removes them from the board
```

| Design choice | Why |
|---|---|
| Hidden standard input | Stored input sequence values and the Wi-Fi password stay out of argv and terminal echo |
| Owner-only key file | The per-device AES key is not passed as a command-line value |
| Version field | A future format can be recognised instead of misread |
| AES-256-GCM | Encrypts the record and authenticates its header, nonce, content and flash address |
| Fail-closed validation | Missing keys, invalid tags or malformed payloads mean no join or input sequence |
| CRC inside the payload | Extra format check after GCM authentication |
| Secure OTP access | Only Secure firmware can read the copied key shares |

**Physical-access boundary:** flash records are ciphertext and key shares are Secure-readable OTP. OTP provisioning disables debug and enables the glitch detector. The stored input sequence exists in SRAM and leaves the device as ordinary HID keystrokes, so a USB capture can observe them. Runtime record crypto uses software Mbed TLS AES-GCM and has not been evaluated against power or timing side channels.

## Stored input sequence behaviour

### Host input readiness investigation

Hardware testing reported that a focused editor received only the command after the 15 second wait, not the earlier sequence lines. Endpoint readiness is not proof that the host input layer is listening. The typist now waits for 2 seconds of continuous HID endpoint readiness before sending the stored input sequence. Losing readiness restarts that settling timer. This remains non blocking and uses wrap safe elapsed time. The existing 15 second wait after the second input line remains unchanged.

This change tests a startup timing hypothesis. It does not confirm the cause until the stored input sequence is observed on hardware. Rebuilding `write_config` or rewriting the unchanged input sequence is not required for this firmware timing change. The earlier additional boot call and buffer clearing did not resolve the reported symptom.

At boot, the device waits for host pairing before it authenticates and decrypts the input sequence record into SRAM. It types the first two lines, waits 15 seconds for the host session, then types its final command. The same sequence runs at later active windows only whilst the authorised USB session remains active. Run `write_config --login /secure/path/device-aes.bin` and enter the three stored input sequence lines at its hidden prompts.

**A keyboard sends key codes, not characters.** The host turns a positional key code plus a modifier into a character using its own layout. So to type into a German QWERTZ host the firmware must send the code of the physical key that yields each character on that layout. `z` is sent as the key US keyboards label `Y` (usage `0x1C`). Symbols such as `@` and `{ [ ] }` need AltGr. `inc/hid_keymap.h` holds that map, shared with `write_config` so the two never disagree about what is typeable.

**Some characters cannot be typed.** Dead keys (`^`, the accents) and non-ASCII characters (umlauts, `ß`, `€`) are left out of the map. `write_config` checks each stored input sequence line against the map, so an unstoreable character fails there with a clear message rather than mistyping silently at the keyboard later.

**The typist never blocks.** It is a state machine driven one step per main-loop pass. It sends a key down. Once that report is accepted it sends the release. It then moves to the next character. It never stalls `tud_task()`. No character is lost when the USB endpoint is briefly busy.

**Every key is released.** A USB keyboard that reports a key down and never releases it makes the host auto-repeat, which would print `zzzz…`. Each key down is followed by a key-up report. Nothing is held during the 15-second wait. Each character then appears exactly once.

**It owns the keyboard while it runs.** During input sequence typing, the wait and the final configured action the normal HID behaviour is held off, so the two never contend for the single keyboard report. Once the final configured action and its Return have been sent, the behaviour runs for the rest of the window. The RAM buffer is then cleared, removing the input sequence text.

**Why the command is typed only after waiting.** The command target may not accept input until the desktop session has finished starting. Keeping the 15-second wait between the second input line Return and the stored command lets the host finish its host input workflow without blocking USB servicing. The stored input sequence is supplied on hidden standard input as three lines when `write_config --login <aes-key-file>` runs. It is stored with the input sequence and checked against the German QWERTZ key map. It is typed after the wait. Its final Return invokes it.

## Host authorisation

The host agent runs as a rootless systemd user service inside a user namespace. A user timer checks automatically mounted FAT volumes every two seconds, so authorisation requires no udev rule, system service or access to /dev/hidraw. It reads CHALLENG.BIN and writes its P-256 signature to RESPONSE.BIN. The device verifies the signature using the public key stored in an authenticated encrypted record. A new nonce is generated for each USB connection, so an old response cannot authorise a later connection. Until verification succeeds, neither the stored input sequence nor simulated keyboard and mouse reports are sent.

Create the host private key directly at its permanent location. Never generate an enrolled host key in `/tmp`. Keep the same private key for the lifetime of the board pairing. Before enrolment, make an encrypted offline backup and verify that its derived public key matches `host-public.pem`. For example, with an encrypted removable drive mounted as `/media/$USER/ENCRYPTED_BACKUP`, run `openssl pkey -in "$HOME/.config/hid-lab/host-private.pem" -aes-256-cbc -out /media/$USER/ENCRYPTED_BACKUP/hid-lab-host-private.pem.enc`. OpenSSL prompts for the backup passphrase. Enrol the public key through `./write_config --pair-host "$HOME/.config/hid-lab/host-public.pem" /secure/path/device-aes.bin` whilst the board is in BOOTSEL mode. Install the agent in `~/.local/libexec/hid-lab/` and the user units in `~/.config/systemd/user/`, then enable the timer with `systemctl --user enable --now hid-lab-pair.timer`. Keep the private key at `~/.config/hid-lab/host-private.pem` so the timer can use it after restart. If the key is lost, restore the original from its encrypted backup. A replacement key will not match the public key stored on the board. If the original cannot be restored, enrol a replacement public key through BOOTSEL using the existing device AES key. The timer cannot pair until the board record is replaced.

For pairing before desktop login, the user manager must run at boot with lingering enabled and the automatically mounted USB volume must be available to that user.

The host key in this prototype is a software PEM file, not a TPM protected key. User only file permissions reduce casual access but do not resist a determined physical attacker with access to the host. Host authorisation blocks an unenrolled computer from triggering the board. It cannot prevent the authorised host or a USB capture device from observing ordinary keyboard reports. The clean Pico 2 W firmware build and host writer were compiled again. The secure UF2 range check passed and all seven host tests passed, including development key generation and the file exchange test. The host public key parser was exercised with a temporary test key. That earlier Secure build used disposable keys and was not flashed. The development profile below now provides a no OTP hardware test.


## Development test profile

The development profile uses the SDK RP2350 Secure platform but skips image signing and encryption. On a blank board with secure boot unset, the ROM accepts this ordinary UF2 without OTP provisioning. The installed SDK has no Non-secure platform startup file. The profile skips firmware signing, firmware encryption and OTP output. `tools/embed_dev_aes_key.py` checks the disposable AES key is exactly 32 bytes and writes a mode 0600 generated header. `secure_store_init()` loads that embedded test key instead of reading OTP. `src/main.c` uses the LED to show pairing status. CMake verifies that the generated key header matches the selected AES key file and stops configuration if they differ. The key can be recovered from the UF2, so this profile must never contain real input sequence data or secrets.

Create development keys once in persistent owner only storage. The guard commands stop instead of replacing an existing key. Do not put these keys in `/tmp`, since the device needs the same AES key for records after reconnects and rebuilds.

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

Before enrolling the public key, back up both development keys on encrypted offline storage. A VeraCrypt container stored on a separate USB drive is suitable. Unlock and mount it, then use its mount path in place of /media/$USER/ENCRYPTED_BACKUP. The OpenSSL command below encrypts the archive separately as well. /media/dp/HIDPAIR is the board volume and is not a backup destination. OpenSSL prompts for a backup passphrase.

```bash
bash -e -o pipefail <<'BASH'
tar -C "$HOME/.config/hid-lab" -cf - dev-aes.bin host-private.pem |
  openssl enc -aes-256-cbc -salt -pbkdf2 \
    -out /media/$USER/ENCRYPTED_BACKUP/hid-lab-development-keys.tar.enc
BASH
```

Verify that the backup decrypts and contains the private key matching the host public key:

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

Expected result is the message Backup verified: host private key matches the public key. and exit status 0. cmp prints nothing when the files match. Do not enrol the host unless the comparison succeeds. Keep the same AES and host private keys for later development builds. Build the profile outside the repository so it does not add another project root build directory:

```bash
cmake -S . -B /tmp/hid-lab-dev-build \
  -DPICO_BOARD=pico2_w \
  -DHID_LAB_DEVELOPMENT_BUILD=ON \
  -DHID_LAB_DEV_AES_KEY="$HOME/.config/hid-lab/dev-aes.bin"
cmake --build /tmp/hid-lab-dev-build -j2
gcc -D_GNU_SOURCE -std=c11 -Wall -Wextra -Werror \
  src/write_config.c -Iinc -lcrypto -o write_config
```

Hold BOOTSEL while connecting the test board. Copy `/tmp/hid-lab-dev-build/hid_lab.uf2` to `/media/$USER/RP2350/`. After it boots the application, return to BOOTSEL and run `./write_config --pair-host "$HOME/.config/hid-lab/host-public.pem" "$HOME/.config/hid-lab/dev-aes.bin"`. This writes the encrypted test pairing record to the BOOTSEL volume. The board then restarts into the application.

Wait for the host to mount HIDPAIR. Find the mount path with `lsblk -o LABEL,FSTYPE,MOUNTPOINTS | rg HIDPAIR`, then run `unshare --user --map-root-user python3 tools/pair_host.py --key "$HOME/.config/hid-lab/host-private.pem" --mount /path/to/HIDPAIR`. The agent reports a submitted proof. The board LED stays off before verification and turns on after accepting the signature. The board then starts simulated HID activity. Use an isolated test host because HID reports go to its focused application. The pairing test above does not store or type the three line input sequence. Those lines configure a separate input sequence behaviour. To test that feature on the development board, return to BOOTSEL and run `./write_config --login "$HOME/.config/hid-lab/dev-aes.bin"`, then enter three harmless dummy lines at the hidden prompts. The record uses AES-GCM, but the development key is recoverable from the UF2. After the board reboots, focus a text editor and pair again. The board types the first two lines, waits 15 seconds, then types the final line and Return. Do not use a terminal or real secrets for this test.

The development key header is generated by `tools/embed_dev_aes_key.py` and is mode 0600. Tests check its size validation and permissions. The seven host tests pass. Both development and secure firmware profiles compile and pass the UF2 range check. No OTP was programmed. No board was attached during this build, so runtime USB mounting and pairing still need the hardware test above.

## Known issues

| Severity | Location | Issue |
|---|---|---|
| Low | `src/usb_descriptors.c` | Product ID `0x0003` belongs to the RP2040 USB boot mode. |
| Risk | `src/wifi_manager.c` | Worst-case main loop time with Wi-Fi has not been measured against the 5 ms HID interval. |
| Risk | `src/secure_store.c` | Runtime AES-GCM and P-256 verification use software Mbed TLS. Key material exists in SRAM and may be exposed by power or timing side channels. The paired host can observe the stored input sequence as ordinary keystrokes. |
| Low | `src/input_tasks.c` | After a long idle, each behaviour whose timer has already elapsed fires once on the first active pass, a brief catch-up at the start of a window. |
| Risk | `inc/hid_keymap.h` | The DE QWERTZ map is from the layout spec and is not yet checked against a real German host. Store a known input sequence and watch the typed characters before relying on it. |

## Building this copy

Production signing, AES and IV keys must live in persistent protected storage outside the repository. Generate them once, back them up in encrypted offline storage before OTP provisioning, then reuse the exact same files for firmware rebuilds. Never regenerate these values when reconnecting a board or rebuilding an update. A newly generated key will not match the board OTP and stored records.

`compile_commands.json` links into `build/`, so clangd needs a build to exist:

```bash
cmake -S . -B build -DHID_LAB_SIGNING_KEY=/secure/signing.pem -DHID_LAB_AES_KEY=/secure/device-aes.bin -DHID_LAB_IV_SALT=/secure/device-iv.bin # add -DPICO_BOARD=pico2 for Pico 2
cmake --build build -j"$(nproc)"
```

Use one build folder per board, because an existing folder keeps the board it was configured with. The secure build produces an OTP provisioning JSON with secure boot, debug disabled, the glitch detector enabled and Secure-only key shares. Loading it is irreversible. Back up the signing key, device AES key and IV salt. The build does not program OTP. The secure image cannot boot on an unprovisioned board. It needs matching OTP keys for secure boot and record decryption. Verification builds made with disposable keys are not deployable. Do not provision their OTP files. GitHub CI creates disposable signing, AES and IV keys in the runner temporary directory to compile both board variants. It does not provision OTP or upload the OTP provisioning file. The uploaded CI UF2 artifacts are for build verification only and cannot boot on a board. Never provision a board with CI keys.

The firmware uses Mbed TLS for authenticated GCM decryption and P-256 signature verification. Its project configuration disables host entropy and clock support, which the firmware does not use. The UF2 range check recognises picotool’s RP2350 E10 absolute marker and checks every firmware payload against the reserved settings sectors. The OTP helper refreshes the application key shares from the current signed image so later builds can generate new shares safely.

Run `python3 -m unittest discover -s tests -v` to check that the UF2 guard accepts picotool’s RP2350 E10 marker and rejects a reserved sector overlap. The tests also check development key header matching, OTP key share refresh, signature binding and the mounted volume file exchange. They use temporary files and do not access a board or program OTP.


## Repository cleanup and clean build

On 15 November 2026, removed the stale ignored `build/` directory from the active repository. Its firmware and OTP outputs predated the current source and could be mistaken for the current device image. Removed generated Python `__pycache__` directories from `tests/` and `tools/`. The source tests, pairing scripts, systemd user service and timer remain because they are part of the current host pairing implementation.

Rebuilt the development profile in `/tmp/hid-lab-cleanup-build` using a newly generated disposable AES key. The RP2350 development UF2 range check passed. All seven host tests passed and `src/write_config.c` compiled with `-Wall -Wextra -Werror`. The build and test outputs remain under `/tmp` and are not part of the repository.


## Development pairing key recovery on 16 November 2026

The original host private key and development AES key had been created under /tmp. They were absent after the machine restarted, so automatic pairing stopped. The setup guidance now creates keys in persistent owner only storage, prevents accidental replacement and requires backup verification before enrolment.

Generated replacement development AES, host private and host public keys in ~/.config/hid-lab/. Each file has mode 0600. Created an encrypted backup of the development AES key and host private key. Decrypted the archive and compared its derived public key with host-public.pem. They matched and cmp returned 0. The verification command now prints a clear success message. Backup commands run inside an explicitly invoked Bash child process, so shell options do not leak into the interactive shell.

Compiled write_config with -Wall -Wextra -Werror. All seven host tests passed and the firmware range check passed. Added a CMake configure check and a unit test that reject a generated development key header which differs from the selected AES key. The corrected build confirmed that the embedded key matches the persistent key.

Copied the corrected development UF2 to the board in BOOTSEL mode. The replacement public key record had already been written using the same persistent AES key. The rootless user timer was active and submitted a proof. Linux initially showed the cached challenge status 1. Unmounted and remounted the RAM backed HIDPAIR volume to refresh the cached sector. The fresh challenge status was 2, which means the board accepted the signature. The pairing test passed.

The old input sequence was encrypted with the previous development AES key. It cannot be recovered unless that old key or the exact old development UF2 is found. If the old key is unavailable, rewrite only harmless test lines after pairing succeeds. Never store real secrets in the development image because its AES key is recoverable from the UF2.


The user confirmed that the LED turns on after reconnecting, which verifies host pairing. The three input strings did not type because their stored record uses the lost development AES key. Re-enter a harmless test sequence with write_config --login ~/.config/hid-lab/dev-aes.bin while the board is in BOOTSEL mode. Focus a text editor before the board pairs again. The development key is recoverable from the UF2, so do not enter real credentials.


## GitHub CI secure build fix on 16 November 2026

The original workflow selected the secure profile without passing its required signing, AES and IV key paths. CMake correctly stopped with HID_LAB_SIGNING_KEY missing. The workflow now creates disposable keys under the runner temporary directory and passes all three paths to CMake for both pico2_w and pico2 builds. It installs libssl development files and compiles write_config with GNU extensions and OpenSSL linkage.

CI does not provision OTP or upload the generated OTP provisioning file. Its signed and encrypted UF2 artifacts use disposable keys and cannot boot on a provisioned board. Artifact names now state that they are not deployable. Never provision a board with CI keys.

Local verification used the disposable secure profile for both board variants. Both UF2 range checks passed. The host writer compiled and all seven host tests passed.


The pairing API and RAM backed MSC storage declarations now share inc/pairing.h. Removed inc/pairing_storage.h because it only exposed three internal storage functions. Removed blank lines between consecutive include directives in the C sources and headers.

The build helpers, Linux pairing agent and host tests use Python for host file, JSON and mount handling plus OpenSSL command calls. They do not run in the firmware. Firmware and write_config remain C.

Verification after the refactor: all seven host tests passed, the development firmware rebuilt and passed its UF2 range check, and write_config compiled successfully.

## Project purpose and public overview

This repository is a portfolio project about RP2350 firmware engineering and security design. It demonstrates cooperative scheduling, USB HID report modelling, cryptographic host authorisation and protected configuration records. The purpose is to study how secure boot, OTP, encryption and host software combine in an embedded system, while documenting their practical limits.

The root README is the short reviewer entry point. It presents the project scope, key engineering work, security boundary and build commands. This guide keeps the detailed implementation, setup and verification notes.


## Public project wording and source comments

Updated the README and implementation comments to describe the repository as the RP2350 HID Security Lab portfolio project. Source descriptions now frame the configured data as a stored input sequence and the pairing flow as host authorisation. Kept established C symbols, storage fields and command line switches unchanged because they are implementation interfaces. Updated the configuration writer success message to say stored input sequence. Rebuilt the development firmware, ran all seven host tests and compiled write_config with warnings treated as errors. All checks passed. The linker still reports its existing _link and _unlink stub warnings.

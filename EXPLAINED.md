# Build and hardware guide

## Pairing and input

The board exposes a small FAT volume named `HIDPAIR`. It carries a fresh challenge, the host response and the pairing status. `pair_host` signs each challenge with the enrolled host private key. The firmware releases keyboard and mouse output only after it accepts the signature.

The configured input sequence is encrypted in internal flash. Once sent, its keyboard reports are visible to the connected host and to any USB capture device. Pairing authorises the host session. It does not make the resulting keystrokes private.

## Build profiles

| Profile | Firmware protection | Use |
| --- | --- | --- |
| Development | Unsigned and unencrypted. A disposable AES key is embedded in the firmware. No production OTP policy is applied. | Pairing and configuration tests on an unprovisioned board. Physical extraction resistance is not established. |
| Production | Firmware is signed and encrypted. Its matching key shares and security policy are described in `hid_lab.otp.json`. The board must be separately provisioned with matching OTP values. | Test on a board provisioned for that production key set. OTP changes can be irreversible. |

The physical access threat model does not assume an attacker has a UF2 file. `HIDPAIR` exposes only the pairing files, not the embedded development key. The development profile has no hardware protected key boundary, so its encrypted records must not be treated as confidential against physical inspection. A successful build does not program OTP.

## Build and install

Run these commands from the repository root. The build needs Bash, CMake, OpenSSL, the Arm compiler, a host C compiler and a Pico SDK checkout with submodules. Set `PICO_SDK_PATH` to that checkout. Keep key files outside the repository and generate them only for a new setup.

Create the private key directory once:

```bash
key_dir="$HOME/rp2350-hid-security-lab"
install -d -m 700 "$key_dir"
```

Create the inputs for the profile you will build.

**Development inputs**

```bash
umask 077
key_dir="$HOME/rp2350-hid-security-lab"
test -e "$key_dir/dev-aes.bin" || openssl rand 32 > "$key_dir/dev-aes.bin"
```

**Production inputs**

```bash
umask 077
key_dir="$HOME/rp2350-hid-security-lab"
secure_dir="$key_dir/secure-device"
if [[ -e "$secure_dir" ]]; then
    if [[ ! -s "$secure_dir/signing.pem" || ! -s "$secure_dir/device-aes.bin" || ! -s "$secure_dir/device-iv.bin" ]]; then
        printf 'Production key directory is incomplete. Restore its original keys before building.\n' >&2
        exit 1
    fi
    printf 'Using the existing production keys in %s.\n' "$secure_dir"
else
    mkdir -m 700 "$secure_dir"
    openssl ecparam -name secp256k1 -genkey -noout -out "$secure_dir/signing.pem"
    openssl rand -out "$secure_dir/device-aes.bin" 32
    openssl rand -out "$secure_dir/device-iv.bin" 16
fi
```

Build commands:

**Development**

```bash
key_dir="$HOME/rp2350-hid-security-lab"
cmake -S . -B build-dev -DPICO_BOARD=pico2_w \
  -DHID_LAB_DEVELOPMENT_BUILD=ON \
  -DHID_LAB_DEV_AES_KEY="$key_dir/dev-aes.bin"
cmake --build build-dev -j2
test -s build-dev/hid_lab.uf2
```

**Production**

```bash
umask 077
secure_dir="$HOME/rp2350-hid-security-lab/secure-device"
install -d -m 700 build-secure
cmake -S . -B build-secure -DPICO_BOARD=pico2_w \
  -DHID_LAB_DEVELOPMENT_BUILD=OFF \
  -DHID_LAB_SIGNING_KEY="$secure_dir/signing.pem" \
  -DHID_LAB_AES_KEY="$secure_dir/device-aes.bin" \
  -DHID_LAB_IV_SALT="$secure_dir/device-iv.bin"
cmake --build build-secure -j2
test -s build-secure/hid_lab.uf2
test -s build-secure/hid_lab.otp.json
```

`hid_lab.otp.json` is a provisioning description, not a programming result. Do not apply it to a board until the keys and permanent security effects have been reviewed.

Compile the Linux tools once:

```bash
gcc -D_GNU_SOURCE -std=c11 -Wall -Wextra -Werror tools/write_config.c -Iinc -lcrypto -o write_config
gcc -std=c11 -Wall -Wextra -Werror tools/pair_host.c -lcrypto -o pair_host
```

Hold BOOTSEL while reconnecting the board. Wait for Linux to mount the `RP2350` boot volume, copy the image for the profile you built and allow the board to restart.

```bash
mountpoint -q "/media/$USER/RP2350" && cp build-dev/hid_lab.uf2 "/media/$USER/RP2350/"
```

For production, use `build-secure/hid_lab.uf2` in that copy command. Production firmware requires a board provisioned with its matching keys before it can start.

## Pairing and input setup

Use the matching AES key for the firmware profile. Generate or reuse the host private key. After the firmware restarts, unplug the board, hold BOOTSEL while reconnecting it and wait for `RP2350` to mount again. Enrol its public key with `pair_host`:

Create a host key pair once for a new host. Reuse the existing pair when one has already been enrolled.

```bash
umask 077
host_private="$HOME/rp2350-hid-security-lab/host-private.pem"
if [[ -e "$host_private" ]]; then
    printf 'Reuse the existing host private key. Do not generate a replacement.\n' >&2
    exit 1
fi
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$host_private"
```

```bash
mountpoint -q "/media/$USER/RP2350" && ./pair_host --enrol \
  --key "$HOME/rp2350-hid-security-lab/host-private.pem" \
  --aes-key "$HOME/rp2350-hid-security-lab/dev-aes.bin"
```

For production, replace the AES key path with `"$HOME/rp2350-hid-security-lab/secure-device/device-aes.bin"`. `pair_host` derives and encrypts the public key, writes `pico_hid_cfg.uf2` and the board restarts. Keep the matching host private key on Linux. After restart, prove possession through the mounted `HIDPAIR` volume:

```bash
./pair_host --key "$HOME/rp2350-hid-security-lab/host-private.pem" --mount "/media/$USER/HIDPAIR"
```

To configure the three input strings and schedule together, enter BOOTSEL and pass `--sequence` after the schedule arguments. The utility prompts for line 1, line 2 and the final action without terminal echo. Line 1 and action are required. Line 2 may be empty. Each is limited to 64 characters supported by the German QWERTZ key map. Both records are written in one UF2 file, followed by one restart. This step is separate from host enrolment.

```bash
mountpoint -q "/media/$USER/RP2350" && ./write_config 14 3d --sequence \
  "$HOME/rp2350-hid-security-lab/dev-aes.bin"
```

For production, use `"$HOME/rp2350-hid-security-lab/secure-device/device-aes.bin"`. Use `./write_config --sequence <aes-key-file>` to write only the input sequence or `./write_config <hours> [period]` to write only the schedule. After successful pairing, the firmware types line 1 and line 2, waits 15 seconds, then types the final action. The default idle interval is seven days.

## Verification

Run the host and firmware pairing tests from the repository root:

```bash
bash tests/run_tests.sh
```

The suite tests signature acceptance and rejection, reconnect challenges, pairing status, key handling, OTP policy output and firmware UF2 boundaries. GitHub Actions runs it before the two firmware builds.

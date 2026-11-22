# Design and hardware guide

## What the signature covers

The firmware publishes a 42 byte challenge in `CHALLENG.BIN` on the board’s FAT volume. The first two bytes identify the protocol version and pairing state. The remaining bytes contain the eight byte board identifier and a 32 byte nonce.

The host agent signs the protocol domain string, including its terminating zero byte, followed by the board identifier and nonce. It uses ECDSA on P-256 with SHA-256 and writes the two 32 byte signature components to `RESPONSE.BIN`. The firmware verifies them against the enrolled public key. Disconnecting clears authorisation. Reconnecting creates a new challenge.

The firmware gate lives in [pairing.c](src/pairing.c). The [main loop](src/main.c) uses its result to schedule the stored input sequence and subsequent simulated activity. The Pico 2 W wireless manager handles network association and retry. There is no application traffic over that connection.

## What each build protects

| Profile | Image and configuration | Intended use |
| --- | --- | --- |
| Development | The image embeds a disposable AES key that can be recovered from the UF2. | Pairing experiments with harmless test data on an unprovisioned board. |
| Secure | The build signs and encrypts the image and generates an OTP provisioning file. The firmware reads protected key shares to open authenticated configuration records. | Research on a board provisioned with matching keys. CI uses disposable keys for build verification. |

After pairing, ordinary USB reports expose the stored input sequence to the receiving host and to a USB capture device. The host private key is a software file. Pairing binds the session to possession of that key and the fresh challenge.

## Try pairing on a development board

1. **Prepare reusable test keys.** On first setup, create a private directory and generate the keys once. For an enrolled board, reuse its existing keys.

```bash
bash -e <<'BASH'
umask 077
keys="$HOME/.config/hid-lab"
install -d -m 700 "$keys"
test ! -e "$keys/dev-aes.bin"
test ! -e "$keys/host-private.pem"
test ! -e "$keys/host-public.pem"
openssl rand -out "$keys/dev-aes.bin" 32
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$keys/host-private.pem"
openssl pkey -in "$keys/host-private.pem" -pubout -out "$keys/host-public.pem"
BASH
```

2. **Verify a backup before enrolment.** Mount an encrypted volume on a separate drive, such as a VeraCrypt container. Set `BACKUP_MOUNT` to its actual mount point. These commands create a private backup directory and compare each saved key with its original. Unmount the encrypted volume afterwards.

```bash
bash -e <<'BASH'
umask 077
mountpoint -q "${BACKUP_MOUNT:?Export the encrypted volume mount point first}"
backup=$(mktemp -d "$BACKUP_MOUNT/hid-lab.XXXXXXXX")
for key in dev-aes.bin host-private.pem host-public.pem
do
    install -m 600 "$HOME/.config/hid-lab/$key" "$backup/$key"
    cmp "$HOME/.config/hid-lab/$key" "$backup/$key"
done
printf 'Backup verified in %s\n' "$backup"
BASH
```

3. **Build the development firmware and native tools.** Set `PICO_SDK_PATH` and install the ARM toolchain and OpenSSL development files. Use `pico2` for the board without a radio.

```bash
keys="$HOME/.config/hid-lab"
cmake -S . -B build-dev -DPICO_BOARD=pico2_w -DHID_LAB_DEVELOPMENT_BUILD=ON \
  -DHID_LAB_DEV_AES_KEY="$keys/dev-aes.bin"
cmake --build build-dev -j2
cc -D_GNU_SOURCE -std=c11 -Iinc src/write_config.c -lcrypto -o build-dev/write_config
cc -std=c11 tools/pair_host.c -lcrypto -o build-dev/pair-host
```

4. **Enrol the host.** Connect the board with BOOTSEL held and copy `build-dev/hid_lab.uf2` to its boot volume. After it restarts, reconnect in BOOTSEL mode and run the configuration writer.

```bash
build-dev/write_config --pair-host "$keys/host-public.pem" "$keys/dev-aes.bin"
```

5. **Observe authorisation.** Use an isolated test host with a text editor focused when pairing completes. After the application starts, locate its HIDPAIR mount with `lsblk -o LABEL,MOUNTPOINTS`. Pass that path to the agent. A submission message means the agent wrote its response. A steady development LED means the firmware accepted it.

```bash
build-dev/pair-host --key "$keys/host-private.pem" --mount "/path/to/HIDPAIR"
```

For automatic pairing during a user session, install the agent as `~/.local/libexec/hid-lab/pair-host`, copy the two [user units](systemd/user) to `~/.config/systemd/user/` and run `systemctl --user daemon-reload` followed by `systemctl --user enable --now hid-lab-pair.timer`.

## Secure build verification

Supply the signing key, device AES key and IV salt from protected storage outside the checkout. Back up and verify these files before provisioning. OTP programming is irreversible. The build produces files for inspection without writing to a board.

```bash
cmake -S . -B build-secure -DPICO_BOARD=pico2_w \
  -DHID_LAB_SIGNING_KEY=/secure/path/signing.pem \
  -DHID_LAB_AES_KEY=/secure/path/device-aes.bin \
  -DHID_LAB_IV_SALT=/secure/path/device-iv.bin
cmake --build build-secure -j2
```

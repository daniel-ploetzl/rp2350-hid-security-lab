#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
sdk=${PICO_SDK_PATH:-}
if [[ -z "$sdk" || ! -f "$sdk/lib/mbedtls/library/ecdsa.c" ]]; then
    printf '%s\n' 'PICO_SDK_PATH must point to a Pico SDK checkout' >&2
    exit 2
fi
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

cc=${CC:-cc}
"$cc" -std=c11 -Wall -Wextra -Werror "$root/tools/build_tools.c" \
    -o "$temporary/build-tools"
"$cc" -std=c11 -Wall -Wextra -Werror \
    "$root/tools/pair_host.c" -lcrypto -o "$temporary/pair-host"
"$cc" -std=c11 -Wall -Wextra -Werror "$root/tests/make_uf2.c" \
    -o "$temporary/make-uf2"
"$cc" -std=c11 -Wall -Wextra -Werror "$root/tests/signature_convert.c" \
    -lcrypto -o "$temporary/signature-convert"

crypto_sources=(bignum.c bignum_core.c constant_time.c ecdsa.c ecp.c \
    ecp_curves.c error.c platform_util.c sha256.c)
crypto_paths=()
for source in "${crypto_sources[@]}"; do
    crypto_paths+=("$sdk/lib/mbedtls/library/$source")
done
"$cc" -std=c11 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    '-DMBEDTLS_CONFIG_FILE="hid_lab_mbedtls_config.h"' \
    -I"$root/tests/pairing_stubs" -I"$root/inc" \
    -I"$sdk/lib/mbedtls/include" -I"$sdk/lib/mbedtls/library" \
    "$root/tests/pairing_firmware_harness.c" "$root/src/pairing.c" \
    "${crypto_paths[@]}" -Wl,--gc-sections -o "$temporary/pairing-harness"

pass_count=0
check() {
    local label=$1
    shift
    if "$@"; then
        printf 'PASS %s\n' "$label"
        pass_count=$((pass_count + 1))
    else
        printf 'FAIL %s\n' "$label" >&2
        exit 1
    fi
}

"$cc" -std=c11 -Wall -Wextra -Werror -I"$root/inc" -I"$root/tests/pairing_stubs" \
    "$root/tests/pairing_status.c" "$root/src/pairing_storage.c" -o "$temporary/status-test"
check "status sector is read only and resets on reconnect" "$temporary/status-test"

dd if=/dev/zero of="$temporary/aes-key" bs=32 count=1 status=none
"$temporary/build-tools" embed-key "$temporary/aes-key" "$temporary/key.h"
check 'development key header is owner only' test "$(stat -c %a "$temporary/key.h")" = 600
check 'development key header verifies' "$temporary/build-tools" verify-key \
    "$temporary/aes-key" "$temporary/key.h"
dd if=/dev/zero of="$temporary/short-key" bs=31 count=1 status=none
if "$temporary/build-tools" embed-key "$temporary/short-key" "$temporary/bad.h" \
    >/dev/null 2>&1; then
    printf '%s\n' 'FAIL short development key rejected' >&2
    exit 1
fi
printf '%s\n' 'PASS short development key rejected'
pass_count=$((pass_count + 1))

"$temporary/make-uf2" valid "$temporary/valid.uf2"
"$temporary/make-uf2" overlap "$temporary/overlap.uf2"
check 'UF2 accepts RP2350 E10 marker' "$temporary/build-tools" verify-uf2 "$temporary/valid.uf2"
if "$temporary/build-tools" verify-uf2 "$temporary/overlap.uf2" >/dev/null 2>&1; then
    printf '%s\n' 'FAIL reserved UF2 overlap rejected' >&2
    exit 1
fi
printf '%s\n' 'PASS reserved UF2 overlap rejected'
pass_count=$((pass_count + 1))

share_a=$(printf '%400s' '' | tr ' ' a)
share_b=$(printf '%400s' '' | tr ' ' b)
share_c=$(printf '%400s' '' | tr ' ' c)
share_d=$(printf '%400s' '' | tr ' ' d)
printf '{"29:0":{"share":"%s"},"29:32":{"share":"%s"},' \
    "$share_a" "$share_b" >"$temporary/otp.json"
printf '"30:0":{"share":"%s"},"30:32":{"share":"%s"}}\n' \
    "$share_c" "$share_d" >>"$temporary/otp.json"
"$temporary/build-tools" extend-otp "$temporary/otp.json"
check 'OTP output copies nested share 29:0' grep -Fq \
    "\"24:0\":{\"share\":\"$share_a\"}" "$temporary/otp.json"
check 'OTP output copies nested share 29:32' grep -Fq \
    "\"24:32\":{\"share\":\"$share_b\"}" "$temporary/otp.json"
check 'OTP output copies nested share 30:0' grep -Fq \
    "\"25:0\":{\"share\":\"$share_c\"}" "$temporary/otp.json"
check 'OTP output copies nested share 30:32' grep -Fq \
    "\"25:32\":{\"share\":\"$share_d\"}" "$temporary/otp.json"
for expected in '"PAGE24_LOCK1":"0x3d3d3d"' '"PAGE25_LOCK1":"0x3d3d3d"' \
    '"secure_boot_enable":1' '"key_invalid":254'; do
    check "OTP output contains $expected" grep -Fq "$expected" "$temporary/otp.json"
done

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 \
    -out "$temporary/host-private.pem" 2>/dev/null
chmod 600 "$temporary/host-private.pem"
openssl pkey -in "$temporary/host-private.pem" -pubout -outform DER \
    -out "$temporary/host-public.der"
tail -c 65 "$temporary/host-public.der" >"$temporary/host-public.raw"
touch "$temporary/empty"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 \
    -out "$temporary/other-private.pem" 2>/dev/null
chmod 600 "$temporary/other-private.pem"
"$temporary/pairing-harness" "$temporary/host-public.raw" "$temporary/empty" dump \
    >"$temporary/challenge.bin"
dd if=/dev/zero of="$temporary/response.bin" bs=64 count=1 status=none

sign_challenge() {
    local challenge_file=$1
    local key_file=$2
    local result_file=$3
    {
        printf 'HID-LAB-PAIR-v1\0'
        dd if="$challenge_file" bs=1 skip=2 count=40 status=none
    } >"$temporary/message.bin"
    openssl dgst -sha256 -sign "$key_file" -out "$temporary/signature.der" \
        "$temporary/message.bin" 2>/dev/null
    "$temporary/signature-convert" "$temporary/signature.der" "$result_file"
}

sign_challenge "$temporary/challenge.bin" "$temporary/host-private.pem" \
    "$temporary/response.bin"
check 'enrolled key authorises firmware gate' "$temporary/pairing-harness" \
    "$temporary/host-public.raw" "$temporary/response.bin" verify
sign_challenge "$temporary/challenge.bin" "$temporary/other-private.pem" \
    "$temporary/response.bin"
check 'wrong key is rejected' test "$("$temporary/pairing-harness" \
    "$temporary/host-public.raw" "$temporary/response.bin" verify)" = 0

for offset in 2 10; do
    cp "$temporary/challenge.bin" "$temporary/changed-challenge.bin"
    changed_byte=1
    if [[ "$offset" = 10 ]]; then
        changed_byte=2
    fi
    printf "\\$(printf '%03o' "$changed_byte")" \
        | dd of="$temporary/changed-challenge.bin" bs=1 seek="$offset" \
        conv=notrunc status=none
    sign_challenge "$temporary/changed-challenge.bin" "$temporary/host-private.pem" \
        "$temporary/response.bin"
    check "tampered challenge byte $offset is rejected" test \
        "$("$temporary/pairing-harness" "$temporary/host-public.raw" \
        "$temporary/response.bin" verify)" = 0
done
check 'short response is rejected' test "$("$temporary/pairing-harness" \
    "$temporary/host-public.raw" "$temporary/empty" verify)" = 0
dd if=/dev/zero of="$temporary/response.bin" bs=64 count=1 status=none
check 'invalid signature is rejected' test "$("$temporary/pairing-harness" \
    "$temporary/host-public.raw" "$temporary/response.bin" verify)" = 0
sign_challenge "$temporary/challenge.bin" "$temporary/host-private.pem" \
    "$temporary/response.bin"
check 'old response fails after reconnect' test "$("$temporary/pairing-harness" \
    "$temporary/host-public.raw" "$temporary/response.bin" reconnect)" = 0
old_nonce=$(dd if="$temporary/challenge.bin" bs=1 skip=10 count=32 status=none | od -An -tx1)
"$temporary/pairing-harness" "$temporary/host-public.raw" "$temporary/empty" \
    dump-reconnect >"$temporary/new-challenge.bin"
new_nonce=$(dd if="$temporary/new-challenge.bin" bs=1 skip=10 count=32 status=none | od -An -tx1)
check 'reconnect creates a fresh nonce' test "$old_nonce" != "$new_nonce"
sign_challenge "$temporary/new-challenge.bin" "$temporary/host-private.pem" \
    "$temporary/response.bin"
check 'fresh response authorises after reconnect' "$temporary/pairing-harness" \
    "$temporary/host-public.raw" "$temporary/response.bin" reconnect

mount="$temporary/HIDPAIR"
mkdir "$mount"
"$temporary/pairing-harness" "$temporary/host-public.raw" "$temporary/empty" dump \
    >"$mount/CHALLENG.BIN"
dd if=/dev/zero of="$mount/RESPONSE.BIN" bs=64 count=1 status=none
check 'C host agent submits proof through mounted files' "$temporary/pair-host" \
    --key "$temporary/host-private.pem" --mount "$mount"

# Simulate the board publishing a receipt after it receives each new signature.
for verdict in accepted rejected stale; do
    truncate -s 0 "$mount/RESPONSE.BIN"
    truncate -s 64 "$mount/RESPONSE.BIN"
    truncate -s 0 "$mount/STATUS.BIN"
    truncate -s 512 "$mount/STATUS.BIN"
    (
        for ((poll=0; poll<100; poll++)); do
            if ! cmp -s -n 64 "$mount/RESPONSE.BIN" /dev/zero; then break; fi
            sleep 0.01
        done
        if [[ "$verdict" == rejected ]]; then
            printf '\001\001\002\000\001\000\000\000'
        else
            printf '\001\002\001\000\001\000\000\000'
        fi
        if [[ "$verdict" == stale ]]; then head -c 32 /dev/zero
        else tail -c 32 "$mount/CHALLENG.BIN"; fi
        cat "$mount/RESPONSE.BIN"
        head -c 408 /dev/zero
    ) >"$temporary/receipt" &
    publisher=$!
    "$temporary/pair-host" --key "$temporary/host-private.pem" --mount "$mount" >"$temporary/journal" &
    observer=$!
    wait "$publisher"
    dd if="$temporary/receipt" of="$mount/STATUS.BIN" conv=notrunc,fsync status=none
    wait "$observer"
    if [[ "$verdict" == stale ]]; then
        check 'stale receipt produces no verdict' test "$(wc -l <"$temporary/journal")" = 1
    else
        check "journal reports $verdict" grep -Fxq "Board reports pairing proof $verdict" "$temporary/journal"
    fi
done

printf 'Completed %s C and Bash checks\n' "$pass_count"

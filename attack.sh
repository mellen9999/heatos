#!/bin/bash
# each check asserts an EXPECTED FAILURE. the harness fails if an attack works.
set -uo pipefail
cd "$(dirname "$0")"

has() { local n; n=$(grep -c -- "$1" || true); [ "${n:-0}" -gt 0 ]; }
pass=0; fail=0; skip=0; sections=0
# the gate runner already learned this: a run that dies partway through prints
# a smaller number and looks exactly like a clean one. count the attacks that
# actually ran and refuse to report a result if any of them went missing.
EXPECTED_SECTIONS=6
section() { sections=$((sections+1)); echo; echo "$1"; }

# production carries no test hook, so build a test-flavoured UKI for this run
# and restore the production one on the way out.
# unlock once into RAM; every subsequent sign reuses it, and we wipe on exit.
./build.sh unlock || { echo "cannot unlock signing keys"; exit 1; }
HEATOS_TEST=1 ./build.sh verity >/dev/null && ./build.sh uki >/dev/null
restore() {
	./build.sh verity >/dev/null 2>&1 && ./build.sh uki >/dev/null 2>&1
	./build.sh lock >/dev/null 2>&1
}
trap restore EXIT
ok()  { printf '  \033[1;32mPASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }
# a skip is never silence: it is counted and reported, because "9 passed" with
# an attack quietly not evaluated is the exact failure this harness exists to
# catch everywhere else.
skipped() { printf '  \033[1;33mSKIP\033[0m  %s\n' "$1"; skip=$((skip+1)); }

# boots the real chain: firmware -> enrolled key -> signed UKI -> verity root
boot_img() {
	timeout 90 qemu-system-x86_64 -machine q35,smm=on -m 256 \
		-global driver=cfi.pflash01,property=secure,value=on \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd \
		-drive if=pflash,format=raw,unit=1,file=ovmf-vars.fd \
		-drive file="$1",if=virtio,format=raw,readonly=on \
		-drive file=fat:esp,format=raw,if=virtio,readonly=on \
		-nographic -no-reboot < /dev/null 2>&1
}

echo
section "A1  flip one byte in the image -- boot must refuse"
cp heatos.img /tmp/heatos-a1.img
python3 -c "
import pathlib,sys
p=pathlib.Path('/tmp/heatos-a1.img'); b=bytearray(p.read_bytes()); b[100000]^=1; p.write_bytes(bytes(b))"
out=$(boot_img /tmp/heatos-a1.img)
# verity detects lazily, when the block is actually read, so the machine may
# execute briefly first. what must be true is that it dies rather than
# continuing -- panic_on_corruption makes that unconditional.
if grep -q 'is corrupted' <<< "$out" && grep -q 'dm-verity device corrupted' <<< "$out"; then
	ok "verity panicked the kernel on one flipped bit"
else
	bad "corrupted image did not panic (verity error present: $(grep -c 'is corrupted' <<< "$out"))"
fi
rm -f /tmp/heatos-a1.img

echo
section "A2  clean image -- must boot, and root must be unwritable"
out=$(boot_img heatos.img)
grep -qi 'secure boot is enabled' <<< "$out" && ok "secure boot was enforcing during the run" || bad "secure boot not enabled"
grep -q 'write-to-root: refused' <<< "$out" && ok "write to / returned EROFS" || bad "root was writable"
grep -q 'busybox-runs: yes'      <<< "$out" && ok "userland actually executes"  || bad "userland did not run"

echo
section "A3  unsigned UKI -- firmware must refuse it"
cp heatos.efi esp/EFI/BOOT/BOOTX64.EFI
o3=$(boot_img heatos.img)
if grep -q HEATOS-TEST-BEGIN <<< "$o3"; then
	bad "unsigned kernel booted -- secure boot is not enforcing"
else
	grep -qi 'access denied' <<< "$o3" && ok "firmware rejected the unsigned image" \
		|| bad "unsigned image did not boot, but not visibly refused by secure boot"
fi

echo
section "A4  tamper the signed UKI -- signature must break"
cp heatos-signed.efi /tmp/heatos-a4.efi
python3 -c "
import pathlib
p=pathlib.Path('/tmp/heatos-a4.efi'); b=bytearray(p.read_bytes()); b[len(b)//2]^=1; p.write_bytes(bytes(b))"
sbverify --cert keys/db.crt /tmp/heatos-a4.efi >/dev/null 2>&1 \
	&& bad "tampered UKI still verified" || ok "one flipped bit invalidates the signature"
cp /tmp/heatos-a4.efi esp/EFI/BOOT/BOOTX64.EFI
o4=$(boot_img heatos.img)
grep -q HEATOS-TEST-BEGIN <<< "$o4" && bad "tampered UKI booted" || ok "firmware refused the tampered image"
rm -f /tmp/heatos-a4.efi
cp heatos-signed.efi esp/EFI/BOOT/BOOTX64.EFI

echo
section "A5  no dynamic loader to hijack"
if [ -z "$(find root -name 'ld-musl-*' -o -name 'ld-linux*' 2>/dev/null)" ]; then
	ok "no ld-musl/ld-linux in the image (LD_PRELOAD has nothing to load)"
else
	bad "a dynamic loader is present"
fi
grep -q 'dynamic-loader-present: no' <<< "$out" && ok "confirmed absent from inside the booted system" || bad "loader present at runtime"

echo
section "A6  TLS must refuse a certificate outside our trust anchors"
if ! printf 'HEAD / HTTP/1.0\r\nHost: letsencrypt.org\r\nConnection: close\r\n\r\n' \
     | timeout 20 ./tlstunnel - letsencrypt.org 443 2>/dev/null | has 'HTTP/1'; then
	skipped "no network -- A6 not evaluated"
else
	ok "trusted CA: handshake with letsencrypt.org succeeded"
	err=$({ printf 'HEAD / HTTP/1.0\r\nHost: google.com\r\n\r\n' | timeout 20 ./tlstunnel - google.com 443 2>&1 >/dev/null; } || true)
	case "$err" in
		*"ssl error 62"*) ok "untrusted CA refused (BR_ERR_X509_NOT_TRUSTED)" ;;
		*)                bad "a cert outside trust/ was not refused: ${err:-no error}" ;;
	esac
fi

echo
printf '  %d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
if [ "$sections" -ne "$EXPECTED_SECTIONS" ]; then
	printf '\033[1;31m  only %d of %d attacks ran -- the harness was truncated\033[0m\n\n' \
		"$sections" "$EXPECTED_SECTIONS"
	exit 1
fi
echo
[ "$fail" -eq 0 ]

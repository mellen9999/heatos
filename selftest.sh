#!/bin/bash
# defensive self-test. boots vrl in a throwaway qemu vm and asserts its own
# tamper-detection refuses every alteration -- no external target, no secrets,
# no network exploit. each check asserts an EXPECTED FAILURE: the harness fails
# if a tampered image is accepted.
set -uo pipefail
cd "$(dirname "$0")"

has() { local n; n=$(grep -c -- "$1" || true); [ "${n:-0}" -gt 0 ]; }
SBGUID_T=11111111-2222-3333-4444-555555555555
pass=0; fail=0; skip=0; sections=0
# the gate runner already learned this: a run that dies partway through prints
# a smaller number and looks exactly like a clean one. count the checks that
# actually ran and refuse to report a result if any of them went missing.
EXPECTED_SECTIONS=11
section() { sections=$((sections+1)); echo; echo "$1"; }

# p2 (root) starts after the 1 MiB gap + the ESP. keep in step with build.sh
# STICK_ESP_MIB (64). the whole stick is what boots on real hardware, so the
# harness attacks the stick, not the bare vrl.img.
ROOT_OFF=$(( (1 + 64) * 1024 * 1024 ))

# production carries no test hook, so build a test-flavoured UKI + stick for this
# run and restore the production ones on the way out.
# unlock once into RAM; every subsequent sign reuses it, and we wipe on exit.
./build.sh unlock || { echo "cannot unlock signing keys"; exit 1; }
# uki rebuilds ovmf-vars.fd from the pristine OVMF template, so restore() also
# discards the throwaway dbx entry A11 enrolls into firmware.
VRL_TEST=1 ./build.sh verity >/dev/null && ./build.sh uki >/dev/null && ./build.sh stick >/dev/null
restore() {
	./build.sh verity >/dev/null 2>&1 && ./build.sh uki >/dev/null 2>&1 && ./build.sh stick >/dev/null 2>&1
	./build.sh lock >/dev/null 2>&1
	rm -f /tmp/vrl-a*.img /tmp/vrl-a*.efi
}
trap restore EXIT
ok()  { printf '  \033[1;32mPASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }
# a skip is never silence: it is counted and reported, because "9 passed" with
# a check quietly not evaluated is the exact failure this harness exists to
# catch everywhere else.
skipped() { printf '  \033[1;33mSKIP\033[0m  %s\n' "$1"; skip=$((skip+1)); }

# boots the real chain over VIRTIO: firmware -> enrolled key -> signed UKI ->
# verity root resolved by PARTUUID off the stick's p2.
boot_img() {
	timeout 120 qemu-system-x86_64 -machine q35,smm=on -m 256 \
		-global driver=cfi.pflash01,property=secure,value=on \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd \
		-drive if=pflash,format=raw,unit=1,file=ovmf-vars.fd \
		-drive file="$1",if=virtio,format=raw,readonly=on \
		-nic user,model=virtio-net-pci \
		-nographic -no-reboot < /dev/null 2>&1
}

# same chain but over an emulated xHCI USB mass-storage device -- the real
# hardware path, including usb enumeration and the dm-mod.waitfor poll.
boot_usb() {
	timeout 120 qemu-system-x86_64 -machine q35,smm=on -m 256 \
		-global driver=cfi.pflash01,property=secure,value=on \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd \
		-drive if=pflash,format=raw,unit=1,file=ovmf-vars.fd \
		-device qemu-xhci,id=xhci \
		-drive if=none,id=stick,format=raw,readonly=on,file="$1" \
		-device usb-storage,bus=xhci.0,drive=stick \
		-nic user,model=virtio-net-pci \
		-nographic -no-reboot < /dev/null 2>&1
}

flip() { python3 -c "import pathlib;p=pathlib.Path('$1');b=bytearray(p.read_bytes());b[$2]^=1;p.write_bytes(bytes(b))"; }

echo
section "A1  flip one byte in the root filesystem -- boot must refuse"
cp stick.img /tmp/vrl-a1.img
flip /tmp/vrl-a1.img $((ROOT_OFF + 100000))
out=$(boot_img /tmp/vrl-a1.img)
# verity detects lazily, when the block is actually read, so the machine may
# execute briefly first. what must be true is that it dies rather than
# continuing -- panic_on_corruption makes that unconditional.
if grep -q 'is corrupted' <<< "$out" && grep -q 'dm-verity device corrupted' <<< "$out"; then
	ok "verity panicked the kernel on one flipped bit"
else
	bad "corrupted image did not panic (verity error present: $(grep -c 'is corrupted' <<< "$out"))"
fi
rm -f /tmp/vrl-a1.img

echo
section "A2  clean stick -- must boot, and root must be unwritable"
out=$(boot_img stick.img)
grep -qi 'secure boot is enabled' <<< "$out" && ok "secure boot was enforcing during the run" || bad "secure boot not enabled"
grep -q 'write-to-root: refused' <<< "$out" && ok "write to / returned EROFS" || bad "root was writable"
grep -q 'busybox-runs: yes'      <<< "$out" && ok "userland actually executes"  || bad "userland did not run"

echo
section "A3  unsigned UKI -- firmware must refuse it"
cp stick.img /tmp/vrl-a3.img
mcopy -o -i /tmp/vrl-a3.img@@1M vrl.efi ::/EFI/BOOT/BOOTX64.EFI
o3=$(boot_img /tmp/vrl-a3.img)
if grep -q VRL-TEST-BEGIN <<< "$o3"; then
	bad "unsigned kernel booted -- secure boot is not enforcing"
else
	grep -qi 'access denied' <<< "$o3" && ok "firmware rejected the unsigned image" \
		|| bad "unsigned image did not boot, but not visibly refused by secure boot"
fi
rm -f /tmp/vrl-a3.img

echo
section "A4  tamper the signed UKI -- signature must break"
cp vrl-signed.efi /tmp/vrl-a4.efi
flip /tmp/vrl-a4.efi $(( $(stat -c%s vrl-signed.efi) / 2 ))
sbverify --cert keys/db.crt /tmp/vrl-a4.efi >/dev/null 2>&1 \
	&& bad "tampered UKI still verified" || ok "one flipped bit invalidates the signature"
cp stick.img /tmp/vrl-a4.img
mcopy -o -i /tmp/vrl-a4.img@@1M /tmp/vrl-a4.efi ::/EFI/BOOT/BOOTX64.EFI
o4=$(boot_img /tmp/vrl-a4.img)
grep -q VRL-TEST-BEGIN <<< "$o4" && bad "tampered UKI booted" || ok "firmware refused the tampered image"
rm -f /tmp/vrl-a4.efi /tmp/vrl-a4.img

echo
section "A5  no dynamic loader to preload into"
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
section "A7  flip a byte in the verity HASH TREE -- boot must refuse"
# the data region is covered by the tree; the tree itself must be covered too,
# or an attacker could rewrite data + recompute the tree. flip the first hash
# block (one past the superblock at data-end). the superblock block itself is
# NOT covered -- dm-mod.create ignores it -- which is the one honest gap here.
blocks=$(grep -oE '4096 4096 [0-9]+ [0-9]+' cmdline.txt | head -1 | awk '{print $3}')
if [ -n "${blocks:-}" ]; then
	cp stick.img /tmp/vrl-a7.img
	flip /tmp/vrl-a7.img $((ROOT_OFF + (blocks + 1) * 4096 + 16))
	o7=$(boot_img /tmp/vrl-a7.img)
	grep -q 'dm-verity device corrupted' <<< "$o7" && ok "hash-tree corruption panicked the kernel" \
		|| bad "a flipped hash-tree byte did not panic"
	rm -f /tmp/vrl-a7.img
else
	bad "could not parse data-block count from cmdline.txt"
fi

echo
section "A8  kernel attack surface is closed"
# reuses A2's clean boot output ($out); every line is a deterministic init probe.
grep -q 'devmem-node: absent'  <<< "$out" && ok "/dev/mem absent"          || bad "/dev/mem present"
grep -q 'kcore: absent'        <<< "$out" && ok "/proc/kcore absent"       || bad "/proc/kcore present"
grep -q 'kexec-loaded: absent' <<< "$out" && ok "kexec unavailable"        || bad "kexec present"
grep -q 'vsyscall-map: 0'      <<< "$out" && ok "no fixed vsyscall page"   || bad "vsyscall page mapped"
grep -q 'lockdown: .*\[confidentiality\]' <<< "$out" && ok "lockdown=confidentiality enforced" || bad "lockdown not in confidentiality mode"

echo
section "A9  write / exec containment"
grep -q 'remount-rw: refused' <<< "$out" && ok "/ cannot be remounted rw"      || bad "/ was remounted rw"
grep -q 'tmp-exec: refused'   <<< "$out" && ok "noexec /tmp blocks execution"  || bad "a binary ran from /tmp"
grep -q 'kptr-restrict: 2'    <<< "$out" && ok "kernel pointers restricted"    || bad "kptr_restrict not 2"

echo
section "A10  boot the stick over emulated USB (the real hardware path)"
o10=$(boot_usb stick.img)
if grep -q VRL-TEST-BEGIN <<< "$o10"; then
	ok "booted from usb-storage via dm-mod.waitfor"
	grep -qi 'secure boot is enabled' <<< "$o10" && ok "secure boot enforcing over USB" || bad "secure boot not enabled over USB"
	grep -q 'write-to-root: refused'  <<< "$o10" && ok "root unwritable over USB"       || bad "root writable over USB"
else
	bad "stick did not boot over emulated USB (waitfor may have timed out)"
fi

echo
section "A11  a superseded but validly-signed image must be refused"
# secure boot checks WHO signed an image, never WHEN. without revocation an old
# release stays bootable forever: drop it on the ESP -- plain FAT, because
# something has to boot -- and the firmware runs it, signature valid, every gate
# green. this asserts dbx actually closes that.
stub=/usr/lib/systemd/boot/efi/linuxx64.efi.stub
R=$(./build.sh ramkeys)
if [ ! -f "$stub" ] || [ ! -f "$R/db.key" ]; then
	skipped "no stub or unlocked key -- A11 not evaluated"
else
	ukify build --linux=bzImage --cmdline="$(cat cmdline.txt) vrl.rel=old" \
		--stub="$stub" --output=/tmp/vrl-a11.efi >/dev/null 2>&1
	sbsign --key "$R/db.key" --cert keys/db.crt \
		--output /tmp/vrl-a11-signed.efi /tmp/vrl-a11.efi >/dev/null 2>&1
	if ! sbverify --cert keys/db.crt /tmp/vrl-a11-signed.efi >/dev/null 2>&1; then
		bad "could not build a validly-signed superseded image to test with"
	else
		ok "the superseded image is validly signed by db"
		h=$(python3 pehash.py --verify /tmp/vrl-a11-signed.efi) \
			&& ok "authenticode digest agrees with its own signature" \
			|| bad "pehash.py disagrees with the signature -- dbx would revoke nothing"
		# revoke it in firmware only; the tracked `revoked` file is untouched.
		virt-fw-vars --input ovmf-vars.fd --output ovmf-vars.fd \
			--add-dbx-hash "$SBGUID_T" "$h" >/dev/null 2>&1 \
			|| bad "could not enroll the test revocation into dbx"
		# drop the revoked image into a copy of the stick's ESP and boot that
		cp stick.img /tmp/vrl-a11.img
		mcopy -o -i /tmp/vrl-a11.img@@1M /tmp/vrl-a11-signed.efi ::/EFI/BOOT/BOOTX64.EFI
		o11=$(boot_img /tmp/vrl-a11.img)
		if grep -q VRL-TEST-BEGIN <<< "$o11"; then
			bad "a revoked image still booted -- dbx is not being enforced"
		else
			has_denied=$(grep -ic 'access denied\|security violation' <<< "$o11" || true)
			[ "${has_denied:-0}" -gt 0 ] \
				&& ok "firmware refused the revoked image" \
				|| bad "revoked image did not boot, but not visibly refused by dbx"
		fi
		# revocation must not have collaterally killed the good image
		o11b=$(boot_img stick.img)
		grep -q VRL-TEST-BEGIN <<< "$o11b" \
			&& ok "the current image still boots with dbx enrolled" \
			|| bad "dbx enrollment broke the image we actually ship"
	fi
	rm -f /tmp/vrl-a11.efi /tmp/vrl-a11-signed.efi /tmp/vrl-a11.img
fi

printf '  %d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
if [ "$sections" -ne "$EXPECTED_SECTIONS" ]; then
	printf '\033[1;31m  only %d of %d checks ran -- the harness was truncated\033[0m\n\n' \
		"$sections" "$EXPECTED_SECTIONS"
	exit 1
fi
echo
[ "$fail" -eq 0 ]

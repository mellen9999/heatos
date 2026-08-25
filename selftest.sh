#!/bin/bash
# defensive self-test. boots vos in a throwaway qemu vm and asserts its own
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
EXPECTED_SECTIONS=14
section() { sections=$((sections+1)); echo; echo "$1"; }

# p2 (root) starts after the 1 MiB gap + the ESP. keep in step with build.sh
# STICK_ESP_MIB (64). the whole stick is what boots on real hardware, so the
# harness attacks the stick, not the bare vos.img.
ROOT_OFF=$(( (1 + 64) * 1024 * 1024 ))

# production carries no test hook, so build a test-flavoured UKI + stick for this
# run and restore the production ones on the way out.
# unlock once into RAM; every subsequent sign reuses it, and we wipe on exit.
./build.sh unlock || { echo "cannot unlock signing keys"; exit 1; }
# uki rebuilds ovmf-vars.fd from the pristine OVMF template, so restore() also
# discards the throwaway dbx entry A11 enrolls into firmware.
VOS_TEST=1 ./build.sh verity >/dev/null && ./build.sh uki >/dev/null && ./build.sh stick >/dev/null
restore() {
	./build.sh verity >/dev/null 2>&1 && ./build.sh uki >/dev/null 2>&1 && ./build.sh stick >/dev/null 2>&1
	./build.sh lock >/dev/null 2>&1
	rm -f /tmp/vos-a*.img /tmp/vos-a*.efi
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
cp stick.img /tmp/vos-a1.img
flip /tmp/vos-a1.img $((ROOT_OFF + 100000))
out=$(boot_img /tmp/vos-a1.img)
# verity detects lazily, when the block is actually read, so the machine may
# execute briefly first. what must be true is that it dies rather than
# continuing -- panic_on_corruption makes that unconditional.
if grep -q 'is corrupted' <<< "$out" && grep -q 'dm-verity device corrupted' <<< "$out"; then
	ok "verity panicked the kernel on one flipped bit"
else
	bad "corrupted image did not panic (verity error present: $(grep -c 'is corrupted' <<< "$out"))"
fi
rm -f /tmp/vos-a1.img

echo
section "A2  clean stick -- must boot, and root must be unwritable"
out=$(boot_img stick.img)
grep -qi 'secure boot is enabled' <<< "$out" && ok "secure boot was enforcing during the run" || bad "secure boot not enabled"
grep -q 'write-to-root: refused' <<< "$out" && ok "write to / returned EROFS" || bad "root was writable"
grep -q 'busybox-runs: yes'      <<< "$out" && ok "userland actually executes"  || bad "userland did not run"

echo
section "A3  unsigned UKI -- firmware must refuse it"
cp stick.img /tmp/vos-a3.img
mcopy -o -i /tmp/vos-a3.img@@1M vos.efi ::/EFI/BOOT/BOOTX64.EFI
o3=$(boot_img /tmp/vos-a3.img)
if grep -q VOS-TEST-BEGIN <<< "$o3"; then
	bad "unsigned kernel booted -- secure boot is not enforcing"
else
	grep -qi 'access denied' <<< "$o3" && ok "firmware rejected the unsigned image" \
		|| bad "unsigned image did not boot, but not visibly refused by secure boot"
fi
rm -f /tmp/vos-a3.img

echo
section "A4  tamper the signed UKI -- signature must break"
cp vos-signed.efi /tmp/vos-a4.efi
flip /tmp/vos-a4.efi $(( $(stat -c%s vos-signed.efi) / 2 ))
sbverify --cert keys/db.crt /tmp/vos-a4.efi >/dev/null 2>&1 \
	&& bad "tampered UKI still verified" || ok "one flipped bit invalidates the signature"
cp stick.img /tmp/vos-a4.img
mcopy -o -i /tmp/vos-a4.img@@1M /tmp/vos-a4.efi ::/EFI/BOOT/BOOTX64.EFI
o4=$(boot_img /tmp/vos-a4.img)
grep -q VOS-TEST-BEGIN <<< "$o4" && bad "tampered UKI booted" || ok "firmware refused the tampered image"
rm -f /tmp/vos-a4.efi /tmp/vos-a4.img

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
	cp stick.img /tmp/vos-a7.img
	flip /tmp/vos-a7.img $((ROOT_OFF + (blocks + 1) * 4096 + 16))
	o7=$(boot_img /tmp/vos-a7.img)
	grep -q 'dm-verity device corrupted' <<< "$o7" && ok "hash-tree corruption panicked the kernel" \
		|| bad "a flipped hash-tree byte did not panic"
	rm -f /tmp/vos-a7.img
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
if grep -q VOS-TEST-BEGIN <<< "$o10"; then
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
	ukify build --linux=bzImage --cmdline="$(cat cmdline.txt) vos.rel=old" \
		--stub="$stub" --output=/tmp/vos-a11.efi >/dev/null 2>&1
	sbsign --key "$R/db.key" --cert keys/db.crt \
		--output /tmp/vos-a11-signed.efi /tmp/vos-a11.efi >/dev/null 2>&1
	if ! sbverify --cert keys/db.crt /tmp/vos-a11-signed.efi >/dev/null 2>&1; then
		bad "could not build a validly-signed superseded image to test with"
	else
		ok "the superseded image is validly signed by db"
		h=$(python3 pehash.py --verify /tmp/vos-a11-signed.efi) \
			&& ok "authenticode digest agrees with its own signature" \
			|| bad "pehash.py disagrees with the signature -- dbx would revoke nothing"
		# revoke it in firmware only; the tracked `revoked` file is untouched.
		virt-fw-vars --input ovmf-vars.fd --output ovmf-vars.fd \
			--add-dbx-hash "$SBGUID_T" "$h" >/dev/null 2>&1 \
			|| bad "could not enroll the test revocation into dbx"
		# drop the revoked image into a copy of the stick's ESP and boot that
		cp stick.img /tmp/vos-a11.img
		mcopy -o -i /tmp/vos-a11.img@@1M /tmp/vos-a11-signed.efi ::/EFI/BOOT/BOOTX64.EFI
		o11=$(boot_img /tmp/vos-a11.img)
		if grep -q VOS-TEST-BEGIN <<< "$o11"; then
			bad "a revoked image still booted -- dbx is not being enforced"
		else
			has_denied=$(grep -ic 'access denied\|security violation' <<< "$o11" || true)
			[ "${has_denied:-0}" -gt 0 ] \
				&& ok "firmware refused the revoked image" \
				|| bad "revoked image did not boot, but not visibly refused by dbx"
		fi
		# revocation must not have collaterally killed the good image
		o11b=$(boot_img stick.img)
		grep -q VOS-TEST-BEGIN <<< "$o11b" \
			&& ok "the current image still boots with dbx enrolled" \
			|| bad "dbx enrollment broke the image we actually ship"
	fi
	rm -f /tmp/vos-a11.efi /tmp/vos-a11-signed.efi /tmp/vos-a11.img
fi

echo
section "A12  learn describes the system that is actually running"
# G24 checks the corpus against the BUILD TREE. this checks it against reality:
# a ref that names a command the booted system does not have is a lie the build
# cannot see, and the whole point of learn is that its questions are answerable
# on the stick, offline.
grep -q 'no-bash: absent' <<< "$out" && ok "bash is gone -- one shell" || bad "a second shell shipped"
refs=$(grep -oP 'learn-refs: \K[0-9]+' <<< "$out" | head -1)
runs=$(grep -oP 'learn-runs: \K[0-9]+' <<< "$out" | head -1)
if [ "${refs:-0}" -gt 0 ] && [ "${refs:-0}" = "${runs:-x}" ]; then
	ok "learn lists all $refs corpus entries from inside the booted system"
else
	bad "learn corpus unreadable at runtime (refs=${refs:-?} listed=${runs:-?})"
fi
grep -q 'learn-ref-ls: MISSING' <<< "$out" \
	&& bad "learn ref ls returned nothing -- the manpage substitute is empty" \
	|| ok "learn ref resolves an entry at runtime"
les=$(grep -oP 'learn-levels: \K[0-9]+' <<< "$out" | head -1)
pls=$(grep -oP 'learn-pools: \K[0-9]+' <<< "$out" | head -1)
[ "${les:-0}" -gt 0 ] && ok "curriculum present in the image ($les levels)" \
	|| bad "no levels in the booted image"
# the pools are what the question generator rolls against. without them every
# question renders with %placeholders% still in it.
[ "${pls:-0}" -gt 0 ] && ok "generator pools present ($pls)" \
	|| bad "no pools in the booted image -- questions cannot render"

echo
section "A13  a session outlives the terminal that started it"
# the whole point of shipping abduco. these probes come from a boot where NOTHING
# was attached to the session -- stdin was /dev/null -- so a listed session with a
# living child is proof the program is owned by abduco and not by a terminal.
grep -q 'devpts-mounted: devpts' <<< "$out" && ok "devpts is mounted" \
	|| bad "no devpts -- nothing can allocate a terminal"
grep -q 'pty-alloc: ok' <<< "$out" && ok "a pty can actually be allocated" \
	|| bad "pty allocation failed"
grep -q 'legacy-ptys: absent' <<< "$out" && ok "the obsolete pty interface is gone" \
	|| bad "legacy ptys are compiled in"
grep -q 'abduco-runs: yes' <<< "$out" && ok "abduco runs in the image" \
	|| bad "abduco missing or broken"
grep -q 'abduco-session-listed: yes' <<< "$out" \
	&& ok "a detached session survives with no terminal attached" \
	|| bad "the detached session vanished"
grep -q 'abduco-child-alive: yes' <<< "$out" \
	&& ok "the detached program kept running and produced output" \
	|| bad "the detached program did not run"
tty_n=$(grep -oP 'ttys-spawned: \K[0-9]+' <<< "$out" | head -1)
[ "${tty_n:-0}" -ge 2 ] && ok "$tty_n virtual terminals spawned" \
	|| bad "only ${tty_n:-0} virtual terminals"
# PID 1 used to BE the shell, so a shell exiting was a kernel panic.
grep -q 'Kernel panic' <<< "$out" && bad "the boot panicked" \
	|| ok "PID 1 survived every console session"

echo
section "A14  state can be encrypted AND authenticated"
# p3's whole reason for existing. encryption alone gives confidentiality: an
# attacker cannot read it. it does not stop them CHANGING it -- decrypting
# tampered ciphertext yields attacker-controlled garbage the filesystem parses
# as root. --integrity makes tampering refused instead, which is the same
# fail-closed property verity gives the read-only root.
grep -q 'flock-works: yes' <<< "$out" && ok "file locking works" \
	|| bad "flock() is ENOSYS -- cryptsetup cannot lock, and the flock applet is a lie"
grep -q 'cryptsetup-runs: yes' <<< "$out" \
	&& ok "cryptsetup runs, using the kernel crypto backend" \
	|| bad "cryptsetup missing, or linked against a crypto library instead of the kernel"
grep -q 'luks-format: ok' <<< "$out" && ok "a LUKS2 volume can be created with integrity" \
	|| bad "luksFormat failed"
grep -q 'luks-open: ok' <<< "$out" && ok "it unlocks with the right passphrase" \
	|| bad "luksOpen failed"
grep -q 'luks-integrity-active: integrity: hmac' <<< "$out" \
	&& ok "the opened volume really is authenticated, not merely encrypted" \
	|| bad "no integrity on the opened volume -- encryption without authentication"
grep -q 'luks-wrong-pass-refused: refused' <<< "$out" \
	&& ok "the wrong passphrase is refused" || bad "a wrong passphrase opened the volume"
grep -q 'fs-ext4: yes' <<< "$out" && ok "ext4 is available for the state filesystem" || bad "no ext4"
grep -q 'fs-vfat: yes' <<< "$out" && ok "vfat is available, so removable media can be mounted" || bad "no vfat"
grep -q 'entropy-trusted: random.trust_cpu=1' <<< "$out" \
	&& ok "the entropy source is pinned on the signed cmdline" \
	|| bad "random.trust_cpu is not pinned -- keys may be generated on a thin pool"

printf '  %d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
if [ "$sections" -ne "$EXPECTED_SECTIONS" ]; then
	printf '\033[1;31m  only %d of %d checks ran -- the harness was truncated\033[0m\n\n' \
		"$sections" "$EXPECTED_SECTIONS"
	exit 1
fi
echo
[ "$fail" -eq 0 ]

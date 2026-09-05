#!/bin/bash
# defensive self-test. boots xos in a throwaway qemu vm and asserts its own
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
EXPECTED_SECTIONS=19
section() { sections=$((sections+1)); echo; echo "$1"; }

# p2 (root) starts after the 1 MiB gap + the ESP. keep in step with build.sh
# STICK_ESP_MIB (64). the whole stick is what boots on real hardware, so the
# harness attacks the stick, not the bare xos.img.
ROOT_OFF=$(( (1 + 64) * 1024 * 1024 ))

# production carries no test hook, so build a test-flavoured UKI + stick for this
# run and restore the production ones on the way out.
# unlock once into RAM; every subsequent sign reuses it, and we wipe on exit.
./build.sh unlock || { echo "cannot unlock signing keys"; exit 1; }
# uki rebuilds ovmf-vars.fd from the pristine OVMF template, so restore() also
# discards the throwaway dbx entry A11 enrolls into firmware.
XOS_TEST=1 ./build.sh verity >/dev/null && ./build.sh uki >/dev/null && ./build.sh stick >/dev/null \
	|| { echo "cannot build test uki/stick"; exit 1; }
# restore is the EXIT trap: if it fails partway, the tree can be left holding
# a TEST uki/stick -- xos.test xos.teststate xos.testwg on a cmdline that must
# never ship. that failure must be impossible to miss, so check every step and
# make noise (and a nonzero exit) rather than silently leaving debug scaffolding
# in place for build.sh's own G31 to (hopefully) catch on the next run.
restore() {
	if ! ./build.sh verity >/dev/null 2>&1 || ! ./build.sh uki >/dev/null 2>&1 || ! ./build.sh stick >/dev/null 2>&1; then
		printf '\033[1;31m  RESTORE FAILED -- the tree may still hold a TEST uki/stick (xos.test xos.teststate xos.testwg). rebuild before shipping anything.\033[0m\n' >&2
		./build.sh lock >/dev/null 2>&1
		rm -f /tmp/xos-a*.img /tmp/xos-a*.efi
		exit 1
	fi
	./build.sh lock >/dev/null 2>&1
	rm -f /tmp/xos-a*.img /tmp/xos-a*.efi
}
trap restore EXIT
ok()  { printf '  \033[1;32mPASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }
# a skip is never silence: it is counted and reported, because "9 passed" with
# a check quietly not evaluated is the exact failure this harness exists to
# catch everywhere else.
skipped() { printf '  \033[1;33mSKIP\033[0m  %s\n' "$1"; skip=$((skip+1)); }

# init prints XOS-TEST-END once the whole probe block finished and
# XOS-TEST-DONE once the console supervisor is up too -- the same
# did-everything-run guard this harness already applies to itself
# (EXPECTED_SECTIONS/EXPECTED_GATES), applied to a single boot's output. a
# probe block that dies partway (a hang, a crash) must not look like a clean
# run just because every check that DID print happened to pass. only call
# this for a boot that is expected to reach the end -- never for an
# adversarial boot that is supposed to be refused before it gets there.
assert_complete() {
	if grep -q 'XOS-TEST-END' <<< "$1" && grep -q 'XOS-TEST-DONE' <<< "$1"; then
		ok "$2: probe run reached XOS-TEST-END and XOS-TEST-DONE"
	else
		bad "$2: probe run did not complete (missing END and/or DONE -- truncated)"
	fi
}

# boots the real chain over VIRTIO: firmware -> enrolled key -> signed UKI ->
# verity root resolved by PARTUUID off the stick's p2.
boot_img() {
	timeout 360 qemu-system-x86_64 -machine q35,smm=on -m 512 \
		-global driver=cfi.pflash01,property=secure,value=on \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd \
		-drive if=pflash,format=raw,unit=1,file=ovmf-vars.fd \
		-drive file="$1",if=virtio,format=raw,readonly=on \
		-nic user,model=virtio-net-pci \
		-nographic -no-reboot < /dev/null 2>&1
}

# same chain but over an emulated xHCI USB mass-storage device -- the real
# hardware path, including usb enumeration and the dm-mod.waitfor poll.
# boot with a second virtio disk attached (becomes /dev/vdb), for the p3 test.
boot_state() {
	local disk="$1"; shift
	timeout 360 qemu-system-x86_64 -machine q35,smm=on -m 512 \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd \
		-drive if=pflash,format=raw,unit=1,file=ovmf-vars.fd \
		-drive file=stick.img,if=virtio,format=raw,readonly=on \
		-drive file="$disk",if=virtio,format=raw \
		-nic user,model=virtio-net-pci -nographic -no-reboot "$@" < /dev/null 2>&1
}

# boot with the hardware clock forced years into the past. proves the floor.
boot_backclock() {
	timeout 360 qemu-system-x86_64 -machine q35,smm=on -m 512 \
		-rtc base=2010-01-01T00:00:00 \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd \
		-drive if=pflash,format=raw,unit=1,file=ovmf-vars.fd \
		-drive file="$1",if=virtio,format=raw,readonly=on \
		-nic user,model=virtio-net-pci -nographic -no-reboot < /dev/null 2>&1
}

boot_usb() {
	timeout 360 qemu-system-x86_64 -machine q35,smm=on -m 512 \
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
cp stick.img /tmp/xos-a1.img
flip /tmp/xos-a1.img $((ROOT_OFF + 100000))
out=$(boot_img /tmp/xos-a1.img)
# verity detects lazily, when the block is actually read, so the machine may
# execute briefly first. what must be true is that it dies rather than
# continuing -- panic_on_corruption makes that unconditional.
if grep -q 'is corrupted' <<< "$out" && grep -q 'dm-verity device corrupted' <<< "$out"; then
	ok "verity panicked the kernel on one flipped bit"
else
	bad "corrupted image did not panic (verity error present: $(grep -c 'is corrupted' <<< "$out"))"
fi
rm -f /tmp/xos-a1.img

echo
section "A2  clean stick -- must boot, and root must be unwritable"
out=$(boot_img stick.img)
grep -qi 'secure boot is enabled' <<< "$out" && ok "secure boot was enforcing during the run" || bad "secure boot not enabled"
grep -q 'write-to-root: refused' <<< "$out" && ok "write to / returned EROFS" || bad "root was writable"
grep -q 'busybox-runs: yes'      <<< "$out" && ok "userland actually executes"  || bad "userland did not run"
grep -q 'rootfs-type: squashfs' <<< "$out" && ok "root is mounted as squashfs" || bad "root filesystem type is not squashfs"
grep -q 'rootfs-flags: ro'      <<< "$out" && ok "root mount flags include ro" || bad "root not mounted ro"
# the strongest self-statement init makes about itself, checked against
# sources that live OUTSIDE the booted system -- the squashfs on disk and the
# roothash build.sh just wrote for this run -- not anything the image could
# have lied about from the inside. dm-0 exposes xos.img's data region, and
# verity() zero-pads that to a 4096 boundary before hashing it (see build.sh),
# so replicate the same padding here rather than hashing rootfs.squashfs raw --
# otherwise an unaligned squashfs size makes this fail for no real reason.
sqsz=$(stat -c%s rootfs.squashfs)
padsz=$(( (4096 - sqsz % 4096) % 4096 ))
if [ "$padsz" -eq 0 ]; then
	want_digest=$(sha256sum rootfs.squashfs | cut -d' ' -f1)
else
	want_digest=$( { cat rootfs.squashfs; head -c "$padsz" /dev/zero; } | sha256sum | cut -d' ' -f1)
fi
got_digest=$(grep -oP 'rootfs-digest: \K[0-9a-f]+' <<< "$out" | head -1)
[ -n "$got_digest" ] && [ "$got_digest" = "$want_digest" ] \
	&& ok "rootfs-digest (hashed live through dm-verity) matches rootfs.squashfs" \
	|| bad "rootfs-digest mismatch (got ${got_digest:-none}, want $want_digest)"
want_rh=$(cat verity.roothash 2>/dev/null)
got_rh=$(grep -oP 'verity-roothash: \K[0-9a-f]+' <<< "$out" | head -1)
[ -n "$got_rh" ] && [ "$got_rh" = "$want_rh" ] \
	&& ok "verity-roothash on the signed cmdline matches verity.roothash" \
	|| bad "verity-roothash mismatch (got ${got_rh:-none}, want ${want_rh:-none})"
grep -q 'verity-onerror: panic_on_corruption' <<< "$out" \
	&& ok "verity is set to panic on corruption, not merely warn" \
	|| bad "verity onerror is not panic_on_corruption"
# networking: qemu's usermode nic + built-in dhcp server, no real internet needed.
grep -q 'net-iface-up: none' <<< "$out" \
	&& bad "no network interface came up" \
	|| ok "a network interface came up"
grep -q 'net-has-address: yes' <<< "$out" && ok "dhcp lease obtained" || bad "no ipv4 address"
grep -q 'net-default-route: yes' <<< "$out" && ok "a default route was installed" || bad "no default route"
dns_n=$(grep -oP 'net-dns-servers: \K[0-9]+' <<< "$out" | head -1)
[ "${dns_n:-0}" -gt 0 ] && ok "$dns_n dns server(s) from dhcp" || bad "no dns servers from dhcp"
# per-boot mac. qemu's default nic mac (52:54:00:12:34:56) ALREADY has the
# locally-administered bit set, so the bit alone proves nothing -- assert the
# address moved off the hardware one, then that the replacement is well-formed.
mac2=$(grep -oP 'mac-uplink: \K[0-9a-f:]{17}' <<< "$out" | head -1)
grep -q 'mac-randomized: yes' <<< "$out" && ok "uplink mac was randomized away from hardware" || bad "uplink still wears its hardware mac"
[ -n "$mac2" ] && [ "$mac2" != "52:54:00:12:34:56" ] && ok "mac is not the qemu default" || bad "mac is still the qemu default"
b1m=$((16#${mac2:0:2}))
[ $((b1m & 2)) -ne 0 ] && [ $((b1m & 1)) -eq 0 ] && ok "locally-administered unicast bits correct" || bad "mac bit math wrong"
# fingerprint words, recomputed from the two sources OUTSIDE the booted
# system -- the tree wordlist and the roothash this run just built.
rh18=$(cat verity.roothash); want_fp=""
for i in 0 2 4 6; do want_fp="$want_fp $(sed -n "$((16#${rh18:$i:2} + 1))p" overlay/usr/share/xos/words)"; done
want_fp="${want_fp# }"
grep -qF "fingerprint: $want_fp" <<< "$out" \
	&& ok "fingerprint words derive from the signed roothash ($want_fp)" \
	|| bad "fingerprint mismatch (want: $want_fp)"
grep -q 'tether-armed: no (not usb)' <<< "$out" \
	&& ok "tether stays disarmed on a non-usb boot device" \
	|| bad "tether armed (or errored) on a virtio boot"
assert_complete "$out" "A2 boot"

echo
section "A3  unsigned UKI -- firmware must refuse it"
cp stick.img /tmp/xos-a3.img
mcopy -o -i /tmp/xos-a3.img@@1M xos.efi ::/EFI/BOOT/BOOTX64.EFI
o3=$(boot_img /tmp/xos-a3.img)
if grep -q XOS-TEST-BEGIN <<< "$o3"; then
	bad "unsigned kernel booted -- secure boot is not enforcing"
else
	grep -qi 'access denied' <<< "$o3" && ok "firmware rejected the unsigned image" \
		|| bad "unsigned image did not boot, but not visibly refused by secure boot"
fi
rm -f /tmp/xos-a3.img

echo
section "A4  tamper the signed UKI -- signature must break"
cp xos-signed.efi /tmp/xos-a4.efi
flip /tmp/xos-a4.efi $(( $(stat -c%s xos-signed.efi) / 2 ))
sbverify --cert keys/db.crt /tmp/xos-a4.efi >/dev/null 2>&1 \
	&& bad "tampered UKI still verified" || ok "one flipped bit invalidates the signature"
cp stick.img /tmp/xos-a4.img
mcopy -o -i /tmp/xos-a4.img@@1M /tmp/xos-a4.efi ::/EFI/BOOT/BOOTX64.EFI
o4=$(boot_img /tmp/xos-a4.img)
grep -q XOS-TEST-BEGIN <<< "$o4" && bad "tampered UKI booted" || ok "firmware refused the tampered image"
rm -f /tmp/xos-a4.efi /tmp/xos-a4.img

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
grep -q 'trust-anchors-in-binary: [1-9]' <<< "$out" \
	&& ok "trust anchors are compiled into the binary, not read from a directory" \
	|| bad "no trust anchor strings found in the shipped binary"

echo
section "A7  flip a byte in the verity HASH TREE -- boot must refuse"
# the data region is covered by the tree; the tree itself must be covered too,
# or an attacker could rewrite data + recompute the tree. flip the first hash
# block (one past the superblock at data-end). the superblock block itself is
# NOT covered -- dm-mod.create ignores it -- which is the one honest gap here.
blocks=$(grep -oE '4096 4096 [0-9]+ [0-9]+' cmdline.txt | head -1 | awk '{print $3}')
if [ -n "${blocks:-}" ]; then
	cp stick.img /tmp/xos-a7.img
	flip /tmp/xos-a7.img $((ROOT_OFF + (blocks + 1) * 4096 + 16))
	o7=$(boot_img /tmp/xos-a7.img)
	grep -q 'dm-verity device corrupted' <<< "$o7" && ok "hash-tree corruption panicked the kernel" \
		|| bad "a flipped hash-tree byte did not panic"
	rm -f /tmp/xos-a7.img
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
grep -q 'module-loader: absent' <<< "$out" && ok "no loadable module support" || bad "module loading is possible"
grep -q 'devport-node: absent'  <<< "$out" && ok "/dev/port absent"           || bad "/dev/port present"
grep -q 'mem-autoinit: heap alloc:on, heap free:on' <<< "$out" \
	&& ok "memory zeroed on both alloc and free" || bad "init_on_free not active"

echo
section "A9  write / exec containment"
grep -q 'remount-rw: refused' <<< "$out" && ok "/ cannot be remounted rw"      || bad "/ was remounted rw"
grep -q 'tmp-exec: refused'   <<< "$out" && ok "noexec /tmp blocks execution"  || bad "a binary ran from /tmp"
grep -q 'kptr-restrict: 2'    <<< "$out" && ok "kernel pointers restricted"    || bad "kptr_restrict not 2"
grep -q 'dmesg-restrict: 1'   <<< "$out" && ok "dmesg restricted to privileged readers" || bad "dmesg_restrict not 1"
grep -q 'sysctls-hardened: yes' <<< "$out" && ok "every hardening sysctl took" || bad "a hardening sysctl is not at its value"
grep -q 'sysctl FAILED'       <<< "$out" && bad "a sysctl write failed at boot" || ok "no sysctl write failed"

echo
section "A10  boot the stick over emulated USB (the real hardware path)"
o10=$(boot_usb stick.img)
if grep -q XOS-TEST-BEGIN <<< "$o10"; then
	ok "booted from usb-storage via dm-mod.waitfor"
	grep -qi 'secure boot is enabled' <<< "$o10" && ok "secure boot enforcing over USB" || bad "secure boot not enabled over USB"
	grep -q 'write-to-root: refused'  <<< "$o10" && ok "root unwritable over USB"       || bad "root writable over USB"
	grep -qF "fingerprint: $want_fp" <<< "$o10" \
		&& ok "same fingerprint words over usb -- stable per image, per boot path" \
		|| bad "fingerprint words changed on the usb boot path"
	grep -q 'tether-armed: yes' <<< "$o10" \
		&& ok "tether armed on the real usb boot path" \
		|| bad "tether did not arm over usb"
	assert_complete "$o10" "A10 boot"
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
if ! R=$(./build.sh ramkeys); then
	skipped "no stub or unlocked key -- A11 not evaluated (ramkeys failed)"
elif [ ! -f "$stub" ] || [ ! -f "$R/db.key" ]; then
	skipped "no stub or unlocked key -- A11 not evaluated"
else
	ukify build --linux=bzImage --cmdline="$(cat cmdline.txt) xos.rel=old" \
		--stub="$stub" --output=/tmp/xos-a11.efi >/dev/null 2>&1
	sbsign --key "$R/db.key" --cert keys/db.crt \
		--output /tmp/xos-a11-signed.efi /tmp/xos-a11.efi >/dev/null 2>&1
	if ! sbverify --cert keys/db.crt /tmp/xos-a11-signed.efi >/dev/null 2>&1; then
		bad "could not build a validly-signed superseded image to test with"
	else
		ok "the superseded image is validly signed by db"
		h=$(python3 pehash.py --verify /tmp/xos-a11-signed.efi) \
			&& ok "authenticode digest agrees with its own signature" \
			|| bad "pehash.py disagrees with the signature -- dbx would revoke nothing"
		# revoke it in firmware only; the tracked `revoked` file is untouched.
		virt-fw-vars --input ovmf-vars.fd --output ovmf-vars.fd \
			--add-dbx-hash "$SBGUID_T" "$h" >/dev/null 2>&1 \
			|| bad "could not enroll the test revocation into dbx"
		# drop the revoked image into a copy of the stick's ESP and boot that
		cp stick.img /tmp/xos-a11.img
		mcopy -o -i /tmp/xos-a11.img@@1M /tmp/xos-a11-signed.efi ::/EFI/BOOT/BOOTX64.EFI
		o11=$(boot_img /tmp/xos-a11.img)
		if grep -q XOS-TEST-BEGIN <<< "$o11"; then
			bad "a revoked image still booted -- dbx is not being enforced"
		else
			has_denied=$(grep -ic 'access denied\|security violation' <<< "$o11" || true)
			[ "${has_denied:-0}" -gt 0 ] \
				&& ok "firmware refused the revoked image" \
				|| bad "revoked image did not boot, but not visibly refused by dbx"
		fi
		# revocation must not have collaterally killed the good image
		o11b=$(boot_img stick.img)
		if grep -q XOS-TEST-BEGIN <<< "$o11b"; then
			ok "the current image still boots with dbx enrolled"
			assert_complete "$o11b" "A11 clean re-boot"
		else
			bad "dbx enrollment broke the image we actually ship"
		fi
	fi
	rm -f /tmp/xos-a11.efi /tmp/xos-a11-signed.efi /tmp/xos-a11.img
fi

echo
section "A12  learn describes the system that is actually running"
# G24 checks the corpus against the BUILD TREE. this checks it against reality:
# a ref that names a command the booted system does not have is a lie the build
# cannot see, and the whole point of learn is that its questions are answerable
# on the stick, offline.
grep -q 'no-bash: absent' <<< "$out" && ok "bash is gone -- one shell" || bad "a second shell shipped"
grep -q 'shell-vi-default: yes' <<< "$out" && ok "vi-mode line editing is the default shell behavior" || bad "vi keybindings are not the default"
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
grep -q 'learn-phrases: yes' <<< "$out" && ok "phrase macros ship" \
	|| bad "learn/phrases missing -- prompts would show literal %macro%"
grep -q 'learn-varies: yes' <<< "$out" \
	&& ok "a rendered prompt has no unexpanded macro" \
	|| bad "a prompt rendered with a literal %macro% in it"
grep -q 'learn-chains: yes' <<< "$out" \
	&& ok "challenge track holds its shape on the booted system" \
	|| bad "learn challenge check failed at runtime"

echo
section "A13  a session outlives the terminal that started it"
# the whole point of shipping abduco. these probes come from a boot where NOTHING
# was attached to the session -- stdin was /dev/null -- so a listed session with a
# living child is proof the program is owned by abduco and not by a terminal.
grep -q 'devpts-mounted: devpts' <<< "$out" && ok "devpts is mounted" \
	|| bad "no devpts -- nothing can allocate a terminal"
grep -q 'ptmx-node: yes' <<< "$out" && ok "/dev/ptmx is a character device" \
	|| bad "/dev/ptmx missing -- pty allocation would fail before it even tries"
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
# the console supervisor honours its device argument. a POSIX gotcha
# (`_dev=$1 _fail=0 _t0` sets the vars only for the command `_t0`) left it
# empty and spun forever on every real boot; no test caught it because test
# boots power off before the console is set up.
grep -q 'console-device-ok: yes' <<< "$out" \
	&& ok "the console supervisor runs with a real device" \
	|| bad "the console got an empty device -- it would error-loop on real hardware"
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
grep -q 'crypto-aes: yes'     <<< "$out" && ok "aes is available in the kernel crypto api"   || bad "aes missing from the kernel crypto api"
grep -q 'crypto-sha512: yes'  <<< "$out" && ok "sha512 is available in the kernel crypto api" || bad "sha512 missing from the kernel crypto api"
grep -q 'loop-node: present'  <<< "$out" && ok "/dev/loop0 exists"                            || bad "no loop device node"
grep -q 'dm-control: present' <<< "$out" && ok "/dev/mapper/control exists"                   || bad "no device-mapper control node"
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
grep -q 'fs-vfat: yes' <<< "$out" && ok "vfat available (usb sticks, esp)" || bad "no vfat"
grep -q 'fs-exfat: yes' <<< "$out" && ok "exfat available (large sd cards, modern sticks)" || bad "no exfat"
grep -q 'fs-iso9660: yes' <<< "$out" && ok "iso9660 available (loop-mount an image)" || bad "no iso9660"
grep -q 'fs-ntfs3: yes' <<< "$out" && ok "ntfs available (read a windows disk)" || bad "no ntfs"
grep -q 'entropy-trusted: random.trust_cpu=1' <<< "$out" \
	&& ok "the entropy source is pinned on the signed cmdline" \
	|| bad "random.trust_cpu is not pinned -- keys may be generated on a thin pool"
# the clock floor. no RTC is compiled in, so system time is set by luck; the
# floor makes it impossible to push BELOW the build date, which is the property
# TLS validation needs -- a clock set backwards revalidates revoked certs.
grep -q 'clock-floor: [0-9]' <<< "$out" && ok "a signed clock floor is pinned on the cmdline" \
	|| bad "no clock floor -- time can be set to anything, incl. before a revocation"
grep -q 'clock-not-before-floor: yes' <<< "$out" \
	&& ok "the running clock is at or above the floor" \
	|| bad "the clock is below the floor -- init did not raise it"
# a machine whose rtc is already sane must make NO network time call -- the
# tls-time pass exists for floored clocks only, and its absence is a privacy
# property worth pinning.
grep -q 'tls-time: skipped (rtc sane)' <<< "$out" \
	&& ok "sane rtc: no tls-time network call was made" \
	|| bad "tls-time ran (or failed) on a boot whose clock was already right"

echo
section "A15  a clock set to the past cannot fall below the signed floor"
# boot with the RTC at 2010. the floor is the build date; init must raise the
# clock to it. this is the property that stops an attacker on the network from
# winding time back to before a certificate was revoked.
backout=$(boot_backclock stick.img)
grep -q 'clock-not-before-floor: yes' <<< "$backout" \
	&& ok "clock forced to 2010 was raised to the build-date floor" \
	|| bad "the clock stayed in the past -- the floor did not hold"
# the floor made time not-backward; tls-time must then make it RIGHT. this is
# the real production path end to end: floored clock -> handshake against the
# compiled-in anchors -> Date header parsed -> clock advanced, forward only.
grep -q 'advanced to tls time' <<< "$backout" \
	&& ok "floored clock was advanced to authenticated tls time" \
	|| bad "tls-time did not advance a floored clock (dead-rtc machines stay 90 days behind)"
grep -q 'tls-time: synced' <<< "$backout" \
	&& ok "probe agrees: tls-time synced" \
	|| bad "tls-time probe did not report synced"
# this is a second full boot of the same stick -- free vehicle for the
# per-boot properties: the mac must be fresh, the fingerprint must not be.
mac15=$(grep -oP 'mac-uplink: \K[0-9a-f:]{17}' <<< "$backout" | head -1)
[ -n "$mac15" ] && [ "$mac15" != "$mac2" ] \
	&& ok "a second boot drew a different mac" || bad "mac repeated across boots"
grep -qF "fingerprint: $want_fp" <<< "$backout" \
	&& ok "fingerprint words identical across boots" \
	|| bad "fingerprint words changed between boots of the same image"
assert_complete "$backout" "A15 boot"

echo
section "A16  state survives a real power cycle"
# the whole reason p3 exists. a blank disk is attached and xos is booted twice.
# boot 1 provisions it -- LUKS2 with integrity, a filesystem, a marker file.
# boot 2 gets the SAME disk and must read the marker back. the file is a plain
# image (no host root needed); xos, which is root inside qemu, does every
# privileged step. this is "reboot and your work is still there", proven.
p3disk=/tmp/xos-p3test.img
rm -f "$p3disk"; truncate -s 64M "$p3disk"
b1=$(boot_state "$p3disk")
grep -q 'ledger: first boot recorded' <<< "$b1" \
	&& ok "boot 1 opened the ledger at one" \
	|| bad "no ledger entry on first boot"
if grep -q 'teststate-phase: provision' <<< "$b1" \
   && grep -q 'teststate-format: ok' <<< "$b1" \
   && grep -q 'teststate-mkfs: ok' <<< "$b1"; then
	ok "boot 1 provisioned p3 (luks2 + integrity + a filesystem)"
else
	bad "boot 1 did not provision p3"
fi
grep -q 'recon: first visit to machine' <<< "$b1" \
	&& ok "boot 1 recorded a recon baseline for this machine" \
	|| bad "recon did not record a baseline on first visit"
assert_complete "$b1" "A16 boot 1"
# boot 2 is the same machine, same disk -- but a pci device has appeared
# (an xhci controller). recon must read the marker back AND call out the
# new hardware; a machine that grew a device since your last visit is
# exactly what recon exists to notice.
b2=$(boot_state "$p3disk" -device qemu-xhci)
grep -q 'teststate-prior-marker: survived-a-reboot' <<< "$b2" \
	&& ok "boot 2 read the marker back -- state survived the power cycle" \
	|| bad "the marker did not survive the reboot"
grep -qE 'recon: MACHINE [0-9a-f]{16} CHANGED' <<< "$b2" \
	&& ok "boot 2 noticed the machine changed" \
	|| bad "a new pci device went unremarked -- recon is blind"
# the ledger must count across a real power cycle, and carry the previous
# boot's timestamp -- a rolled-back p3 image shows a lower number than the
# one you remember, which is the only thing on the stick that can say so.
grep -qE 'ledger: boot 2 on this state \(last was [0-9]{4}-[0-9]{2}-[0-9]{2}' <<< "$b2" \
	&& ok "boot 2 counted, and named when boot 1 happened" \
	|| bad "the ledger did not advance to 2 across the power cycle"
grep -q 'new:  pci' <<< "$b2" \
	&& ok "the diff names the device that appeared" \
	|| bad "recon said 'changed' but not what changed"
assert_complete "$b2" "A16 boot 2"
# boot 3 is the same machine AND the same hardware as boot 2 -- recon must now
# report NO change. the other half of the guarantee: a feature that cried
# "changed" on every boot would be as useless as one that never noticed.
b3=$(boot_state "$p3disk" -device qemu-xhci)
grep -q 'recon: machine [0-9a-f]\{16\} is as you left it' <<< "$b3" \
	&& ok "boot 3 saw identical hardware and said nothing changed" \
	|| bad "recon cried 'changed' on an unchanged machine -- false alarms"
grep -q 'ledger: boot 3 on this state' <<< "$b3" \
	&& ok "boot 3 counted on -- the ledger is monotonic" \
	|| bad "the ledger lost count on boot 3"
assert_complete "$b3" "A16 boot 3"
rm -f "$p3disk"

echo
section "A17  remote access: wireguard up, ssh in over it, invisible otherwise"
# the "ssh in from titan and attach to what is running" ask. a full two-machine
# handshake is verified on real hardware; here every component is proven: the
# wireguard interface comes up and wg configures it, dropbear accepts a real
# ed25519 pubkey login end to end, and a wrong key is refused. dropbear only
# ever binds to the wireguard address in the real flow, so xos stays invisible
# on the network it is plugged into.
grep -q 'wg-iface-up: ok' <<< "$out" && ok "a wireguard interface comes up" \
	|| bad "no wireguard -- the kernel or wg userland is missing"
grep -q 'wg-show: ok' <<< "$out" && ok "wg configures the interface (key, port)" \
	|| bad "wg could not configure the interface"
grep -q 'ssh-listening: yes' <<< "$out" && ok "dropbear listens" || bad "dropbear did not start"
grep -q 'ssh-pubkey-login: ok' <<< "$out" \
	&& ok "an ed25519 public-key login works end to end" \
	|| bad "pubkey ssh login failed"
grep -q 'ssh-wrong-key-refused: refused' <<< "$out" \
	&& ok "a key not in authorized_keys is refused" \
	|| bad "the wrong key was accepted -- auth is not enforced"

echo
section "A18  yank the boot stick -- the machine must die"
# the dead-man tether. root is a RAM copy, so removal would otherwise change
# nothing. boot over emulated usb with a qmp monitor attached; xos.testtether
# keeps init alive after the probe block (A18 owns this boot's lifetime), then
# hot-remove the usb device the way a hand does and assert the poweroff.
if ! R=$(./build.sh ramkeys) || [ ! -f "$stub" ] || [ ! -f "$R/db.key" ]; then
	skipped "no stub or unlocked key -- A18 not evaluated"
else
	ukify build --linux=bzImage --cmdline="$(cat cmdline.txt) xos.testtether" \
		--stub="$stub" --output=/tmp/xos-a18.efi >/dev/null 2>&1
	sbsign --key "$R/db.key" --cert keys/db.crt \
		--output /tmp/xos-a18-signed.efi /tmp/xos-a18.efi >/dev/null 2>&1
	cp stick.img /tmp/xos-a18.img
	mcopy -o -i /tmp/xos-a18.img@@1M /tmp/xos-a18-signed.efi ::/EFI/BOOT/BOOTX64.EFI
	a18log=/tmp/xos-a18.log; a18qmp=/tmp/xos-a18.qmp; rm -f "$a18log" "$a18qmp"
	timeout 360 qemu-system-x86_64 -machine q35,smm=on -m 512 \
		-global driver=cfi.pflash01,property=secure,value=on \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd \
		-drive if=pflash,format=raw,unit=1,file=ovmf-vars.fd \
		-device qemu-xhci,id=xhci \
		-drive if=none,id=stick,format=raw,readonly=on,file=/tmp/xos-a18.img \
		-device usb-storage,bus=xhci.0,drive=stick,id=stickdev \
		-qmp unix:"$a18qmp",server,nowait \
		-nic user,model=virtio-net-pci -nographic -no-reboot </dev/null >"$a18log" 2>&1 &
	qpid=$!
	t=0; while [ "$t" -lt 180 ] && ! grep -q 'XOS-TEST-DONE' "$a18log" 2>/dev/null; do sleep 1; t=$((t+1)); done
	if ! grep -q 'tether-armed: yes' "$a18log" 2>/dev/null; then
		bad "tether did not arm on the usb boot"; kill "$qpid" 2>/dev/null
	else
		ok "tether armed over emulated usb"
		python3 - "$a18qmp" <<'PY'
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); f = s.makefile("rw")
f.readline(); f.write(json.dumps({"execute": "qmp_capabilities"}) + "\n"); f.flush(); f.readline()
f.write(json.dumps({"execute": "device_del", "arguments": {"id": "stickdev"}}) + "\n"); f.flush(); f.readline()
PY
		t=0; while [ "$t" -lt 30 ] && kill -0 "$qpid" 2>/dev/null; do sleep 1; t=$((t+1)); done
		grep -q 'boot stick removed -- powering off' "$a18log" \
			&& ok "init saw the yank and announced the poweroff" \
			|| bad "no removal message -- the tether never fired"
		if kill -0 "$qpid" 2>/dev/null; then
			bad "machine still running ${t}s after the stick was pulled"; kill "$qpid" 2>/dev/null
		else
			ok "machine powered off within ${t}s of the yank"
		fi
	fi
	wait "$qpid" 2>/dev/null
	rm -f /tmp/xos-a18.efi /tmp/xos-a18-signed.efi /tmp/xos-a18.img "$a18log" "$a18qmp"
fi

echo
section "A19  every opt-out knob holds, and the state prompt is real"
# the knobs are guards; a guard that silently stopped guarding is the exact
# regression class this harness exists for. one signed variant UKI turns every
# opt-out on at once and asserts each visibly took. then two production-
# flavoured boots (no xos.test -- the probe block ends in poweroff and never
# reaches state_open) attach a PARTITIONED luks disk and prove the real
# state_open() scan finds it: the unlock prompt must appear, and xos.nostate
# must make it not. A16's whole-disk vdb has no partition attr, so the real
# scan never sees it -- this is the only place the production path runs.
if ! R=$(./build.sh ramkeys) || [ ! -f "$stub" ] || [ ! -f "$R/db.key" ]; then
	skipped "no stub or unlocked key -- A19 not evaluated"
else
	ukify build --linux=bzImage \
		--cmdline="$(cat cmdline.txt) xos.nonet xos.realmac xos.notether xos.nostate" \
		--stub="$stub" --output=/tmp/xos-a19.efi >/dev/null 2>&1
	sbsign --key "$R/db.key" --cert keys/db.crt \
		--output /tmp/xos-a19-signed.efi /tmp/xos-a19.efi >/dev/null 2>&1
	cp stick.img /tmp/xos-a19.img
	mcopy -o -i /tmp/xos-a19.img@@1M /tmp/xos-a19-signed.efi ::/EFI/BOOT/BOOTX64.EFI
	o19=$(boot_img /tmp/xos-a19.img)
	grep -q 'net-has-address: no' <<< "$o19" \
		&& ok "xos.nonet: no address was configured" \
		|| bad "xos.nonet did not hold -- the box got a lease"
	grep -q 'net-dns-servers: 0' <<< "$o19" \
		&& ok "xos.nonet: no resolver was written" \
		|| bad "xos.nonet: dns servers appeared"
	grep -q 'mac-randomized: off (xos.realmac)' <<< "$o19" \
		&& ok "xos.realmac: burned-in mac kept" \
		|| bad "xos.realmac did not hold"
	grep -q 'tether-armed: off (xos.notether)' <<< "$o19" \
		&& ok "xos.notether: tether stayed down" \
		|| bad "xos.notether did not hold"
	assert_complete "$o19" "A19 opt-out boot"

	# the partitioned luks disk, built host-side: gpt with one partition at
	# 1MiB, a luks2 header dd'd into it. in the guest it enumerates as vdb1
	# WITH a partition attr -- exactly what the real scan looks for.
	a19disk=/tmp/xos-a19-state.img; a19luks=/tmp/xos-a19.luks
	truncate -s 48M "$a19disk"
	printf 'label: gpt\n, 40M, L\n' | sfdisk "$a19disk" >/dev/null 2>&1
	truncate -s 40M "$a19luks"
	printf 'testpass' | cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 \
		--pbkdf-force-iterations 1000 --batch-mode --key-file - "$a19luks" >/dev/null 2>&1
	dd if="$a19luks" of="$a19disk" bs=1M seek=1 conv=notrunc status=none

	# production cmdline: the test flags stripped, nothing else touched. this
	# boot never prints XOS-TEST-END; it is killed by its own timeout after
	# the assertion window.
	prodcmd=$(tr ' ' '\n' < cmdline.txt | grep -v '^xos\.test' | tr '\n' ' ')
	ukify build --linux=bzImage --cmdline="$prodcmd" \
		--stub="$stub" --output=/tmp/xos-a19p.efi >/dev/null 2>&1
	sbsign --key "$R/db.key" --cert keys/db.crt \
		--output /tmp/xos-a19p-signed.efi /tmp/xos-a19p.efi >/dev/null 2>&1
	cp stick.img /tmp/xos-a19p.img
	mcopy -o -i /tmp/xos-a19p.img@@1M /tmp/xos-a19p-signed.efi ::/EFI/BOOT/BOOTX64.EFI
	o19p=$(timeout 90 qemu-system-x86_64 -machine q35,smm=on -m 512 \
		-global driver=cfi.pflash01,property=secure,value=on \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd \
		-drive if=pflash,format=raw,unit=1,file=ovmf-vars.fd \
		-drive file=/tmp/xos-a19p.img,if=virtio,format=raw,readonly=on \
		-drive file="$a19disk",if=virtio,format=raw \
		-nic user,model=virtio-net-pci -nographic -no-reboot < /dev/null 2>&1)
	grep -q 'unlock persistent state?' <<< "$o19p" \
		&& ok "the real state_open() scan found the partitioned luks disk and asked" \
		|| bad "no unlock prompt -- the production state scan is not finding partitions"

	# same disk, same cmdline plus xos.nostate: the prompt must NOT appear.
	ukify build --linux=bzImage --cmdline="$prodcmd xos.nostate" \
		--stub="$stub" --output=/tmp/xos-a19n.efi >/dev/null 2>&1
	sbsign --key "$R/db.key" --cert keys/db.crt \
		--output /tmp/xos-a19n-signed.efi /tmp/xos-a19n.efi >/dev/null 2>&1
	cp stick.img /tmp/xos-a19n.img
	mcopy -o -i /tmp/xos-a19n.img@@1M /tmp/xos-a19n-signed.efi ::/EFI/BOOT/BOOTX64.EFI
	o19n=$(timeout 90 qemu-system-x86_64 -machine q35,smm=on -m 512 \
		-global driver=cfi.pflash01,property=secure,value=on \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd \
		-drive if=pflash,format=raw,unit=1,file=ovmf-vars.fd \
		-drive file=/tmp/xos-a19n.img,if=virtio,format=raw,readonly=on \
		-drive file="$a19disk",if=virtio,format=raw \
		-nic user,model=virtio-net-pci -nographic -no-reboot < /dev/null 2>&1)
	if grep -q 'unlock persistent state?' <<< "$o19n"; then
		bad "xos.nostate did not hold -- the unlock prompt appeared anyway"
	elif grep -q 'this image is:' <<< "$o19n"; then
		ok "xos.nostate: same disk, no prompt, boot carried on"
	else
		bad "the nostate boot never reached the banner -- nothing was proven"
	fi
	rm -f /tmp/xos-a19*.efi /tmp/xos-a19*.img "$a19luks"
fi

printf '  %d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
if [ "$sections" -ne "$EXPECTED_SECTIONS" ]; then
	printf '\033[1;31m  only %d of %d checks ran -- the harness was truncated\033[0m\n\n' \
		"$sections" "$EXPECTED_SECTIONS"
	exit 1
fi
echo
[ "$fail" -eq 0 ]

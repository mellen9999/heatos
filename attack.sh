#!/bin/bash
# each check asserts an EXPECTED FAILURE. the harness fails if an attack works.
set -uo pipefail
cd "$(dirname "$0")"

pass=0; fail=0
ok()  { printf '  \033[1;32mPASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }

boot_img() {
	timeout 45 qemu-system-x86_64 -m 128 -kernel bzImage \
		-drive file="$1",if=virtio,format=raw,readonly=on \
		-append "$(cat cmdline.txt) heatos.test" -nographic -no-reboot < /dev/null 2>&1
}

echo
echo "A1  flip one byte in the image -- boot must refuse"
cp heatos.img /tmp/heatos-a1.img
python3 -c "
import pathlib,sys
p=pathlib.Path('/tmp/heatos-a1.img'); b=bytearray(p.read_bytes()); b[100000]^=1; p.write_bytes(bytes(b))"
out=$(boot_img /tmp/heatos-a1.img)
if grep -q 'is corrupted' <<< "$out" && ! grep -q HEATOS-TEST-BEGIN <<< "$out"; then
	ok "verity refused the block and killed init"
else
	bad "corrupted image booted or produced no verity error"
fi
rm -f /tmp/heatos-a1.img

echo
echo "A2  clean image -- root must be unwritable"
out=$(boot_img heatos.img)
grep -q 'write-to-root: refused' <<< "$out" && ok "write to / returned EROFS" || bad "root was writable"
grep -q 'busybox-runs: yes'      <<< "$out" && ok "userland actually executes"  || bad "userland did not run"

echo
echo "A5  no dynamic loader to hijack"
if [ -z "$(find root -name 'ld-musl-*' -o -name 'ld-linux*' 2>/dev/null)" ]; then
	ok "no ld-musl/ld-linux in the image (LD_PRELOAD has nothing to load)"
else
	bad "a dynamic loader is present"
fi
grep -q 'dynamic-loader-present: no' <<< "$out" && ok "confirmed absent from inside the booted system" || bad "loader present at runtime"

echo
printf '  %d passed, %d failed\n\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

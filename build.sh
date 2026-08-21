#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

KVER="${KVER:-6.12.43}"
BBVER="${BBVER:-1.37.0}"
JOBS="$(nproc)"
IMAGE_MAX=8388608

say() { printf '\n\033[1;33m==> %s\033[0m\n' "$*"; }

fetch() {
  say "fetching + verifying sources"
  mkdir -p src
  local ktar="linux-$KVER.tar.xz" bbtar="busybox-$BBVER.tar.bz2"

  [ -f "src/$ktar" ]  || curl -fL "https://cdn.kernel.org/pub/linux/kernel/v6.x/$ktar" -o "src/$ktar"
  [ -f "src/$bbtar" ] || curl -fL "https://busybox.net/downloads/$bbtar" -o "src/$bbtar"

  # G8 -- every source pinned, verified BEFORE extraction. a verified boot
  # chain rooted in an unverified tarball proves nothing.
  grep -q " $ktar$"  sources.sha256 || { echo "FAIL: $ktar not pinned in sources.sha256" >&2; return 1; }
  grep -q " $bbtar$" sources.sha256 || { echo "FAIL: $bbtar not pinned in sources.sha256" >&2; return 1; }
  ( cd src && sha256sum -c --strict ../sources.sha256 ) || {
    echo "FAIL: source digest mismatch -- refusing to extract" >&2; return 1; }

  [ -d "src/linux-$KVER" ]    || tar -C src -xf "src/$ktar"
  [ -d "src/busybox-$BBVER" ] || tar -C src -xf "src/$bbtar"
}

kernel() {
  say "building kernel $KVER"
  local d="src/linux-$KVER"
  make -C "$d" tinyconfig
  # olddefconfig silently drops any option whose deps are unmet, so enable to a
  # fixpoint (a parent enabled on pass N unlocks its children on pass N+1) and
  # then GATE on it -- a kernel quietly missing squashfs still "builds fine".
  for _pass in 1 2 3; do
    while read -r opt; do
      "$d/scripts/config" --file "$d/.config" --enable "$opt"
    done < <(grep -o '^CONFIG_[A-Z0-9_]*' kernel.config)
    make -C "$d" olddefconfig >/dev/null
  done
  local missing=()
  while read -r opt; do
    grep -q "^$opt=y" "$d/.config" || missing+=("$opt")
  done < <(grep -o '^CONFIG_[A-Z0-9_]*' kernel.config)
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "FAIL: kernel options requested but not enabled: ${missing[*]}" >&2
    return 1
  fi
  grep -q '^CONFIG_MODULES=y' "$d/.config" && { echo "FAIL: module loader enabled" >&2; return 1; }
  make -C "$d" -j"$JOBS" bzImage
  cp "$d/arch/x86/boot/bzImage" bzImage
}

bbset() {
  local d="$1" opt="$2" val="$3"
  sed -i "/^CONFIG_$opt=/d;/^# CONFIG_$opt is not set\$/d" "$d/.config"
  if [ "$val" = y ]; then
    echo "CONFIG_$opt=y" >> "$d/.config"
  else
    echo "# CONFIG_$opt is not set" >> "$d/.config"
  fi
}

headers() {
  say "installing kernel headers into sysroot"
  local d="src/linux-$KVER"
  rm -rf sysroot
  make -C "$d" headers_install INSTALL_HDR_PATH="$PWD/sysroot" >/dev/null
  printf '  sysroot/include: %s headers\n' "$(find sysroot/include -name '*.h' | wc -l)"
}

busybox() {
  say "building busybox $BBVER (${BBMODE:-full})"
  [ -d sysroot/include/linux ] || headers
  local d="src/busybox-$BBVER"
  make -C "$d" defconfig >/dev/null

  # static-PIE: plain -static is an ASLR downgrade (fixed load address), so we
  # drive it through EXTRA flags instead of CONFIG_STATIC, which would inject a
  # conflicting -static. G3 verifies the result is ET_DYN.
  bbset "$d" STATIC n
  bbset "$d" PIE n
  for off in TC PAM FEATURE_WTMP FEATURE_UTMP; do bbset "$d" "$off" n; done
  sed -i '/^CONFIG_EXTRA_CFLAGS=/d;/^CONFIG_EXTRA_LDFLAGS=/d' "$d/.config"
  echo "CONFIG_EXTRA_CFLAGS=\"-fPIE -Os -isystem $PWD/sysroot/include\"" >> "$d/.config"
  echo 'CONFIG_EXTRA_LDFLAGS=""' >> "$d/.config"

  if [ "${BBMODE:-full}" = trim ]; then
    grep -o '^CONFIG_[A-Z0-9_]*=y' "$d/.config" | sed 's/^CONFIG_//;s/=y$//' > /tmp/bb-all.$$
    local keep
    keep=$(tr ' ' '\n' < busybox.config.applets | grep -v '^$' | tr 'a-z' 'A-Z' | sort -u)
    while read -r sym; do
      case "$sym" in
        STATIC|*FEATURE*|*PLATFORM*|*LFS*|DESKTOP|LONG_OPTS|SHOW_USAGE|*_PREFIX*|INSTALL_*|*_APPLET_*) continue ;;
      esac
      grep -qx "$sym" <<< "$keep" || bbset "$d" "$sym" n
    done < /tmp/bb-all.$$
    rm -f /tmp/bb-all.$$
  fi

  # `yes |` takes SIGPIPE when make exits; pipefail would turn that into exit 141
  # and silently abort before compiling. this bit us twice.
  yes '' | make -C "$d" oldconfig >/dev/null 2>&1 || true

  rm -f "$d/busybox"
  local specs="$PWD/musl-static-pie.specs"
  [ -f "$specs" ] || { echo "FAIL: $specs missing" >&2; return 1; }
  local cc="gcc -specs=$specs"
  make -C "$d" -j"$JOBS" CC="$cc" HOSTCC=gcc
  [ -f "$d/busybox" ] || { echo "busybox build failed" >&2; return 1; }
  strip "$d/busybox"
  cp "$d/busybox" busybox
  # form gates can pass on a binary that segfaults -- so prove it executes
  ./busybox true 2>/dev/null || { echo "FAIL: built busybox does not run" >&2; return 1; }
  printf '  busybox binary: %d bytes (musl static-pie, runs)\n' "$(stat -c%s busybox)"
}

rootfs() {
  say "building read-only root"
  rm -rf root
  mkdir -p root/bin root/proc root/sys root/dev root/etc
  cp busybox root/bin/
  # one binary, many names: busybox reads argv[0] to decide what to be.
  # names come from busybox itself, not our config list -- the two drift
  # (CONFIG_TEST1 is the applet named "["), and a missing applet makes
  # shell tests fail open rather than fail loud.
  ./busybox --list > /tmp/heatos-applets.$$ 2>/dev/null || {
    echo "FAIL: busybox --list unavailable (enable the busybox applet)" >&2; return 1; }
  [ -s /tmp/heatos-applets.$$ ] || { echo "FAIL: empty applet list" >&2; return 1; }
  while read -r a; do
    ln -sf busybox "root/bin/$a"
  done < /tmp/heatos-applets.$$
  grep -qx '\[' /tmp/heatos-applets.$$ || { echo "FAIL: '[' applet missing -- shell tests would fail open" >&2; rm -f /tmp/heatos-applets.$$; return 1; }
  rm -f /tmp/heatos-applets.$$
  cp init root/init
  chmod +x root/init
  echo 'heatos' > root/etc/hostname
  mksquashfs root rootfs.squashfs -noappend -no-xattrs -all-root -comp gzip -quiet
  printf '  rootfs.squashfs: %d bytes (%d files)\n' "$(stat -c%s rootfs.squashfs)" "$(find root -type f -o -type l | wc -l)"
}

floppy() {
  say "writing floppy.img"
  rm -f floppy.img
  truncate -s 1474560 floppy.img
  /usr/bin/mkfs.fat -F 12 -n FLOPPY floppy.img >/dev/null
  syslinux --install floppy.img
  printf 'DEFAULT linux\nLABEL linux\n  KERNEL /bzImage\n  INITRD /initramfs.cpio.gz\n  APPEND console=ttyS0,115200 quiet\n' > syslinux.cfg
  mcopy -i floppy.img bzImage ::/bzImage
  mcopy -i floppy.img initramfs.cpio.gz ::/initramfs.cpio.gz
  mcopy -i floppy.img syslinux.cfg ::/syslinux.cfg
}

size() {
  local k i total
  k=$(stat -c%s bzImage)
  i=$(stat -c%s initramfs.cpio.gz)
  total=$((k + i + 32768))
  printf '\n  kernel      %8d\n  initramfs   %8d\n  boot+fs     %8d\n  ---------------------\n  total       %8d / %d\n\n' \
    "$k" "$i" 32768 "$total" "$IMAGE_MAX"
  if [ "$total" -gt "$IMAGE_MAX" ]; then
    printf '\033[1;31m  OVER BUDGET by %d bytes -- cut something\033[0m\n\n' "$((total - CAP))"
    return 1
  fi
  printf '\033[1;32m  fits, %d bytes to spare\033[0m\n\n' "$((CAP - total))"
}

run() {
  qemu-system-x86_64 -m 64 -kernel bzImage -initrd initramfs.cpio.gz \
    -append "console=ttyS0,115200" -nographic -no-reboot
}

boot() {
  qemu-system-x86_64 -m 64 -fda floppy.img -boot a -nographic -no-reboot
}

case "${1:-all}" in
  fetch|kernel|headers|busybox|rootfs|floppy|size|run|boot) "$1" ;;
  all) fetch; kernel; headers; busybox; rootfs; size; floppy ;;
  *) echo "usage: $0 {fetch|kernel|busybox|initramfs|floppy|size|run|boot|all}"; exit 1 ;;
esac

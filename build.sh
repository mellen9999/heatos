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
  while read -r opt; do
    [ -z "$opt" ] && continue
    "$d/scripts/config" --file "$d/.config" --enable "$opt"
  done < <(grep -o '^CONFIG_[A-Z0-9_]*' kernel.config)
  make -C "$d" olddefconfig
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

busybox() {
  say "building busybox $BBVER (${BBMODE:-full})"
  local d="src/busybox-$BBVER"
  make -C "$d" defconfig >/dev/null

  bbset "$d" STATIC y
  for off in TC PAM FEATURE_WTMP FEATURE_UTMP; do bbset "$d" "$off" n; done

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

  yes '' | make -C "$d" oldconfig >/dev/null 2>&1

  rm -f "$d/busybox"
  local cc=gcc
  command -v musl-gcc >/dev/null && cc=musl-gcc
  make -C "$d" -j"$JOBS" CC="$cc" HOSTCC=gcc
  [ -f "$d/busybox" ] || { echo "busybox build failed" >&2; return 1; }
  strip "$d/busybox"
  cp "$d/busybox" busybox
  printf '  busybox binary: %d bytes (%s)\n' "$(stat -c%s busybox)" "$cc"
}

initramfs() {
  say "packing initramfs"
  rm -rf root
  mkdir -p root/bin root/proc root/sys root/dev
  cp busybox root/bin/
  ln -sf busybox root/bin/sh
  cp init root/init
  (cd root && find . | cpio -o -H newc --quiet | gzip -9) > initramfs.cpio.gz
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
  fetch|kernel|busybox|initramfs|floppy|size|run|boot) "$1" ;;
  all) fetch; kernel; busybox; initramfs; size; floppy ;;
  *) echo "usage: $0 {fetch|kernel|busybox|initramfs|floppy|size|run|boot|all}"; exit 1 ;;
esac

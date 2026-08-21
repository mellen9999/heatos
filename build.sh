#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

KVER="${KVER:-6.12.43}"
BBVER="${BBVER:-1.37.0}"
JOBS="$(nproc)"
IMAGE_MAX=8388608
SALT=48454154534f530000000000000000000000000000000000000000000000000a

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

verity() {
  say "building verity hash tree"
  cp rootfs.squashfs heatos.img
  local data blocks
  data=$(stat -c%s heatos.img)
  if [ $((data % 4096)) -ne 0 ]; then
    data=$(( (data / 4096 + 1) * 4096 ))
    truncate -s "$data" heatos.img
  fi
  blocks=$((data / 4096))

  # fixed salt: the image must be reproducible, and a random salt would
  # change the root hash on every build for identical content.
  veritysetup format heatos.img heatos.img \
    --hash-offset="$data" --data-blocks="$blocks" --salt="$SALT" > verity.info
  local rh
  rh=$(awk '/Root hash/{print $NF}' verity.info)
  [ ${#rh} -eq 64 ] || { echo "FAIL: no root hash from veritysetup" >&2; return 1; }
  echo "$rh" > verity.roothash

  # veritysetup writes a superblock AT the hash offset, so the hash tree
  # itself starts one block later -- pointing the table at $blocks lands on
  # the superblock and the root mount fails with no verity error at all.
  printf 'dm-mod.create="vroot,,,ro,0 %d verity 1 /dev/vda /dev/vda 4096 4096 %d %d sha256 %s %s" root=/dev/dm-0 ro rootfstype=squashfs rootwait init=/init console=ttyS0,115200
' \
    "$((blocks * 8))" "$blocks" "$((blocks + 1))" "$rh" "$SALT" > cmdline.txt

  printf '  heatos.img: %d bytes  root hash: %s
' "$(stat -c%s heatos.img)" "$rh"
}

size() {
  say "gates"
  local bad=0
  g() { printf '  %-42s %s
' "$1" "$2"; [ "$2" = ok ] || bad=1; }

  local sz; sz=$(stat -c%s heatos.img)
  g "G1 image <= $IMAGE_MAX ($sz)" "$([ "$sz" -le "$IMAGE_MAX" ] && echo ok || echo FAIL)"

  local elfs interp exec_type
  elfs=$(find root -type f -exec sh -c 'head -c4 "$1" | grep -q ELF && echo "$1"' _ {} \; 2>/dev/null)
  interp=0; exec_type=0
  for f in $elfs; do
    readelf -l "$f" 2>/dev/null | grep -q INTERP && interp=$((interp+1))
    readelf -h "$f" 2>/dev/null | grep -q 'Type:.*EXEC' && exec_type=$((exec_type+1))
  done
  g "G2 no dynamic loader ($interp with INTERP)" "$([ "$interp" -eq 0 ] && echo ok || echo FAIL)"
  g "G3 all ELF are PIE ($exec_type non-PIE)"    "$([ "$exec_type" -eq 0 ] && echo ok || echo FAIL)"

  local suid ww
  suid=$(find root -type f \( -perm -4000 -o -perm -2000 \) | wc -l)
  ww=$(find root -type f -perm -0002 | wc -l)
  g "G4 no setuid/setgid ($suid)"      "$([ "$suid" -eq 0 ] && echo ok || echo FAIL)"
  g "G5 no world-writable ($ww)"       "$([ "$ww" -eq 0 ] && echo ok || echo FAIL)"

  local want have
  want=$(cat verity.roothash)
  have=$(grep -oE 'sha256 [0-9a-f]{64}' cmdline.txt | awk '{print $2}')
  g "G6 cmdline root hash matches tree" "$([ "$want" = "$have" ] && echo ok || echo FAIL)"

  g "G7 kernel has no module loader" "$(grep -q '^CONFIG_MODULES=y' "src/linux-$KVER/.config" && echo FAIL || echo ok)"

  echo
  [ "$bad" -eq 0 ] && printf '[1;32m  all gates green -- %d bytes, %d to spare[0m

' "$sz" "$((IMAGE_MAX - sz))" \
                   || { printf '[1;31m  GATES FAILED[0m

'; return 1; }
}

boot() {
  [ -f cmdline.txt ] || { echo "FAIL: run ./build.sh verity first" >&2; return 1; }
  qemu-system-x86_64 -m 128 -kernel bzImage \
    -drive file="${1:-heatos.img}",if=virtio,format=raw,readonly=on \
    -append "$(cat cmdline.txt) ${HEATOS_APPEND:-}" -nographic -no-reboot
}

case "${1:-all}" in
  fetch|kernel|headers|busybox|rootfs|verity|size|boot) "$1" ;;
  all) fetch; kernel; headers; busybox; rootfs; verity; size ;;
  *) echo "usage: $0 {fetch|kernel|busybox|initramfs|floppy|size|run|boot|all}"; exit 1 ;;
esac

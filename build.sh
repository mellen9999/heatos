#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

KVER="${KVER:-6.12.43}"
BBVER="${BBVER:-1.37.0}"
BASHVER="${BASHVER:-5.3}"
IIVER="${IIVER:-2.0}"
BSSLVER="${BSSLVER:-0.6}"
CMDCHAMP_SRC="${CMDCHAMP_SRC:-$HOME/projects/cmdchamp}"
# plaintext private keys live ONLY here, only while unlocked. /dev/shm is
# tmpfs, so nothing lands on disk.
RAMKEYS="/dev/shm/heatos-keys-$(id -u)"
JOBS="$(nproc)"
IMAGE_MAX=8388608
SALT=48454154534f530000000000000000000000000000000000000000000000000a
SBGUID=11111111-2222-3333-4444-555555555555
# the verity superblock carries a UUID that veritysetup randomises per format.
# it sits outside the hash tree so it changes no security property -- it just
# made every build produce different bytes, which is the property that lets
# anyone check the artifact against this source.
VUUID=00000000-0000-4000-8000-000068656174
# fixed GPT identifiers so the stick is byte-deterministic AND so ONE signed
# cmdline (which names the root by PARTUUID, never by /dev/sdX) boots the same
# image whether it is p2 on a real usb stick or the whole disk under qemu.
GPT_DISK=48454154-4f53-4000-8000-000000000000
PU_ESP=48454154-4f53-4001-8000-000000000001
PU_ROOT=48454154-4f53-4002-8000-000000000002
STICK_ESP_MIB=64
# fixed build clock: the same commit must yield the same image, so the
# artifact can be checked against its source instead of trusted.
export SOURCE_DATE_EPOCH=1755648000
# busybox renders its banner timestamp in LOCAL time, so without a pinned TZ
# the same source builds differently in a different timezone.
export TZ=UTC
export KBUILD_BUILD_TIMESTAMP="$(date -u -d "@$SOURCE_DATE_EPOCH" 2>/dev/null)"
export KBUILD_BUILD_USER=heatos
export KBUILD_BUILD_HOST=heatos

say() { printf '\n\033[1;33m==> %s\033[0m\n' "$*"; }

# grep -q exits the moment it matches, SIGPIPEs whatever is feeding it, and
# under `set -o pipefail` that reads as failure -- so a SUCCESSFUL match looks
# like a failed command. this trap bit five separate checks in this script.
# always pipe into `has` instead of `grep -q`.
has() { local n; n=$(grep -c -- "$1" || true); [ "${n:-0}" -gt 0 ]; }

# a missing host tool used to surface as a mid-build failure -- the exact fail
# mode this repo eliminates everywhere else. name every one up front instead.
STUB=/usr/lib/systemd/boot/efi/linuxx64.efi.stub
OVMF_CODE=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd
OVMF_VARS=/usr/share/edk2/x64/OVMF_VARS.4m.fd
deps() {
  say "checking host toolchain"
  local miss=() cmd
  # cmd:package pairs so the error names what to install (arch/paru)
  for cmd in gcc:gcc ld:binutils strip:binutils readelf:binutils make:make \
             curl:curl tar:tar python3:python openssl:openssl \
             mksquashfs:squashfs-tools unsquashfs:squashfs-tools \
             veritysetup:cryptsetup sbsign:sbsigntools sbverify:sbsigntools \
             ukify:systemd virt-fw-vars:python-virt-firmware \
             mcopy:mtools mmd:mtools mkfs.fat:dosfstools sfdisk:util-linux \
             wipefs:util-linux lsblk:util-linux qemu-system-x86_64:qemu-base; do
    command -v "${cmd%%:*}" >/dev/null 2>&1 || miss+=("${cmd%%:*} (${cmd##*:})")
  done
  # musl is linked into every binary but is NOT built from source here -- it is
  # host-provided. SOURCES.md records this honestly; the build must have it.
  [ -f /usr/lib/musl/lib/rcrt1.o ] || miss+=("/usr/lib/musl/lib/rcrt1.o (musl)")
  [ -f "$STUB" ]      || miss+=("$STUB (systemd)")
  [ -f "$OVMF_CODE" ] || miss+=("$OVMF_CODE (edk2-ovmf)")
  [ -f "$OVMF_VARS" ] || miss+=("$OVMF_VARS (edk2-ovmf)")
  if [ "${#miss[@]}" -gt 0 ]; then
    echo "FAIL: missing host dependencies:" >&2
    printf '  - %s\n' "${miss[@]}" >&2
    return 1
  fi
  printf '  all host tools present\n'
}

# download, verify, extract ONE pinned tarball. verification is per-source and
# happens before extraction -- the old bulk `sha256sum -c` ran after only two of
# five sources had been downloaded, so on a clean clone it failed, and in a tree
# that already had src/ populated it passed. that is why nobody saw it.
get() {
  local url="$1" tar="$2" dir="$3"
  [ -f "src/$tar" ] || curl -fL --progress-bar "$url" -o "src/$tar"
  grep -q " $tar$" sources.sha256 || { echo "FAIL: $tar not pinned in sources.sha256" >&2; return 1; }
  ( cd src && grep " $tar$" ../sources.sha256 | sha256sum -c --strict - >/dev/null ) || {
    echo "FAIL: $tar digest mismatch -- refusing to extract" >&2; return 1; }
  [ -d "src/$dir" ] || tar -C src -xf "src/$tar"
}

fetch() {
  say "fetching + verifying sources"
  mkdir -p src

  # G8 -- every source pinned, verified BEFORE extraction. a verified boot
  # chain rooted in an unverified tarball proves nothing.
  get "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KVER.tar.xz" \
      "linux-$KVER.tar.xz" "linux-$KVER"
  get "https://busybox.net/downloads/busybox-$BBVER.tar.bz2" \
      "busybox-$BBVER.tar.bz2" "busybox-$BBVER"
  # bash: GNU publishes PGP sigs, not digest lists, so the pin is anchored to
  # a signature check done once by hand (Chet Ramey, DSA 7C0135FB...).
  get "https://ftp.gnu.org/gnu/bash/bash-$BASHVER.tar.gz" \
      "bash-$BASHVER.tar.gz" "bash-$BASHVER"
  # ii: suckless publishes no signature, so this pin is trust-on-first-use
  # over TLS only. see SOURCES.md -- it is weaker than the others on purpose.
  get "https://dl.suckless.org/tools/ii-$IIVER.tar.gz" \
      "ii-$IIVER.tar.gz" "ii-$IIVER"
  # bearssl: also no upstream signature -- see SOURCES.md
  get "https://bearssl.org/bearssl-$BSSLVER.tar.gz" \
      "bearssl-$BSSLVER.tar.gz" "bearssl-$BSSLVER"

  # completeness: now that every source is present, re-check the whole pinned
  # set. this catches a tarball that is pinned but no longer fetched, which the
  # per-source checks above cannot see.
  ( cd src && grep -E '\.tar\.(xz|bz2|gz)$' ../sources.sha256 | sha256sum -c --strict - >/dev/null ) || {
    echo "FAIL: pinned source set does not match src/" >&2; return 1; }
  printf '  %d sources verified against sources.sha256\n' \
    "$(grep -cE '\.tar\.(xz|bz2|gz)$' sources.sha256)"
}

kernel() {
  say "building kernel $KVER"
  local d="src/linux-$KVER"
  make -C "$d" tinyconfig
  # kernel.config now has two classes of line: `CONFIG_X=y` (must be on) and
  # `CONFIG_X=n` (must be off). split them -- feeding a `=n` line to --enable
  # would turn hardening-disable requests into enables.
  local enables disables
  enables=$(grep -oP '^CONFIG_[A-Z0-9_]+(?==y$)' kernel.config)
  disables=$(grep -oP '^CONFIG_[A-Z0-9_]+(?==n$)' kernel.config)
  # olddefconfig silently drops any option whose deps are unmet, so enable to a
  # fixpoint (a parent enabled on pass N unlocks its children on pass N+1) and
  # then GATE on it -- a kernel quietly missing squashfs still "builds fine".
  # disables run each pass too: olddefconfig can re-select a choice default
  # (e.g. the lockdown FORCE_NONE member) that an earlier pass turned off.
  for _pass in 1 2 3; do
    while read -r opt; do
      [ -n "$opt" ] && "$d/scripts/config" --file "$d/.config" --enable "$opt"
    done <<< "$enables"
    while read -r opt; do
      [ -n "$opt" ] && "$d/scripts/config" --file "$d/.config" --disable "$opt"
    done <<< "$disables"
    make -C "$d" olddefconfig >/dev/null
  done
  local missing=() present=()
  while read -r opt; do
    [ -n "$opt" ] || continue
    grep -q "^$opt=y" "$d/.config" || missing+=("$opt")
  done <<< "$enables"
  # a `=n` opt that is present as =y is a hardening request that silently lost
  while read -r opt; do
    [ -n "$opt" ] || continue
    grep -q "^$opt=y" "$d/.config" && present+=("$opt")
  done <<< "$disables"
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "FAIL: kernel options requested but not enabled: ${missing[*]}" >&2
    return 1
  fi
  if [ "${#present[@]}" -gt 0 ]; then
    echo "FAIL: kernel options requested off but still enabled: ${present[*]}" >&2
    return 1
  fi
  grep -q '^CONFIG_MODULES=y' "$d/.config" && { echo "FAIL: module loader enabled" >&2; return 1; }
  echo 0 > "$d/.version"
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
  say "building busybox $BBVER (${BBMODE:-trim})"
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

  if [ "${BBMODE:-trim}" = trim ]; then
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

bash_() {
  say "building bash $BASHVER (musl static-pie)"
  local d="src/bash-$BASHVER" specs="$PWD/musl-static-pie.specs"
  [ -d "$d" ] || { echo "FAIL: bash source missing, run fetch" >&2; return 1; }
  if [ ! -f "$d/bash" ]; then
    ( cd "$d" && CC="gcc -specs=$specs" ./configure --host=x86_64-pc-linux-gnu \
        --without-bash-malloc --disable-nls --enable-static-link >/dev/null 2>&1 \
      && make -j"$JOBS" >/dev/null 2>&1 )
  fi
  [ -f "$d/bash" ] || { echo "FAIL: bash did not build" >&2; return 1; }
  strip "$d/bash"; cp "$d/bash" bash
  ./bash -c 'exit 0' || { echo "FAIL: built bash does not run" >&2; return 1; }
  printf '  bash: %d bytes\n' "$(stat -c%s bash)"
}

ta() {
  say "compiling trust anchors"
  local d="src/bearssl-$BSSLVER"
  [ -x "$d/build/brssl" ] || { echo "FAIL: brssl missing, run tls first" >&2; return 1; }
  local pems; pems=$(find trust -name '*.pem' | sort)
  [ -n "$pems" ] || { echo "FAIL: trust/ is empty -- refusing to build a client that trusts nothing" >&2; return 1; }
  # shellcheck disable=SC2086
  "$d/build/brssl" ta $pems > ta.h || return 1
  local n; n=$(grep -oE 'TAs_NUM[[:space:]]+[0-9]+' ta.h | grep -oE '[0-9]+$')
  [ "${n:-0}" -gt 0 ] || { echo "FAIL: ta.h has no anchors" >&2; return 1; }
  printf '  %s trust anchor(s) compiled in:\n' "$n"
  local f; for f in $pems; do printf '    %s\n' "$(openssl x509 -in "$f" -noout -subject | sed 's/^subject=//')"; done
}

tls() {
  say "building bearssl + tlstunnel"
  local d="src/bearssl-$BSSLVER" specs="$PWD/musl-static-pie.specs"
  [ -f "$d/build/libbearssl.a" ] || \
    make -C "$d" CC="gcc -specs=$specs" CFLAGS="-W -Wall -Os -fPIE -isystem $PWD/sysroot/include" \
      build/libbearssl.a >/dev/null 2>&1
  [ -x "$d/build/brssl" ] || \
    make -C "$d" CC="gcc -specs=$specs" CFLAGS="-W -Wall -Os -fPIE -isystem $PWD/sysroot/include" \
      build/brssl >/dev/null 2>&1
  [ -f "$d/build/libbearssl.a" ] || { echo "FAIL: libbearssl.a did not build" >&2; return 1; }
  ta || return 1
  gcc -specs="$specs" -fPIE -Os -isystem "$PWD/sysroot/include" \
    -I"$d/inc" -I. -o tlstunnel tlstunnel.c "$d/build/libbearssl.a" || return 1
  { ./tlstunnel 2>&1 || true; } | has usage || { echo "FAIL: tlstunnel does not run" >&2; return 1; }
  printf '  tlstunnel: %d bytes\n' "$(stat -c%s tlstunnel)"
}

ii_() {
  say "building ii $IIVER (irc, musl static-pie)"
  local d="src/ii-$IIVER" specs="$PWD/musl-static-pie.specs"
  [ -d "$d" ] || { echo "FAIL: ii source missing, run fetch" >&2; return 1; }
  make -C "$d" clean >/dev/null 2>&1 || true
  make -C "$d" CC="gcc -specs=$specs" \
    CFLAGS="-fPIE -Os -isystem $PWD/sysroot/include" LDFLAGS="" >/dev/null 2>&1
  [ -f "$d/ii" ] || { echo "FAIL: ii did not build" >&2; return 1; }
  strip "$d/ii"; cp "$d/ii" ii
  # ii exits non-zero when printing usage, and pipefail would read that as a
  # build failure, so the producer is neutralised as well as the consumer.
  { ./ii 2>&1 || true; } | has usage || { echo "FAIL: built ii does not run" >&2; return 1; }
  printf '  ii: %d bytes\n' "$(stat -c%s ii)"
}

rootfs() {
  say "building read-only root"
  rm -rf root
  mkdir -p root/bin root/proc root/sys root/dev root/etc root/tmp
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
  # every component is REQUIRED. these were `[ -f x ] && cp x` -- one missing
  # binary silently produced a smaller image that still passed every gate.
  # a build that ships less than it claims must fail, not shrink.
  local b
  for b in bash ii tlstunnel; do
    [ -f "$b" ] || { echo "FAIL: $b not built -- run ./build.sh all" >&2; return 1; }
    cp "$b" "root/bin/$b"
  done

  # cmdchamp is content, not recipe -- it lives outside this repo. pin its
  # digest or the image quietly depends on the state of one directory on one
  # machine, and sources.sha256 stops describing what is in the image.
  local want have
  want=$(awk '$2=="cmdchamp"{print $1}' sources.sha256)
  [ -n "$want" ] || { echo "FAIL: cmdchamp not pinned in sources.sha256" >&2; return 1; }
  [ -f "$CMDCHAMP_SRC/cmdchamp" ] || { echo "FAIL: no cmdchamp at $CMDCHAMP_SRC" >&2; return 1; }
  have=$(sha256sum < "$CMDCHAMP_SRC/cmdchamp" | awk '{print $1}')
  [ "$want" = "$have" ] || {
    echo "FAIL: cmdchamp digest mismatch (pinned ${want:0:16}..., got ${have:0:16}...)" >&2; return 1; }
  mkdir -p root/opt/cmdchamp root/usr/bin
  cp "$CMDCHAMP_SRC/cmdchamp" root/opt/cmdchamp/cmdchamp
  chmod +x root/opt/cmdchamp/cmdchamp
  ln -sf /opt/cmdchamp/cmdchamp root/bin/cmdchamp
  # cmdchamp's shebang is #!/usr/bin/env bash and upstream content is not ours
  # to rewrite, so provide the path it expects.
  ln -sf /bin/busybox root/usr/bin/env

  # hand-written shims for things busybox lacks
  # overlay carries the tput shim cmdchamp needs and the udhcpc script without
  # which dhcp silently configures nothing. it was optional; under `set -e` a
  # failing test in an && list does not abort, so a missing overlay just
  # produced a quieter, more broken image.
  [ -d overlay ] || { echo "FAIL: overlay/ missing" >&2; return 1; }
  cp -r overlay/. root/

  cp init root/init
  chmod +x root/init
  echo 'heatos' > root/etc/hostname
  # without /etc/passwd, anything calling getpwuid() fails -- ii did exactly that
  printf 'root:x:0:0:root:/root:/bin/sh\n' > root/etc/passwd
  printf 'root:x:0:\n' > root/etc/group
  # root is read-only, so resolv.conf must live on the tmpfs udhcpc writes to
  ln -sf /tmp/resolv.conf root/etc/resolv.conf
  # squashfs-tools >= 4.6 reads SOURCE_DATE_EPOCH itself and clamps every
  # timestamp to it -- and hard-errors if you also pass -mkfs-time, which is
  # how this was caught. -processors 1 keeps block ordering deterministic.
  mksquashfs root rootfs.squashfs -noappend -no-xattrs -all-root -comp gzip -quiet -processors 1
  printf '  rootfs.squashfs: %d bytes (%d files)\n' "$(stat -c%s rootfs.squashfs)" "$(find root -type f -o -type l | wc -l)"
}

keys() {
  say "generating heatos secure boot keys"
  # idempotent against BOTH states: plaintext keys/db.key (freshly generated)
  # and sealed keys/db.key.enc (seal deletes db.key, so checking only the
  # plaintext made `all` regenerate certs over a sealed key -- old key, new
  # cert, sbverify fails. this was silent because `all` never ran end to end.)
  { [ -f keys/db.key ] || [ -f keys/db.key.enc ]; } && { echo "  already present (delete keys/ to regenerate)"; return 0; }
  mkdir -p keys
  for k in PK KEK db; do
    openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
      -subj "/CN=heatos $k/" -keyout "keys/$k.key" -out "keys/$k.crt" 2>/dev/null
    openssl x509 -in "keys/$k.crt" -outform DER -out "keys/$k.der"
  done
  chmod 700 keys; chmod 600 keys/*.key
  echo "  PK/KEK/db written to keys/ (gitignored, heatos-only -- NOT heatpc's)"
}

seal() {
  say "encrypting private keys"
  # fail loud rather than no-op: silently skipping an already-sealed keyset is
  # how you end up believing a new passphrase took effect when it did not.
  if [ ! -f keys/db.key ] && [ -f keys/db.key.enc ]; then
    echo "FAIL: keys are already sealed. use './build.sh reseal' to change the passphrase." >&2
    return 1
  fi
  [ -f keys/db.key ] || { echo "FAIL: no keys/db.key -- run ./build.sh keys first" >&2; return 1; }
  local pass
  if [ -n "${HEATOS_KEYPASS:-}" ]; then pass="$HEATOS_KEYPASS"
  else read -rsp "  passphrase for heatos signing keys: " pass; echo; fi
  [ -n "$pass" ] || { echo "FAIL: empty passphrase" >&2; return 1; }
  local k
  for k in PK KEK db; do
    [ -f "keys/$k.key" ] || continue
    HEATOS_PASS="$pass" openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
      -in "keys/$k.key" -out "keys/$k.key.enc" -pass env:HEATOS_PASS || return 1
    shred -u "keys/$k.key" 2>/dev/null || rm -f "keys/$k.key"
  done
  chmod 600 keys/*.enc
  echo "  sealed. plaintext keys removed from disk."
}

reseal() {
  say "changing the signing passphrase"
  unlock || return 1
  local newpass
  if [ -n "${HEATOS_NEWKEYPASS:-}" ]; then newpass="$HEATOS_NEWKEYPASS"
  else read -rsp "  NEW passphrase: " newpass; echo; fi
  [ -n "$newpass" ] || { echo "FAIL: empty passphrase" >&2; return 1; }
  local k
  for k in PK KEK db; do
    [ -f "$RAMKEYS/$k.key" ] || continue
    HEATOS_PASS="$newpass" openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
      -in "$RAMKEYS/$k.key" -out "keys/$k.key.enc.new" -pass env:HEATOS_PASS || return 1
    mv "keys/$k.key.enc.new" "keys/$k.key.enc"
  done
  lock
  echo "  passphrase changed."
}

unlock() {
  [ -f "$RAMKEYS/db.key" ] && return 0
  [ -f keys/db.key.enc ] || { echo "FAIL: keys/db.key.enc missing -- run ./build.sh keys then seal" >&2; return 1; }
  local pass
  if [ -n "${HEATOS_KEYPASS:-}" ]; then pass="$HEATOS_KEYPASS"
  else read -rsp "  passphrase to unlock signing keys: " pass; echo; fi
  mkdir -p "$RAMKEYS"; chmod 700 "$RAMKEYS"
  local k
  for k in PK KEK db; do
    [ -f "keys/$k.key.enc" ] || continue
    HEATOS_PASS="$pass" openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
      -in "keys/$k.key.enc" -out "$RAMKEYS/$k.key" -pass env:HEATOS_PASS 2>/dev/null \
      || { rm -rf "$RAMKEYS"; echo "FAIL: wrong passphrase" >&2; return 1; }
  done
  chmod 600 "$RAMKEYS"/*.key
  openssl rsa -in "$RAMKEYS/db.key" -noout 2>/dev/null \
    || { rm -rf "$RAMKEYS"; echo "FAIL: decrypted key is not a valid RSA key" >&2; return 1; }
  echo "  unlocked into RAM ($RAMKEYS)"
}

lock() {
  rm -rf "$RAMKEYS"
  echo "  locked -- plaintext keys wiped from RAM"
}

uki() {
  say "building + signing unified kernel image"
  [ -f cmdline.txt ] || { echo "FAIL: run verity first" >&2; return 1; }
  local stub="$STUB"
  [ -f "$stub" ] || { echo "FAIL: systemd-stub missing" >&2; return 1; }
  grep -q '^CONFIG_EFI_STUB=y' "src/linux-$KVER/.config" || {
    echo "FAIL: kernel lacks EFI_STUB -- firmware cannot load it" >&2; return 1; }

  unlock || return 1
  ukify build --linux=bzImage --cmdline="$(cat cmdline.txt)" --stub="$stub" --output=heatos.efi >/dev/null
  sbsign --key "$RAMKEYS/db.key" --cert keys/db.crt --output heatos-signed.efi heatos.efi >/dev/null \
    || { echo "FAIL: signing failed -- refusing to ship an unsigned image" >&2; rm -f heatos-signed.efi; return 1; }
  [ -f heatos-signed.efi ] || { echo "FAIL: no signed image produced" >&2; return 1; }
  sbverify --cert keys/db.crt heatos-signed.efi >/dev/null 2>&1 || {
    echo "FAIL: signature does not verify" >&2; return 1; }

  mkdir -p esp/EFI/BOOT
  cp heatos-signed.efi esp/EFI/BOOT/BOOTX64.EFI

  cp "$OVMF_VARS" ovmf-vars.fd
  virt-fw-vars --input ovmf-vars.fd --output ovmf-vars.fd \
    --set-pk  "$SBGUID" keys/PK.der \
    --add-kek "$SBGUID" keys/KEK.der \
    --add-db  "$SBGUID" keys/db.der >/dev/null 2>&1
  printf '  signed UKI: %d bytes, keys enrolled into ovmf-vars.fd\n' "$(stat -c%s heatos-signed.efi)"
}

# assemble the bootable stick image: GPT (fixed GUIDs) + FAT32 ESP carrying the
# signed UKI and the public keys for enrollment + raw heatos.img as p2. entirely
# deterministic (no root, no loop mount -- sfdisk + mtools), so the layout is
# reproducible even though we do not pin it: everything that MATTERS on the stick
# is already covered (p2 by image.sha256 + the verity tree, BOOTX64.EFI by the db
# signature). only FAT/GPT metadata is unauthenticated, and tampering it can at
# most deny boot, never change what runs.
stick() {
  say "assembling stick.img"
  [ -f heatos-signed.efi ] || { echo "FAIL: no signed UKI -- run ./build.sh uki" >&2; return 1; }
  [ -f heatos.img ]        || { echo "FAIL: no heatos.img -- run ./build.sh verity" >&2; return 1; }
  for k in PK KEK db; do [ -f "keys/$k.der" ] || { echo "FAIL: keys/$k.der missing" >&2; return 1; }; done

  local esp_bytes root_bytes esp_start_s esp_size_s root_start_s root_size_s total
  esp_bytes=$((STICK_ESP_MIB * 1024 * 1024))
  root_bytes=$(stat -c%s heatos.img)                 # already a 4K multiple (verity padded it)
  esp_start_s=2048                                    # 1 MiB, in 512B sectors
  esp_size_s=$((esp_bytes / 512))
  root_start_s=$(( (1 + STICK_ESP_MIB) * 1024 * 1024 / 512 ))
  root_size_s=$((root_bytes / 512))                  # exact: root_bytes is a 4K multiple
  total=$(( root_start_s * 512 + root_bytes + 1024 * 1024 ))   # + 1 MiB backup-GPT slack

  rm -f stick.img
  truncate -s "$total" stick.img

  # deterministic GPT: fixed disk id + per-partition uuids/types/names, no
  # timestamps in GPT (only CRCs), so identical inputs -> identical bytes.
  # named fields + sizes in SECTORS -- sfdisk rejects a bare 'B' byte suffix.
  sfdisk stick.img >/dev/null <<EOF
label: gpt
label-id: $GPT_DISK
start=$esp_start_s, size=$esp_size_s, type=C12A7328-F81F-11D2-BA4B-00A08693446B, uuid=$PU_ESP, name="HEATOS-ESP"
start=$root_start_s, size=$root_size_s, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=$PU_ROOT, name="HEATOS-ROOT"
EOF

  # FAT32 in a temp file, then dd into the ESP slot. --invariant drops the
  # volume id + creation timestamp that would otherwise randomise the bytes.
  rm -f esp.part; truncate -s "$esp_bytes" esp.part
  mkfs.fat --invariant -F 32 -n HEATOS esp.part >/dev/null
  # pin mtime of everything we copy so mcopy writes deterministic dir entries
  touch -d "@$SOURCE_DATE_EPOCH" heatos-signed.efi keys/PK.der keys/KEK.der keys/db.der
  mmd   -i esp.part ::/EFI ::/EFI/BOOT ::/heatos-keys
  mcopy -pm -i esp.part heatos-signed.efi ::/EFI/BOOT/BOOTX64.EFI
  mcopy -pm -i esp.part keys/PK.der keys/KEK.der keys/db.der ::/heatos-keys/
  dd if=esp.part    of=stick.img bs=1M seek=1                     conv=notrunc status=none
  dd if=heatos.img  of=stick.img bs=1M seek=$((1 + STICK_ESP_MIB)) conv=notrunc status=none
  rm -f esp.part
  printf '  stick.img: %d bytes (esp %d MiB + root %d bytes)\n' "$(stat -c%s stick.img)" "$STICK_ESP_MIB" "$root_bytes"
}

# write stick.img to a real removable disk. this is dd-to-wrong-disk territory,
# so every guard is fail-closed and there is deliberately NO --force flag.
usb() {
  local dev="${1:-}"
  [ -n "$dev" ] || { echo "FAIL: usage: ./build.sh usb /dev/sdX" >&2; return 1; }
  [ -b "$dev" ] || { echo "FAIL: $dev is not a block device" >&2; return 1; }
  local n; n=$(basename "$dev")
  [ -e "/sys/block/$n" ] || { echo "FAIL: $dev is not a whole disk (partitions not allowed)" >&2; return 1; }
  [ "$(cat "/sys/block/$n/removable" 2>/dev/null)" = 1 ] || {
    echo "FAIL: $dev is not removable -- refusing to touch a fixed disk" >&2; return 1; }
  if lsblk -nro MOUNTPOINTS "$dev" 2>/dev/null | grep -q .; then
    echo "FAIL: $dev (or a partition of it) is mounted -- unmount first" >&2; return 1; fi
  [ -f stick.img ] || stick || return 1

  local dev_bytes img_bytes model
  dev_bytes=$(( $(cat "/sys/block/$n/size") * 512 ))
  img_bytes=$(stat -c%s stick.img)
  [ "$dev_bytes" -ge "$img_bytes" ] || { echo "FAIL: $dev too small ($dev_bytes < $img_bytes)" >&2; return 1; }
  if [ "$dev_bytes" -gt $((128 * 1024 * 1024 * 1024)) ]; then
    echo "WARN: $dev is $((dev_bytes / 1024 / 1024 / 1024)) GiB -- larger than any usb stick, is this the right disk?" >&2
  fi
  model=$(cat "/sys/block/$n/device/model" 2>/dev/null | tr -s ' ' | sed 's/ *$//')
  echo "  target: $dev  size: $((dev_bytes / 1024 / 1024)) MiB  model: ${model:-unknown}"
  if wipefs -n "$dev" 2>/dev/null | grep -q .; then
    echo "  WARNING: $dev already contains a filesystem/partition signature -- it will be DESTROYED."
  fi
  # confirmation the user cannot bypass by hammering 'y': type the model back.
  local answer
  read -rp "  to confirm, type the disk model exactly ('${model:-unknown}'): " answer
  [ "$answer" = "${model:-unknown}" ] || { echo "FAIL: confirmation did not match -- aborted" >&2; return 1; }

  say "writing stick.img to $dev"
  dd if=stick.img of="$dev" bs=1M oflag=direct conv=fsync status=progress

  # verify by DIRECT-IO readback -- a page-cache read would just echo what we
  # wrote and prove nothing. compare the whole stick, then the p2 root region
  # against the pinned image digest.
  say "verifying written bytes"
  local want_stick have_stick want_root have_root root_off
  want_stick=$(sha256sum < stick.img | awk '{print $1}')
  have_stick=$(dd if="$dev" bs=1M iflag=direct count=$(( (img_bytes + 1048575) / 1048576 )) status=none | head -c "$img_bytes" | sha256sum | awk '{print $1}')
  [ "$want_stick" = "$have_stick" ] || { echo "FAIL: stick readback mismatch -- write did not land" >&2; return 1; }
  root_off=$(( (1 + STICK_ESP_MIB) * 1024 * 1024 ))
  want_root=$(awk '$1=="image"{print $2}' image.sha256)
  have_root=$(dd if="$dev" bs=1M skip=$((1 + STICK_ESP_MIB)) iflag=direct count=$(( ($(stat -c%s heatos.img) + 1048575) / 1048576 )) status=none | head -c "$(stat -c%s heatos.img)" | sha256sum | awk '{print $1}')
  if [ -n "$want_root" ] && [ "$want_root" != "$have_root" ]; then
    echo "FAIL: root partition on disk does not match pinned image digest" >&2; return 1; fi
  sync
  printf '\n  \033[1;32mdone -- %s carries a verified heatos\033[0m\n' "$dev"
  echo "  boot it: firmware boot menu -> USB. secure boot: enroll keys from the"
  echo "  stick's /heatos-keys (db, KEK, then PK last). see README."
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

  # fixed salt AND fixed uuid: the image must be reproducible. a random salt
  # would change the root hash for identical content; a random uuid left the
  # root hash stable and still changed the image bytes on every single build.
  veritysetup format heatos.img heatos.img \
    --hash-offset="$data" --data-blocks="$blocks" --salt="$SALT" --uuid="$VUUID" > verity.info
  local rh
  rh=$(awk '/Root hash/{print $NF}' verity.info)
  [ ${#rh} -eq 64 ] || { echo "FAIL: no root hash from veritysetup" >&2; return 1; }
  echo "$rh" > verity.roothash

  # veritysetup writes a superblock AT the hash offset, so the hash tree
  # itself starts one block later -- pointing the table at $blocks lands on
  # the superblock and the root mount fails with no verity error at all.
  # heatos.test is DEBUG scaffolding, and the cmdline lives INSIDE the UKI
  # signature -- so it must never ship in a production image. attack.sh
  # rebuilds a test-flavoured UKI for its own runs.
  local testflag=""
  [ "${HEATOS_TEST:-0}" = 1 ] && testflag=" heatos.test"
  # the root is named by PARTUUID, not /dev/vda: on a real machine the stick is
  # /dev/sda|sdb, and dm-init resolves PARTUUID= via early_lookup_bdev. one
  # cmdline, inside one signature, boots qemu and metal alike.
  #
  # dm-mod.waitfor polls (5ms) until the device exists -- usb enumeration takes
  # a second or two, and without this dm-init tries exactly once and the root
  # never appears (a silent hang rootwait cannot fix). there is NO timeout knob
  # in 6.12: an unsupported controller hangs at "waiting for device", visibly.
  #
  # console: serial LAST so it owns /dev/console (harness scrapes serial, output
  # stays byte-identical); tty0 first mirrors printk to a real screen.
  #
  # default dm-verity refuses only the bad block and lets boot continue if
  # nothing essential needed it. panic_on_corruption makes ANY corruption
  # anywhere fatal -- the machine refuses to run at all, which is the point.
  #
  # oops=panic + panic=-1: any oops becomes a fatal, non-recoverable halt (no
  # boot-and-limp). page_alloc.shuffle=1 activates SHUFFLE_PAGE_ALLOCATOR. the
  # rest of the hardening is compiled in (lockdown, kstack offset, slab), which
  # is stronger than a cmdline flag -- there is no runtime knob left to flip.
  local dev="PARTUUID=$PU_ROOT"
  printf 'dm-mod.waitfor=%s dm-mod.create="vroot,,,ro,0 %d verity 1 %s %s 4096 4096 %d %d sha256 %s %s 1 panic_on_corruption" root=/dev/dm-0 ro rootfstype=squashfs rootwait init=/init oops=panic panic=-1 page_alloc.shuffle=1 console=tty0 console=ttyS0,115200%s\n' \
    "$dev" "$((blocks * 8))" "$dev" "$dev" "$blocks" "$((blocks + 1))" "$rh" "$SALT" "$testflag" > cmdline.txt

  printf '  heatos.img: %d bytes  root hash: %s
' "$(stat -c%s heatos.img)" "$rh"
}

toolchain() {
  { gcc --version | head -1
    ld --version | head -1
    mksquashfs -version 2>&1 | head -1
    veritysetup --version
    sha256sum musl-static-pie.specs | awk '{print $1}'
  } | sha256sum | awk '{print $1}'
}

pin() {
  say "pinning the bytes this source produces"
  [ -f heatos.img ] || { echo "FAIL: no heatos.img -- build first" >&2; return 1; }
  { echo "# the exact artifact this source builds. regenerate with ./build.sh pin."
    echo "# G13 compares against this. a mismatch on the SAME toolchain means the"
    echo "# image no longer corresponds to the source; on a different toolchain it"
    echo "# only means you cannot independently verify this build."
    printf 'image     %s\n'   "$(sha256sum < heatos.img      | awk '{print $1}')"
    printf 'squashfs  %s\n'   "$(sha256sum < rootfs.squashfs | awk '{print $1}')"
    printf 'roothash  %s\n'   "$(cat verity.roothash)"
    printf 'toolchain %s\n'   "$(toolchain)"
  } > image.sha256
  cat image.sha256
}

size() {
  say "gates"
  local bad=0 ran=0
  local EXPECTED_GATES=17
  g() { printf '  %-42s %s
' "$1" "$2"; ran=$((ran+1)); [ "$2" = ok ] || bad=1; }

  local sz; sz=$(stat -c%s heatos.img)
  g "G1 image <= $IMAGE_MAX ($sz)" "$([ "$sz" -le "$IMAGE_MAX" ] && echo ok || echo FAIL)"

  local elfs interp exec_type
  elfs=$(find root -type f -exec sh -c 'head -c4 "$1" | grep -q ELF && echo "$1"' _ {} \; 2>/dev/null)
  interp=0; exec_type=0
  local rwe_stack=0
  for f in $elfs; do
    readelf -l "$f" 2>/dev/null | grep -q INTERP && interp=$((interp+1))
    readelf -h "$f" 2>/dev/null | grep -q 'Type:.*EXEC' && exec_type=$((exec_type+1))
    # GNU_STACK marked RWE = executable stack (the noexecstack link flag failed).
    # this one IS kernel-enforced, unlike RELRO in a static-pie binary.
    readelf -lW "$f" 2>/dev/null | awk '/GNU_STACK/{print $(NF)}' | has RWE && rwe_stack=$((rwe_stack+1))
  done
  g "G2 no dynamic loader ($interp with INTERP)" "$([ "$interp" -eq 0 ] && echo ok || echo FAIL)"
  g "G3 all ELF are PIE ($exec_type non-PIE)"    "$([ "$exec_type" -eq 0 ] && echo ok || echo FAIL)"
  g "G16 no executable stack ($rwe_stack RWE)"   "$([ "$rwe_stack" -eq 0 ] && echo ok || echo FAIL)"

  local suid ww
  suid=$(find root -type f \( -perm -4000 -o -perm -2000 \) | wc -l)
  ww=$(find root -type f -perm -0002 | wc -l)
  g "G4 no setuid/setgid ($suid)"      "$([ "$suid" -eq 0 ] && echo ok || echo FAIL)"
  g "G5 no world-writable ($ww)"       "$([ "$ww" -eq 0 ] && echo ok || echo FAIL)"

  local want have
  want=$(cat verity.roothash)
  have=$(grep -oE 'sha256 [0-9a-f]{64}' cmdline.txt | awk '{print $2}')
  g "G6 cmdline root hash matches tree" "$([ "$want" = "$have" ] && echo ok || echo FAIL)"

  # a full reproducibility check needs two builds; this asserts the mechanism
  # that makes it possible is still in place, which is cheap and catches drift.
  local pinned; pinned=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%d 2>/dev/null)
  g "G10 build clock pinned ($pinned)" \
    "$(strings busybox 2>/dev/null | has "BusyBox v.*$pinned" && echo ok || echo FAIL)"

  # find, not ls: `ls nonexistent | wc -l` exits non-zero under pipefail and
  # set -e then kills the whole gate run silently. this bit us four times.
  local plain; plain=$(find keys -maxdepth 1 -name '*.key' 2>/dev/null | wc -l)
  g "G11 no plaintext private key on disk ($plain)" "$([ "$plain" -eq 0 ] && echo ok || echo FAIL)"

  # G12 -- the image contains everything the manifest declares. component
  # copies were `[ -f x ] && cp x`, so a component that failed to build made
  # the image smaller and every other gate still went green.
  local listing missing=0 want_n=0 p
  listing=$(unsquashfs -l rootfs.squashfs 2>/dev/null | sed 's|^squashfs-root/||')
  while read -r p; do
    case "$p" in ''|'#'*) continue ;; esac
    want_n=$((want_n+1))
    if [ "$(printf '%s\n' "$listing" | grep -cFx -- "$p" || true)" = 0 ]; then
      missing=$((missing+1)); printf '    missing from image: %s\n' "$p" >&2
    fi
  done < manifest
  g "G12 image has all $want_n manifest entries ($missing missing)" \
    "$([ "$missing" -eq 0 ] && [ "$want_n" -gt 0 ] && echo ok || echo FAIL)"

  # G13 -- the artifact matches the digest committed alongside the source.
  # this is the whole point of a pinned clock, salt and uuid: without it,
  # "reproducible" is a claim in a README that nothing ever checks.
  if [ -f image.sha256 ]; then
    local want_img have_img want_sq have_sq want_tc have_tc
    want_img=$(awk '$1=="image"{print $2}'     image.sha256)
    want_sq=$(awk '$1=="squashfs"{print $2}'   image.sha256)
    want_tc=$(awk '$1=="toolchain"{print $2}'  image.sha256)
    have_img=$(sha256sum < heatos.img | awk '{print $1}')
    have_sq=$(sha256sum < rootfs.squashfs | awk '{print $1}')
    have_tc=$(toolchain)
    if [ "$want_tc" != "$have_tc" ]; then
      g "G13 reproducible (toolchain differs, not checked)" ok
      printf '    this gcc/squashfs-tools is not the one the pin was taken with,\n' >&2
      printf '    so a byte mismatch here would prove nothing. rebuild is unverified.\n' >&2
    else
      # check the squashfs digest too -- pin() records it, so a mismatch there
      # localises drift to the filesystem vs the verity padding/tree, and stops
      # the recorded line from being decoration nothing ever reads.
      g "G13 image matches committed digest" \
        "$([ "$want_img" = "$have_img" ] && [ "$want_sq" = "$have_sq" ] && echo ok || echo FAIL)"
      [ "$want_img" = "$have_img" ] || \
        printf '    image pinned %s\n    image built  %s\n' "${want_img:0:32}..." "${have_img:0:32}..." >&2
      [ "$want_sq" = "$have_sq" ] || \
        printf '    squashfs pinned %s\n    squashfs built  %s\n' "${want_sq:0:32}..." "${have_sq:0:32}..." >&2
    fi
  else
    g "G13 image digest pinned" FAIL
    printf '    no image.sha256 -- run ./build.sh pin\n' >&2
  fi

  g "G7 kernel has no module loader" "$(grep -q '^CONFIG_MODULES=y' "src/linux-$KVER/.config" && echo FAIL || echo ok)"

  # G14 -- the built kernel actually honours the config contract. kernel() checks
  # this at build time; re-checking here catches a stale prebuilt .config that
  # was never rebuilt after kernel.config changed.
  local kc="src/linux-$KVER/.config" k_miss=0 k_bad=0 opt
  if [ -f "$kc" ]; then
    while read -r opt; do
      [ -n "$opt" ] || continue
      grep -q "^$opt=y" "$kc" || { k_miss=$((k_miss+1)); printf '    config not enabled: %s\n' "$opt" >&2; }
    done < <(grep -oP '^CONFIG_[A-Z0-9_]+(?==y$)' kernel.config)
    while read -r opt; do
      [ -n "$opt" ] || continue
      grep -q "^$opt=y" "$kc" && { k_bad=$((k_bad+1)); printf '    config still on: %s\n' "$opt" >&2; }
    done < <(grep -oP '^CONFIG_[A-Z0-9_]+(?==n$)' kernel.config)
    g "G14 kernel hardening config ($k_miss off, $k_bad leaked)" \
      "$([ "$k_miss" -eq 0 ] && [ "$k_bad" -eq 0 ] && echo ok || echo FAIL)"
  else
    g "G14 kernel hardening config" FAIL
    printf '    no %s\n' "$kc" >&2
  fi

  # G15 -- the tamper-proof hardening lives on the cmdline (inside the UKI
  # signature). assert every param that must be there is.
  local c15=0 want15
  for want15 in 'panic_on_corruption' 'oops=panic' 'panic=-1' 'page_alloc.shuffle=1' 'dm-mod.waitfor=PARTUUID='; do
    grep -qF "$want15" cmdline.txt || { c15=$((c15+1)); printf '    cmdline missing: %s\n' "$want15" >&2; }
  done
  g "G15 cmdline hardening params ($c15 missing)" "$([ "$c15" -eq 0 ] && echo ok || echo FAIL)"

  # G18 -- no firmware blobs in the image. r8169 pulls in FW_LOADER; if a blob
  # ever gets shipped it is unverified-by-vendor content on a verified system.
  local fw
  fw=$(unsquashfs -l rootfs.squashfs 2>/dev/null | grep -c 'squashfs-root/lib/firmware' || true)
  g "G18 no firmware blobs in image ($fw)" "$([ "${fw:-0}" -eq 0 ] && echo ok || echo FAIL)"

  # G17 -- stick.img is coherent with the pinned artifacts: right PARTUUIDs, p2
  # byte-equal to heatos.img, ESP carries the exact signed UKI.
  if [ -f stick.img ]; then
    local s_ok=1 j pe pr root_off
    j=$(sfdisk -J stick.img 2>/dev/null || true)
    printf '%s' "$j" | grep -qi "\"$PU_ESP\""  || { s_ok=0; printf '    esp PARTUUID absent\n' >&2; }
    printf '%s' "$j" | grep -qi "\"$PU_ROOT\"" || { s_ok=0; printf '    root PARTUUID absent\n' >&2; }
    root_off=$(( (1 + STICK_ESP_MIB) * 1024 * 1024 ))
    cmp -s -n "$(stat -c%s heatos.img)" heatos.img <(dd if=stick.img bs=1M skip=$((1 + STICK_ESP_MIB)) count=$(( ($(stat -c%s heatos.img) + 1048575) / 1048576 )) status=none 2>/dev/null) \
      || { s_ok=0; printf '    p2 region != heatos.img\n' >&2; }
    mcopy -n -i stick.img@@1M ::/EFI/BOOT/BOOTX64.EFI /tmp/heatos-esp-uki.$$ 2>/dev/null \
      && cmp -s heatos-signed.efi /tmp/heatos-esp-uki.$$ || { s_ok=0; printf '    ESP UKI != heatos-signed.efi\n' >&2; }
    rm -f /tmp/heatos-esp-uki.$$
    g "G17 stick.img coherent with artifacts" "$([ "$s_ok" -eq 1 ] && echo ok || echo FAIL)"
  else
    g "G17 stick.img coherent" FAIL
    printf '    no stick.img -- run ./build.sh stick\n' >&2
  fi

  # G19 -- the whole bootable system fits the size claim, not just the disk
  # image. the UKI (kernel + cmdline) lives on the ESP and was never gated.
  if [ -f heatos-signed.efi ]; then
    local whole; whole=$(( $(stat -c%s heatos-signed.efi) + $(stat -c%s heatos.img) ))
    g "G19 UKI + image <= $IMAGE_MAX ($whole)" "$([ "$whole" -le "$IMAGE_MAX" ] && echo ok || echo FAIL)"
  else
    g "G19 UKI + image size" FAIL
    printf '    no heatos-signed.efi -- run ./build.sh uki\n' >&2
  fi

  # a gate that dies mid-run under set -e looked exactly like a passing one,
  # so prove every gate actually executed.
  if [ "$ran" -ne "$EXPECTED_GATES" ]; then
    printf '\033[1;31m  only %d of %d gates ran -- the gate run was truncated\033[0m\n\n' "$ran" "$EXPECTED_GATES"
    return 1
  fi

  echo
  [ "$bad" -eq 0 ] && printf '[1;32m  all gates green -- %d bytes, %d to spare[0m

' "$sz" "$((IMAGE_MAX - sz))" \
                   || { printf '[1;31m  GATES FAILED[0m

'; return 1; }
}

# boot the WHOLE partitioned stick under qemu -- the exact bytes that get dd'd
# to a real disk. OVMF finds BOOTX64.EFI on the stick's own ESP (p1); root is
# resolved by PARTUUID from p2, identically to real hardware. no more fat:esp.
boot() {
  [ -f ovmf-vars.fd ] || { echo "FAIL: run ./build.sh uki first" >&2; return 1; }
  [ -f stick.img ] || stick || return 1
  qemu-system-x86_64 -machine q35,smm=on -m 256 \
    -global driver=cfi.pflash01,property=secure,value=on \
    -drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,unit=1,file=ovmf-vars.fd \
    -drive file="${1:-stick.img}",if=virtio,format=raw,readonly=on \
    -nic user,model=virtio-net-pci \
    -nographic -no-reboot
}

# same, but attach the stick as an emulated USB mass-storage device on xHCI --
# exercises the real boot path (usb enumeration, dm-mod.waitfor polling, the
# removable-media \EFI\BOOT\BOOTX64.EFI fallback) without any hardware.
bootusb() {
  [ -f ovmf-vars.fd ] || { echo "FAIL: run ./build.sh uki first" >&2; return 1; }
  [ -f stick.img ] || stick || return 1
  qemu-system-x86_64 -machine q35,smm=on -m 256 \
    -global driver=cfi.pflash01,property=secure,value=on \
    -drive if=pflash,format=raw,unit=0,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,unit=1,file=ovmf-vars.fd \
    -device qemu-xhci,id=xhci \
    -drive if=none,id=stick,format=raw,readonly=on,file="${1:-stick.img}" \
    -device usb-storage,bus=xhci.0,drive=stick \
    -nic user,model=virtio-net-pci \
    -nographic -no-reboot
}

case "${1:-all}" in
  deps|fetch|kernel|headers|busybox|bash_|ii_|tls|ta|rootfs|verity|keys|seal|reseal|unlock|lock|uki|stick|usb|pin|size|boot|bootusb) "$@" ;;
  all)
    deps; fetch; kernel; headers; busybox; bash_; tls; ii_; rootfs; verity; keys
    # clean clone makes plaintext keys; seal them so uki's unlock has db.key.enc
    # and G11 stays green. a sealed tree short-circuits keys() and skips this.
    if [ -f keys/db.key ]; then seal; fi
    uki; stick; size ;;
  *) echo "usage: $0 {deps|fetch|kernel|headers|busybox|bash_|ii_|tls|ta|rootfs|verity|keys|seal|reseal|unlock|lock|uki|stick|usb <dev>|pin|size|boot|bootusb|all}"; exit 1 ;;
esac

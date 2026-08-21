#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

KVER="${KVER:-6.12.43}"
BBVER="${BBVER:-1.37.0}"
BASHVER="${BASHVER:-5.3}"
IIVER="${IIVER:-2.0}"
CMDCHAMP_SRC="${CMDCHAMP_SRC:-$HOME/projects/cmdchamp}"
# plaintext private keys live ONLY here, only while unlocked. /dev/shm is
# tmpfs, so nothing lands on disk.
RAMKEYS="/dev/shm/heatos-keys-$(id -u)"
JOBS="$(nproc)"
IMAGE_MAX=8388608
SALT=48454154534f530000000000000000000000000000000000000000000000000a
SBGUID=11111111-2222-3333-4444-555555555555
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

  # bash: GNU publishes PGP sigs, not digest lists, so the pin is anchored to
  # a signature check done once by hand (Chet Ramey, DSA 7C0135FB...).
  local bashtar="bash-$BASHVER.tar.gz"
  [ -f "src/$bashtar" ] || curl -fL "https://ftp.gnu.org/gnu/bash/$bashtar" -o "src/$bashtar"
  grep -q " $bashtar$" sources.sha256 || { echo "FAIL: $bashtar not pinned" >&2; return 1; }
  [ -d "src/bash-$BASHVER" ] || tar -C src -xf "src/$bashtar"

  # ii: suckless publishes no signature, so this pin is trust-on-first-use
  # over TLS only. see SOURCES.md -- it is weaker than the others on purpose.
  local iitar="ii-$IIVER.tar.gz"
  [ -f "src/$iitar" ] || curl -fL "https://dl.suckless.org/tools/$iitar" -o "src/$iitar"
  grep -q " $iitar$" sources.sha256 || { echo "FAIL: $iitar not pinned" >&2; return 1; }
  [ -d "src/ii-$IIVER" ] || tar -C src -xf "src/$iitar"
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
  # bash + cmdchamp: the game is hard bash (assoc arrays, [[ ]], =~), so we
  # ship bash rather than attempt an ash port.
  if [ -f bash ]; then
    cp bash root/bin/bash
    if [ -d "$CMDCHAMP_SRC" ]; then
      mkdir -p root/opt/cmdchamp
      cp "$CMDCHAMP_SRC/cmdchamp" root/opt/cmdchamp/cmdchamp
      chmod +x root/opt/cmdchamp/cmdchamp
      ln -sf /opt/cmdchamp/cmdchamp root/bin/cmdchamp
      # cmdchamp's shebang is #!/usr/bin/env bash and upstream content is not
      # ours to rewrite, so provide the path it expects.
      mkdir -p root/usr/bin
      ln -sf /bin/busybox root/usr/bin/env
    fi
  fi

  [ -f ii ] && cp ii root/bin/ii

  # hand-written shims for things busybox lacks
  [ -d overlay ] && cp -r overlay/. root/

  cp init root/init
  chmod +x root/init
  echo 'heatos' > root/etc/hostname
  # without /etc/passwd, anything calling getpwuid() fails -- ii did exactly that
  printf 'root:x:0:0:root:/root:/bin/sh\n' > root/etc/passwd
  printf 'root:x:0:\n' > root/etc/group
  # root is read-only, so resolv.conf must live on the tmpfs udhcpc writes to
  ln -sf /tmp/resolv.conf root/etc/resolv.conf
  mksquashfs root rootfs.squashfs -noappend -no-xattrs -all-root -comp gzip -quiet -processors 1
  printf '  rootfs.squashfs: %d bytes (%d files)\n' "$(stat -c%s rootfs.squashfs)" "$(find root -type f -o -type l | wc -l)"
}

keys() {
  say "generating heatos secure boot keys"
  [ -f keys/db.key ] && { echo "  already present (delete keys/ to regenerate)"; return 0; }
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
  local stub=/usr/lib/systemd/boot/efi/linuxx64.efi.stub
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

  cp /usr/share/edk2/x64/OVMF_VARS.4m.fd ovmf-vars.fd
  virt-fw-vars --input ovmf-vars.fd --output ovmf-vars.fd \
    --set-pk  "$SBGUID" keys/PK.der \
    --add-kek "$SBGUID" keys/KEK.der \
    --add-db  "$SBGUID" keys/db.der >/dev/null 2>&1
  printf '  signed UKI: %d bytes, keys enrolled into ovmf-vars.fd\n' "$(stat -c%s heatos-signed.efi)"
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
  # heatos.test is DEBUG scaffolding, and the cmdline lives INSIDE the UKI
  # signature -- so it must never ship in a production image. attack.sh
  # rebuilds a test-flavoured UKI for its own runs.
  local testflag=""
  [ "${HEATOS_TEST:-0}" = 1 ] && testflag=" heatos.test"
  # default dm-verity refuses only the bad block and lets boot continue if
  # nothing essential needed it. panic_on_corruption makes ANY corruption
  # anywhere fatal -- the machine refuses to run at all, which is the point.
  printf 'dm-mod.create="vroot,,,ro,0 %d verity 1 /dev/vda /dev/vda 4096 4096 %d %d sha256 %s %s 1 panic_on_corruption" root=/dev/dm-0 ro rootfstype=squashfs rootwait init=/init console=ttyS0,115200%s\n' \
    "$((blocks * 8))" "$blocks" "$((blocks + 1))" "$rh" "$SALT" "$testflag" > cmdline.txt

  printf '  heatos.img: %d bytes  root hash: %s
' "$(stat -c%s heatos.img)" "$rh"
}

size() {
  say "gates"
  local bad=0 ran=0
  local EXPECTED_GATES=9
  g() { printf '  %-42s %s
' "$1" "$2"; ran=$((ran+1)); [ "$2" = ok ] || bad=1; }

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

  # a full reproducibility check needs two builds; this asserts the mechanism
  # that makes it possible is still in place, which is cheap and catches drift.
  local pinned; pinned=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%d 2>/dev/null)
  g "G10 build clock pinned ($pinned)" \
    "$(strings busybox 2>/dev/null | has "BusyBox v.*$pinned" && echo ok || echo FAIL)"

  # find, not ls: `ls nonexistent | wc -l` exits non-zero under pipefail and
  # set -e then kills the whole gate run silently. this bit us four times.
  local plain; plain=$(find keys -maxdepth 1 -name '*.key' 2>/dev/null | wc -l)
  g "G11 no plaintext private key on disk ($plain)" "$([ "$plain" -eq 0 ] && echo ok || echo FAIL)"

  g "G7 kernel has no module loader" "$(grep -q '^CONFIG_MODULES=y' "src/linux-$KVER/.config" && echo FAIL || echo ok)"

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

boot() {
  [ -f ovmf-vars.fd ] || { echo "FAIL: run ./build.sh uki first" >&2; return 1; }
  qemu-system-x86_64 -machine q35,smm=on -m 256 \
    -global driver=cfi.pflash01,property=secure,value=on \
    -drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd \
    -drive if=pflash,format=raw,unit=1,file=ovmf-vars.fd \
    -drive file="${1:-heatos.img}",if=virtio,format=raw,readonly=on \
    -drive file=fat:esp,format=raw,if=virtio,readonly=on \
    -nographic -no-reboot
}

case "${1:-all}" in
  fetch|kernel|headers|busybox|bash_|ii_|rootfs|verity|keys|seal|reseal|unlock|lock|uki|size|boot) "$1" ;;
  all) fetch; kernel; headers; busybox; rootfs; verity; keys; uki; size ;;
  *) echo "usage: $0 {fetch|kernel|busybox|initramfs|floppy|size|run|boot|all}"; exit 1 ;;
esac

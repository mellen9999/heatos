# xos

xos -- an operating system that lives on a usb stick and can prove it hasn't been
altered. plug it in, boot it, and your machine's own disks are never touched --
xos ships no driver that can see them. pull the stick and nothing remains;
nothing was ever written.

every block of the root filesystem is covered by a hash tree. the tree's root
hash sits on the kernel command line, the command line sits inside a signed
boot image, and the firmware refuses to run that image unless it's signed by a
key you hold. change one byte anywhere on the stick and the kernel refuses the
read rather than reporting it afterwards.

## the stick

`./build.sh usb /dev/sdX` writes a bootable stick: a GPT with an EFI system
partition (the signed kernel + your public keys) and a second partition holding
the verified root. the writer refuses anything that isn't a removable whole
disk, refuses a mounted one, makes you type the disk's model back before it
writes, and reads every byte back with direct I/O to confirm the write landed.

boot it from your firmware's boot menu. with secure boot off, the firmware just
runs it. with secure boot on, enroll your xos keys first (see below) and the
firmware verifies the signature on every boot.

the root is named on the cmdline by PARTUUID, never by `/dev/sda`, and the
kernel waits for that partition to appear -- so the same signed image boots
whether the stick enumerates as the first disk or the third.

the boot banner prints four words derived from the image's root hash on the
signed cmdline -- `this image is: cobra drifter payday willow`. write them on
the stick. a swapped or superseded stick speaks different words; a tampered
one does not speak at all. they change only when the image is re-pinned, so
re-memorize after a reflash.

## the chain

    firmware (secure boot, your enrolled keys)
      verifies -> signed UKI  (kernel + cmdline in one signed PE)
                    carries -> verity root hash + the root's PARTUUID
                                 covers -> every block of a read-only squashfs

each link is checked by the one above it. one key at the top, complete
coverage at the bottom.

and one link pointing backwards: `dbx`, the revocation list, which is the only
part of the chain that can say an image is *old*.

## install

    ./build.sh install        # the whole thing, one command

`install` builds the image if it is not already there, auto-detects the usb
stick (only ever a **removable** disk -- your fixed drives are never listed, so
it cannot target the wrong one), flashes it, **reads every byte back and checks
it against the pinned digest**, and offers to add the encrypted state partition.
name the disk explicitly -- `./build.sh install /dev/sdX` -- if more than one
removable disk is attached. before it writes anything it makes you type the
disk's model back, so a wrong path cannot wipe a drive on a slip of the enter
key.

## build

    ./build.sh all            # sources verified against pinned digests, then built
    ./selftest.sh             # adversarial self-test: asserts every tamper attempt is refused
    ./build.sh boot           # boots the real chain in qemu (dev only)
    ./build.sh usb /dev/sdX   # write a real bootable stick (install wraps this)
    ./build.sh addstate /dev/sdX  # add the encrypted state partition to a flashed stick
    ./build.sh revoke IMG     # retire a superseded image so it can never boot again

qemu is the development and test rig -- the self-test needs to byte-flip boot
media, which you can't do to a machine you're running on. the stick is the
product. `./build.sh bootusb` runs the exact stick image through emulated USB,
so the real boot path (enumeration, the wait-for-device poll) is testable
without hardware.

the repo holds recipes, never artifacts -- the pre-commit hook refuses any
staged file whose magic says ELF, PE or squashfs, whatever it is named. that
rule exists because a name-based version of it missed three committed
binaries, and the build preferred them over building from source.

`git pull && ./build.sh all` relinks the whole system, which is what makes
static linking survivable when a dependency gets a CVE.

## remote access

xos ships no wifi driver -- a wifi chip needs a firmware blob loaded into it,
and "a firmware blob shipped in the image" is a hard build failure (see
`what's enforced` below). the answer is usb: an android phone in tethering
mode, or a plain usb-ethernet dongle, both enumerate as a wired NIC over xhci
and need no firmware at all. plug either in and `udhcpc` runs on it exactly
like a wired port -- any laptop plus a phone is online, firmware-free.

off by default, and it can only be switched on from the encrypted state
partition -- so an attacker holding the stick cannot even see that it exists,
let alone enable it.

the model is dial-OUT. xos connects to a machine you control (call it titan)
over wireguard, and the ssh server binds to the wireguard address alone. xos
never opens a port on the network it is plugged into: `nmap` from that LAN finds
nothing. you reach xos by sshing back down the tunnel.

three things make a dropped connection survivable, each solving a different
failure: wireguard roams, so a changed IP or a dead link resumes rather than
resets; dropbear-on-wireguard keeps xos invisible; and abduco keeps the session
alive, so you ssh back in and `abduco -a work` straight into what was running.

to enable it, put two files on p3 (which is encrypted, so this is the opt-in):

    /tmp/home/wg0.conf          your wireguard config: private key, titan's
                                public key + endpoint, an Address = line
    authorized_keys             titan's PUBLIC ssh key -- either baked into the
                                image at etc/dropbear/authorized_keys (verity
                                covers it) or dropped on p3

on the next unlock, init brings up `wg0`, generates the ssh host key on p3 if it
is not there yet (a host key in the reproducible image would be a *published*
private key), and starts dropbear bound to the tunnel. pubkey only -- password
auth is compiled out, and xos is single-user root, so there is no password to
guess and no second account to find.

`dropbearkey`, `dbclient` and `wg` ship for making keys and driving the tunnel
by hand; `learn` teaches the whole flow end to end.

## secure boot: enrolling your keys

`./build.sh all` generates a platform key (PK), key-exchange key (KEK) and
signing key (db) under `keys/`, and the public halves land on the stick under
`/xos-keys/`. to turn secure boot on:

1. in your firmware setup, clear the existing keys / enter setup mode.
2. enroll from the stick: `db.der`, then `KEK.der`, then `PK.der` last --
   enrolling the PK exits setup mode and turns enforcement on. (a firmware
   KeyTool, or `sbctl` from another OS, works too.)

there is no shim and no MOK: you hold the only key, on purpose.

**danger.** replacing the platform key removes the vendor chain. any other OS on
that machine that relied on the factory keys -- Windows especially -- stops
booting until you restore them, and a few laptops have bricked on non-factory
PKs. only do this on hardware you own and can reflash. a usb stick with a
physical write-protect switch closes the last gap: the FAT and GPT metadata on
the stick are the only bytes not covered by a signature, and a write-protected
stick makes even those physically immutable.

## reproducible

the same source produces the same bytes. `image.sha256` commits the digest of
the image this tree builds, and G13 checks it -- so the signature at the top of
the chain attests to source you can read, not to whatever one machine produced.

that is the load-bearing part. verified boot proves the machine runs what was
signed. it says nothing about whether what was signed matches the code, and
without this it cannot.

on a different gcc the bytes will differ for innocent reasons, so G13 records
a toolchain fingerprint and skips with a note rather than failing. a gate that
cries wolf is a gate you stop reading.

the stick image itself is assembled deterministically but is not pinned: the
bytes that matter on it are already covered -- the root by `image.sha256` and
the hash tree, the kernel by the db signature. only the FAT/GPT metadata is
unauthenticated, and tampering it can at most deny boot, never change what runs.

## what's enforced

the build fails, loudly, on any of:

- image over 8 MiB, or the whole bootable system (signed kernel + image) over it
- any dynamically linked binary (no `ld.so` means nothing to `LD_PRELOAD`)
- any non-PIE binary (plain `-static` is an ASLR downgrade; this is static-PIE)
- any binary with an executable stack
- any setuid or world-writable file
- root hash in the signed image not matching the filesystem
- a kernel with a module loader (you can't `insmod` into a kernel that has none)
- a kernel missing any hardening option it must have, or carrying one it must not
  (spectre/meltdown mitigations, lockdown, KASLR, stack protector, slab
  hardening on; /dev/mem, kexec, io_uring, bpf, ia32 emulation off)
- the signed cmdline missing its hardening params or the wait-for-device root
- an upstream tarball whose digest doesn't match `sources.sha256`
- an image missing anything `manifest` says it must contain
- a firmware blob shipped in the image
- a stick whose partitions or embedded kernel don't match the built artifacts
- an image whose bytes don't match `image.sha256` on the pinned toolchain
- a plaintext private signing key sitting on disk
- an image that is in `revoked` (you would be shipping a brick)
- a revocation digest that disagrees with the signature it is meant to revoke
- a second shell in the image, or `/bin/sh` that is not busybox ash
- a shipped command with no `learn` entry, a `learn` entry for nothing shipped,
  or a requested busybox applet that did not actually build
- a `learn` question whose answer is not in the reference it cites
- a lesson using a command no earlier lesson introduced
- a documented command that no lesson introduces
- a `learn` answer invoking a command xos does not ship
- a challenge track that stops getting harder
- a `bzImage` built from a different `.config` than the one just validated

a build that reports success while quietly dropping features is the failure
mode this is built against. every claim above has a check that fails when it
stops being true. the self-test then boots the real chain in a vm and expects
every attack to fail: a flipped root byte, a flipped hash-tree byte, an unsigned
kernel, a tampered signature, a superseded image the firmware has revoked, a
cert outside the trust store, and it reads back from inside the running system
that /dev/mem and kcore are gone, lockdown is enforcing, and neither the root
nor /tmp will run injected code -- over both virtio and emulated USB.

## hardening

the kernel is built from `tinyconfig` up, so nothing is on that we did not ask
for. on top of the minimal set: KASLR, stack protector, page-table isolation
and the full spectre/meltdown mitigation set, hardened usercopy, slab freelist
randomization and hardening, kernel-stack-offset randomization, and lockdown in
confidentiality mode compiled in (stronger than a cmdline flag -- there is no
runtime knob to flip back). /dev/mem, /dev/port, kexec, hibernation, io_uring,
the bpf syscall, ia32 emulation and the fixed vsyscall page are all compiled
out, so they cannot be attacked because they do not exist.

at runtime the root is read-only and verity-covered; /proc, /sys and /tmp are
mounted nosuid,nodev,noexec, which matters because a static-PIE binary needs no
loader -- without noexec, /tmp was a place to drop and run code. sysctls tighten
kernel-pointer exposure, dmesg, and the network stack. every writable byte lives
on tmpfs and is gone at reboot. memory is zeroed on both allocation and free,
so freed pages do not keep secrets around for a use-after-free or a cold-boot
read.

every boot draws a fresh locally-administered mac before dhcp, so the stick
never presents a stable link-layer identity to the networks it visits.
`xos.realmac` (a rebuild, like any knob -- the cmdline is signed) opts back
into the burned-in address for mac-allowlisted networks.

time has no trusted source on a strange machine, and tls validation reads the
clock. `xos.epoch`, the build date pinned inside the signed uki, is a floor the
clock can never fall below -- an attacker cannot wind time back to before a
revocation. a floor is not a clock, though: a dead cmos battery boots at the
build date, up to 90 days behind. there is no ntp (unsigned udp is exactly the
attacker-controlled source the floor shuts out); instead init reads the Date
header off an https response whose certificate chained to the compiled-in
anchors -- forward-only, capped at two years past the build, and validated at
laddered instants to escape the bootstrap paradox of checking a certificate's
dates with the clock you are trying to set. a machine whose rtc is sane makes
no network call at all.

the boot stick is a dead-man switch: the root runs from RAM, so pulling the
stick would otherwise change nothing. when the boot device sits on the usb
bus, init watches it and powers the machine off within seconds of removal,
taking the tmpfs session with it. `xos.notether` opts out. the arming test is
"is the boot device on usb", so qemu/virtio boots never arm.

when the state partition is unlocked, init takes an inventory of the machine
-- dmi identity, the pci and usb buses, the cpu -- and diffs it against the
last visit to that same machine, one baseline file per machine on p3. a
reflashed bios, a new pci card, or an extra usb device gets printed before
the first console spawns; evil-maid detection for the *machines* you visit,
not just the stick. no state unlocked, no recon -- the stick records nothing
about where it has been unless you open the encrypted partition.

the same unlock feeds a boot ledger: p3 counts its own opens and shows the
number and the previous boot's time at every unlock. remember it like the
fingerprint words -- a stick that says boot 44 when you left it at 47 was
rolled back to an older copy of p3, and nothing else on it can tell you that.

userland is compiled static-PIE with the stack protector and stack-clash
protection, and linked with a non-executable stack.

the one attack surface this posture knowingly accepts: the usb-net drivers
(rndis, cdc-ether) that make phone tethering work parse whatever a plugged-in
device claims to be. xos is a pure usb host, so this is reachable only by
physically plugging something in, and it sits behind every mitigation above --
naming it here beats pretending it isn't attack surface.

## revocation

a signature says who signed an image. it never says when.

so every image xos has ever signed stays bootable forever. an old release --
older kernel, older bugs, whatever CVE you rebuilt to escape -- can be dropped
back onto the ESP, and the firmware runs it. the signature is valid, because it
is valid. verity passes, because that old image has its own consistent root
hash. every gate in this repo goes green. nothing above notices, because there
was nothing above to notice: verified boot has no idea what "current" means.

`revoked` is the answer. it lists the authenticode digest of every image that
must never boot again; `./build.sh revoke IMAGE` appends one, and `dbx` enrolls
the list into firmware alongside the db key. after that the firmware refuses
the old image with `Access Denied`, at exactly the same place it refuses an
unsigned one.

two things guard the guard, because a revocation that silently matches nothing
is indistinguishable from one that works:

- the digest is the *authenticode* hash, not `sha256sum` of the file -- three
  regions are excluded from it. G21 checks `pehash.py` against the digest
  inside the image's own PKCS#7 signature, which sbsign already signed, so a
  wrong hash function fails the build instead of quietly revoking nothing.
- A11 boots a superseded-but-validly-signed image in a vm and fails unless
  the firmware actually refuses it.

entries are permanent. removing one un-revokes a known-bad image, which is the
whole reason the file is tracked and the image is not.

## userland

busybox, ii (irc), a tls tunnel, `learn`, abduco (session detach),
cryptsetup (encrypted state), and wg + dropbear (remote access) -- musl,
`-static-pie`, every one
of them built from a pinned source in this repo. `manifest` declares what the
image must hold; the component copies used to be `[ -f x ] && cp x`, so a
component that failed to build shrank the image and every gate still went green.

**one shell.** `/bin/sh` is busybox ash and nothing else is. the image used to
carry two shell parsers -- ash for the prompt, and bash purely as the runtime
for cmdchamp, whose data model is bash associative arrays. two parsers is twice
the thing to audit, and bash is the larger of them by a wide margin: it ships
`/dev/tcp/*/*` and `/dev/udp/*/*`, a socket client inside the shell, on a system
that compiles out bpf, io_uring and kexec. G23 fails the build if a second shell
comes back.

on real hardware the framebuffer console gets its own shell so a screen and
keyboard are usable; the serial console stays primary and is what the harness
reads.

`learn` is this repo's own, and it is why the one shell can be ash. it teaches
the whole shipped command surface from nothing to fluent -- the ~140 applets,
builtins and binaries this image actually contains, in dependency order. losing
cmdchamp cost the corpus that needed bash; on a read-only root the filesystem is
already a lookup table, so `learn` reads `ref/<cmd>` and needs no associative
array at all.

30 levels and 800-odd questions cover the whole surface in dependency order,
from `ls` to reading a suspect disk's bytes without mounting it to proving, from
inside the running system, that the machine underneath you is the one you built.
the questions are generated, not fixed: each rolls its own filenames, values
and file *contents* -- the sandbox data is rebuilt from the roll's seed, so a
count has to be computed, never remembered -- and is graded by running what you
type, so `sort -u` and `sort | uniq` both pass. the gameable count questions go
further: the answer's own output is derived by running it, and yours must match
exactly, so `grep -c WARN` cannot pass an ERROR question. a miss shows you
where your command died -- what it printed against what was wanted, the line
count at every pipeline stage, and the exact flags between you and the nearest
accepted answer. every level ends with a named boss -- five questions, thirty seconds each,
no hints and no reference -- and the last level is the machine itself. `learn` resumes the curriculum
where the last boss fell, `learn review` re-asks the weakest cards first,
`learn daily` is the same ten questions for everyone on a date, and
`learn place` climbs the curriculum one question per rung so a first run can
skip what you already know. `learn challenge` is the endgame, unlocked when
the last boss falls: thirteen timed chains that compose the whole curriculum,
one life, graded purely on what your pipeline prints. Tab at any question is
the reference panel, mid-line, without losing what you typed.

five rules govern it, and all five are gates rather than intentions:

- everything shipped is documented, and nothing documented is unshipped (G24).
  the same check compares `busybox --list` against `busybox.config.applets`,
  which closes a real hole: an applet dropped for an unmet dependency used to
  ship silently, because `manifest` names only a handful of them by hand.
- no question may be asked whose answer is not in the corpus, and every flag an
  answer uses is documented in the entry it points at (G25). the build runs
  `learn`'s own checker under the built busybox, so there is one implementation,
  used at build time and on the machine. it grades by *running* each answer in a
  throwaway sandbox, so it has caught questions teaching flags this build does
  not have -- `nc -l`, `xargs -d`, `flock` when file locking was compiled out.
- every documented flag is either taught by a question or retired in
  `learn/skip` with a written reason (G26): "we teach everything xos can do" is a
  number the build reports, zero open, not a promise. checkable only because the
  command surface is fixed at build time -- a busybox bump that adds a flag lands
  in neither set and stops the build until someone rules on it.
- a level may only use commands it or an earlier level introduced (G27), so
  "teach in the right order" survives someone moving a question. it found six
  real violations the first time it ran.
- the challenge track holds its shape (G29): at least twelve stages, every
  stage a real chain, difficulty never falling, the end in the deep end, and
  no stage claiming a level whose commands are not yet taught.

the reference is complete; the curriculum is selective. a lesson's `uses:` are
drilled with questions, its `mentions:` are named and explained but not drilled
-- because nobody needs to be quizzed on `ls -X`, and nobody should be unable to
look it up either.

tls trusts exactly the certificate authorities in `trust/`, compiled into the
binary rather than read from a directory, so the set is covered by the hash
tree and the signature. a normal distro trusts about 150 roots, any one of
which can issue for any name. this trusts one.

`musl-static-pie.specs` exists
because arch's `musl-gcc` selects the dynamic PIE startup file, producing a
binary with no interpreter but a shared libc — it links clean and segfaults.
note that musl itself is host-provided, not built from source here -- see
SOURCES.md.

## not this

not a general distro. no package manager, no compiler. persistence is opt-in
and encrypted (p3) -- decline it and nothing survives a
reboot. pre-xHCI machines (roughly pre-2012) are out of scope: the stick
enumerates over xHCI only. iphone usb tethering does not work -- it needs
usbmuxd, apple's pairing daemon, which xos does not ship; android tethering
and plain usb-ethernet dongles do.
don't enroll these keys on hardware whose own secure boot chain you still need.

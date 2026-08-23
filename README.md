# heatos

an operating system that lives on a usb stick and can prove it hasn't been
altered. plug it in, boot it, and your machine's own disks are never touched --
heatos ships no driver that can see them. pull the stick and nothing remains;
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
runs it. with secure boot on, enroll your heatos keys first (see below) and the
firmware verifies the signature on every boot.

the root is named on the cmdline by PARTUUID, never by `/dev/sda`, and the
kernel waits for that partition to appear -- so the same signed image boots
whether the stick enumerates as the first disk or the third.

## the chain

    firmware (secure boot, your enrolled keys)
      verifies -> signed UKI  (kernel + cmdline in one signed PE)
                    carries -> verity root hash + the root's PARTUUID
                                 covers -> every block of a read-only squashfs

each link is checked by the one above it. one key at the top, complete
coverage at the bottom.

## build

    ./build.sh all      # sources verified against pinned digests, then built
    ./attack.sh         # tries to break it, expects every attempt to fail
    ./build.sh boot     # boots the real chain in qemu (dev only)
    ./build.sh usb /dev/sdX   # write a real bootable stick

qemu is the development and test rig -- the attack harness needs to byte-flip
boot media, which you can't do to a machine you're running on. the stick is the
product. `./build.sh bootusb` runs the exact stick image through emulated USB,
so the real boot path (enumeration, the wait-for-device poll) is testable
without hardware.

the repo holds recipes, never artifacts -- the pre-commit hook refuses any
staged file whose magic says ELF, PE or squashfs, whatever it is named. that
rule exists because a name-based version of it missed three committed
binaries, and the build preferred them over building from source.

`git pull && ./build.sh all` relinks the whole system, which is what makes
static linking survivable when a dependency gets a CVE.

## secure boot: enrolling your keys

`./build.sh all` generates a platform key (PK), key-exchange key (KEK) and
signing key (db) under `keys/`, and the public halves land on the stick under
`/heatos-keys/`. to turn secure boot on:

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

a build that reports success while quietly dropping features is the failure
mode this is built against. every claim above has a check that fails when it
stops being true. the attack harness then boots the real chain ten ways and
expects every attack to fail: a flipped root byte, a flipped hash-tree byte, an
unsigned kernel, a tampered signature, a cert outside the trust store, and it
reads back from inside the running system that /dev/mem and kcore are gone,
lockdown is enforcing, and neither the root nor /tmp will run injected code.

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
on tmpfs and is gone at reboot.

userland is compiled static-PIE with the stack protector and stack-clash
protection, and linked with a non-executable stack.

## userland

busybox, bash, cmdchamp, ii (irc), and a tls tunnel -- musl, `-static-pie`,
every one of them built from a pinned source in this repo. `/bin/sh` is busybox
ash: small, and the only shell you type at. bash is not a second login shell --
it is the runtime cmdchamp needs (its data model is bash associative arrays), so
it rides along the way an app ships its interpreter. `manifest` declares what
the image must hold; the component copies used to be `[ -f x ] && cp x`, so a
component that failed to build shrank the image and every gate still went green.

on real hardware the framebuffer console gets its own shell so a screen and
keyboard are usable; the serial console stays primary and is what the harness
reads.

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

not a daily driver. no package manager, no persistence, nothing survives a
reboot. pre-xHCI machines (roughly pre-2012) are out of scope: the stick
enumerates over xHCI only.
don't enroll these keys on hardware whose own secure boot chain you still need.

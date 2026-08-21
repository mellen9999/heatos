# heatos

a small linux that can prove it hasn't been altered.

every block of the root filesystem is covered by a hash tree. the tree's root
hash sits on the kernel command line, the command line sits inside a signed
boot image, and the firmware refuses to run that image unless it's signed by a
key you hold. change one byte anywhere on disk and the kernel refuses the read
rather than reporting it afterwards.

it is a lab artifact. it runs in qemu, holds no secrets, and does not stay
running anything.

## the chain

    firmware (secure boot, your enrolled keys)
      verifies -> signed UKI  (kernel + cmdline in one signed PE)
                    carries -> verity root hash
                                 covers -> every block of a read-only squashfs

each link is checked by the one above it. one key at the top, complete
coverage at the bottom.

## build

    ./build.sh all      # sources verified against pinned digests, then built
    ./attack.sh         # tries to break it, expects every attempt to fail
    ./build.sh boot     # boots the real chain in qemu

the repo holds recipes, never artifacts -- the pre-commit hook refuses any
staged file whose magic says ELF, PE or squashfs, whatever it is named. that
rule exists because a name-based version of it missed three committed
binaries, and the build preferred them over building from source.

`git pull && ./build.sh all` relinks the whole system, which is what makes
static linking survivable when a dependency gets a CVE.

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

## what's enforced

the build fails, loudly, on any of:

- image over 8 MiB
- any dynamically linked binary (no `ld.so` means nothing to `LD_PRELOAD`)
- any non-PIE binary (plain `-static` is an ASLR downgrade; this is static-PIE)
- any setuid or world-writable file
- root hash in the signed image not matching the filesystem
- a kernel with a module loader (you can't `insmod` into a kernel that has none)
- an upstream tarball whose digest doesn't match `sources.sha256`
- an image missing anything `manifest` says it must contain
- an image whose bytes don't match `image.sha256` on the pinned toolchain
- a plaintext private signing key sitting on disk

a build that reports success while quietly dropping features is the failure
mode this is built against. every claim above has a check that fails when it
stops being true.

## userland

busybox, bash, cmdchamp, ii (irc), and a tls tunnel -- musl, `-static-pie`,
every one of them built from a pinned source in this repo. `manifest` declares
what the image must hold; the component copies used to be `[ -f x ] && cp x`,
so a component that failed to build shrank the image and every gate still went
green.

tls trusts exactly the certificate authorities in `trust/`, compiled into the
binary rather than read from a directory, so the set is covered by the hash
tree and the signature. a normal distro trusts about 150 roots, any one of
which can issue for any name. this trusts one.

`musl-static-pie.specs` exists
because arch's `musl-gcc` selects the dynamic PIE startup file, producing a
binary with no interpreter but a shared libc — it links clean and segfaults.

## not this

not a daily driver. no package manager, no persistence, nothing survives a
reboot.
don't boot it on hardware that has its own secure boot keys enrolled.

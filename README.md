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
    ./attack.sh         # tries to break it nine ways, expects nine failures
    ./build.sh boot     # boots the real chain in qemu

the repo holds recipes, never artifacts. everything above is regenerated from
source; `git pull && ./build.sh all` relinks the whole system, which is what
makes static linking survivable when a dependency gets a CVE.

## what's enforced

the build fails, loudly, on any of:

- image over 8 MiB
- any dynamically linked binary (no `ld.so` means nothing to `LD_PRELOAD`)
- any non-PIE binary (plain `-static` is an ASLR downgrade; this is static-PIE)
- any setuid or world-writable file
- root hash in the signed image not matching the filesystem
- a kernel with a module loader (you can't `insmod` into a kernel that has none)
- an upstream tarball whose digest doesn't match `sources.sha256`

a build that reports success while quietly dropping features is the failure
mode this is built against. every claim above has a check that fails when it
stops being true.

## userland

busybox, musl, `-static-pie`, one binary. `musl-static-pie.specs` exists
because arch's `musl-gcc` selects the dynamic PIE startup file, producing a
binary with no interpreter but a shared libc — it links clean and segfaults.

## not this

not a daily driver. no networking, no package manager, no persistence.
don't boot it on hardware that has its own secure boot keys enrolled.

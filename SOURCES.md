# upstream sources and how each pin is anchored

`sources.sha256` pins every tarball by digest, checked before extraction (G8).
But a digest only says "this is the same bytes I saw once" -- what matters is
what that first sighting was anchored to. They are not equal:

| source | anchor | strength |
|---|---|---|
| linux | sha256sums published by kernel.org, matched byte for byte | good -- an independent published list |
| busybox | sha256 published by busybox.net, matched | good -- same |
| bearssl | none available (bearssl.org publishes no .sig/.asc) | **weakest -- trust-on-first-use over TLS only** |
| ii | none available (suckless publishes no .sig/.asc/.sha256) | **weakest -- trust-on-first-use over TLS only** |
| abduco | none available (brain-dump.org publishes no .sig/.asc) | **weakest -- trust-on-first-use over TLS only** |
| cryptsetup | sha256sums published by kernel.org, matched | good -- an independent published list |
| util-linux | sha256sums published by kernel.org, matched | good -- same |
| lvm2 | none matched (sourceware publishes signatures, not yet checked here) | **weakest -- trust-on-first-use over TLS only** |
| popt | none available | **weakest -- trust-on-first-use over TLS only** |
| json-c | github release tarball, no signature | **weakest -- trust-on-first-use over TLS only** |
| wireguard-tools | github release tag, no signature | **weakest -- trust-on-first-use over TLS only** |
| dropbear | github release tag, no signature | **weakest -- trust-on-first-use over TLS only** |

Those pins protect against a *later* substitution, not against the tarball
having been wrong when first fetched. That is a real gap and is recorded here
rather than hidden behind a hash that looks as authoritative as the others.

Note what dropping bash cost this table. bash was the only entry anchored to a
maintainer's PGP signature -- the strongest link here -- so the "best" tier is
now empty, and every remaining pin rests on a digest list published over TLS by
the same project that ships the tarball. The image got smaller and lost a shell
parser, and the provenance story got weaker. Both are true.

Adding cryptsetup took this repo from four pinned upstreams to nine in one
step -- the largest single increase in trust surface it has ever taken, and
three of the five newcomers are trust-on-first-use. It buys p3: state that is
encrypted AND authenticated, which is the only way a key can live on this stick
at all. Using the kernel's crypto through AF_ALG is what kept it to five rather
than six; an openssl or gcrypt backend would have been a sixth, and a large one.

lvm2 is the one worth revisiting: sourceware does publish signatures for it, and
this pin does not yet check them. That is a known gap, written down here rather
than left for someone to assume was handled.

wireguard-tools and dropbear are the remote-access userland. dropbear is the one
listening service on the whole system, so its pin matters more than most; it is
pinned by digest but the digest was taken on first fetch, not matched against a
maintainer signature. dropbear does publish signed releases upstream -- matching
that signature is the obvious hardening, and another known gap named here.

`learn` and its corpus are first-party: written in this repo, reviewed in its
diffs, covered by the hash tree like everything else. The reference entries are
generated from the built binaries' own `--help` output rather than transcribed,
so they cannot describe a flag the shipped binary lacks.

## the toolchain is host-provided, and unpinned

Every shipped binary is *linked* against musl, but musl is not built from source
here -- `libc.a`, `rcrt1.o`, `crti.o`/`crtn.o` come from the host's
`/usr/lib/musl` (arch's `musl` package) and are covered by no digest in this
repo. The same is true of gcc, binutils, the systemd EFI stub, squashfs-tools,
cryptsetup and the OVMF firmware. So "built from source" is true of the
applications and false of libc and the toolchain.

`toolchain()` fingerprints tool *version strings*, not their bytes, so it
detects an innocent gcc upgrade (which changes the image for legitimate reasons)
but not a compromised compiler that reports the same version. Closing this would
mean a bootstrappable or content-addressed toolchain (Nix/Guix, `mkosi`, a
pinned musl build) -- out of scope for a lab artifact, but named here so the
reproducibility claim is not read as more than it is.

# upstream sources and how each pin is anchored

`sources.sha256` pins every tarball by digest, checked before extraction (G8).
But a digest only says "this is the same bytes I saw once" -- what matters is
what that first sighting was anchored to. They are not equal:

| source | anchor | strength |
|---|---|---|
| linux | sha256sums published by kernel.org, matched byte for byte | good -- an independent published list |
| busybox | sha256 published by busybox.net, matched | good -- same |
| bash | **PGP signature verified** against the GNU keyring: "Good signature from Chet Ramey" | best -- signed by the maintainer |
| ii | none available (suckless publishes no .sig/.asc/.sha256) | **weakest -- trust-on-first-use over TLS only** |

The ii pin protects against a *later* substitution, not against the tarball
having been wrong when first fetched. That is a real gap and is recorded here
rather than hidden behind a hash that looks as authoritative as the others.

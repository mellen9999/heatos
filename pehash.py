#!/usr/bin/env python3
"""authenticode sha-256 of a PE image -- the digest UEFI matches against dbx.

this is NOT sha256sum of the file. the firmware hashes the image with three
regions excluded: the header checksum, the certificate-table directory entry,
and the attached signature itself. hashing the whole file instead produces a
number that never matches anything, and a dbx entry that silently revokes
nothing -- which looks exactly like a dbx entry that works.

two independent checks keep this honest, because a wrong hash here fails open:
  G15  the digest this computes must equal the one inside the image's own
       PKCS#7 signature (sbsign signed that digest, so it is ground truth)
  A7   a revoked image must actually be refused by the firmware, in a vm
"""
import hashlib
import struct
import sys


def _regions(b):
    """(spans_to_hash, cert_offset, cert_size) per the authenticode spec."""
    if b[:2] != b"MZ":
        raise ValueError("not a PE image (no MZ)")
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    if b[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE image (no PE signature)")

    nsections = struct.unpack_from("<H", b, pe + 6)[0]
    opt_size = struct.unpack_from("<H", b, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", b, opt)[0]
    if magic == 0x10B:      # PE32
        dd = opt + 96
    elif magic == 0x20B:    # PE32+
        dd = opt + 112
    else:
        raise ValueError("unknown optional header magic 0x%x" % magic)

    checksum = opt + 64
    cert_dd = dd + 4 * 8                      # data directory entry 4
    size_of_headers = struct.unpack_from("<I", b, opt + 60)[0]
    cert_off, cert_size = struct.unpack_from("<II", b, cert_dd)

    # headers, with the checksum and the cert-table entry cut out
    spans = [(0, checksum),
             (checksum + 4, cert_dd),
             (cert_dd + 8, size_of_headers)]

    # sections in file order, exactly SizeOfRawData bytes each
    sec = opt + opt_size
    secs = []
    for i in range(nsections):
        h = sec + i * 40
        raw_size, raw_ptr = struct.unpack_from("<II", b, h + 16)
        if raw_size:
            secs.append((raw_ptr, raw_size))
    secs.sort()
    hashed = size_of_headers
    for ptr, size in secs:
        spans.append((ptr, ptr + size))
        hashed += size

    # trailing data, excluding the signature blob at the very end
    tail = len(b) - cert_size
    if tail > hashed:
        spans.append((hashed, tail))
    return spans, cert_off, cert_size


def pe_hash(path):
    b = open(path, "rb").read()
    spans, _, _ = _regions(b)
    h = hashlib.sha256()
    for start, end in spans:
        if end < start or end > len(b):
            raise ValueError("malformed PE: span %d..%d outside %d bytes"
                             % (start, end, len(b)))
        h.update(b[start:end])
    return h.hexdigest()


def extract_sig(path, out):
    b = open(path, "rb").read()
    _, off, size = _regions(b)
    if not size:
        raise ValueError("image carries no signature")
    # WIN_CERTIFICATE: dwLength(4) wRevision(2) wCertificateType(2), then DER
    open(out, "wb").write(b[off + 8:off + size])


def verify(path):
    """assert this hasher agrees with the signature already on the image.

    sbsign signed the authenticode digest, so that digest sits verbatim inside
    the PKCS#7 blob. if our number is not in there, our number is wrong.
    """
    b = open(path, "rb").read()
    _, off, size = _regions(b)
    if not size:
        raise ValueError("image carries no signature to check against")
    der = b[off + 8:off + size]
    want = pe_hash(path)
    if bytes.fromhex(want) not in der:
        raise ValueError("computed digest %s is absent from the image's own "
                         "signature -- the hasher is wrong" % want)
    return want


if __name__ == "__main__":
    try:
        if len(sys.argv) == 4 and sys.argv[1] == "--sig":
            extract_sig(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 3 and sys.argv[1] == "--verify":
            print(verify(sys.argv[2]))
        elif len(sys.argv) == 2:
            print(pe_hash(sys.argv[1]))
        else:
            sys.exit("usage: pehash.py IMAGE | --verify IMAGE | --sig IMAGE OUT.der")
    except (OSError, ValueError) as e:
        sys.exit("pehash: %s" % e)

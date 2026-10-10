#!/usr/bin/env python3
"""Authenticode SHA-256 digest of PE files, with and without the padding of the
file to a multiple of 8 bytes, and extraction of the digest stored in a PKCS#7
blob (.p7u from `signtool sign /dg`) or in a signed PE file."""

import hashlib
import struct
import sys

# DigestInfo: AlgorithmIdentifier { sha256, NULL } followed by OCTET STRING (32 bytes)
DIGEST_INFO_SHA256 = bytes.fromhex("300d060960864801650304020105000420")


def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def authenticode_digest(data, pad):
    """Hash as in the Authenticode PE spec; pad unsigned files to 8 bytes if pad."""
    pe = u32(data, 0x3C)
    opt = pe + 24
    magic = u16(data, opt)
    checksum = opt + 64
    data_dirs = opt + (96 if magic == 0x10B else 112)
    cert_dir = data_dirs + 4 * 8
    size_of_headers = u32(data, opt + 60)
    nsections = u16(data, pe + 6)
    sections_off = opt + u16(data, pe + 20)

    h = hashlib.sha256()
    h.update(data[:checksum])
    h.update(data[checksum + 4:cert_dir])
    h.update(data[cert_dir + 8:size_of_headers])
    hashed = size_of_headers
    sections = []
    for i in range(nsections):
        s = sections_off + 40 * i
        raw_size, raw_ptr = u32(data, s + 16), u32(data, s + 20)
        if raw_size:
            sections.append((raw_ptr, raw_size))
    for raw_ptr, raw_size in sorted(sections):
        h.update(data[raw_ptr:raw_ptr + raw_size])
        hashed += raw_size
    cert_size = u32(data, cert_dir + 4) if u32(data, cert_dir) else 0
    end = len(data) - cert_size
    if end > hashed:
        h.update(data[hashed:end])
    if pad and cert_size == 0:
        h.update(bytes((8 - len(data) % 8) % 8))
    return h.hexdigest()


def stored_digest(blob):
    """First SHA-256 DigestInfo of the blob: the SpcIndirectDataContent digest."""
    i = blob.find(DIGEST_INFO_SHA256)
    if i < 0:
        return None
    i += len(DIGEST_INFO_SHA256)
    return blob[i:i + 32].hex()


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("hash", "stored"):
        sys.exit("usage: signtool_digest.py hash|stored FILE")
    with open(sys.argv[2], "rb") as f:
        data = f.read()
    if sys.argv[1] == "hash":
        print(f"size={len(data)}")
        print(f"mod8={len(data) % 8}")
        print("no_padding=" + authenticode_digest(data, False))
        print("padding=" + authenticode_digest(data, True))
    else:
        print("stored=" + str(stored_digest(data)))


if __name__ == "__main__":
    main()

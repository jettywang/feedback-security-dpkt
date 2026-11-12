"""Independent Internet-checksum reference implementation.

Deliberately uses only the Python standard library (``struct``) and shares no
code with dpkt so it can serve as an independent oracle. The input ``bytes``
are never mutated; the odd-length padding byte exists only inside the local
accumulator.
"""

import struct


def ones_complement_sum(buf: bytes) -> int:
    """Return the un-folded one's-complement sum of *buf*.

    Bytes are summed as 16-bit big-endian words (network byte order). An odd
    trailing byte is treated as the high byte of a final zero-padded word, per
    RFC 1071.
    """
    if not isinstance(buf, (bytes, bytearray, memoryview)):
        raise TypeError("checksum input must be bytes-like")
    view = memoryview(buf)
    even_len = (len(view) // 2) * 2
    total = sum(struct.unpack(">%dH" % (even_len // 2), bytes(view[:even_len])))
    if len(view) != even_len:
        total += view[-1] << 8
    return total


def fold(total: int) -> int:
    """Fold an arbitrary-width sum into 16 bits, then invert."""
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def internet_checksum(buf: bytes) -> int:
    """Compute the RFC 1071 Internet checksum of *buf*."""
    return fold(ones_complement_sum(buf))


def verify_ones_complement(buf: bytes) -> bool:
    """True iff *buf*, including its embedded checksum field, sums to 0xFFFF.

    On a correctly checksummed message, adding the checksum field itself makes
    the folded one's-complement sum equal to 0xFFFF (equivalent to a zero
    checksum result). This never writes to *buf*.
    """
    total = ones_complement_sum(buf)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def ipv4_pseudo_header(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    return struct.pack(">4s4sBBH", src, dst, 0, proto, length)


def ipv6_pseudo_header(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    return struct.pack(">16s16sI3xB", src, dst, length, proto)


def transport_checksum(
    pseudo: bytes, segment: bytes, checksum_offset: int = 6
) -> int:
    """Recompute a TCP/UDP checksum with the checksum field treated as zero."""
    if len(segment) < checksum_offset + 2:
        raise ValueError("segment too short to contain a checksum field")
    zeroed = segment[:checksum_offset] + b"\x00\x00" + segment[checksum_offset + 2:]
    return internet_checksum(pseudo + zeroed)

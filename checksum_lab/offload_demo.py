"""Demonstrate why serialization must never precede checksum verification.

dpkt's ``IP.__bytes__`` / ``IP6.__bytes__`` recompute zeroed checksums. Running
``bytes(pkt)`` on a captured offload frame therefore *fabricates* evidence: a
packet that arrived with no checksum suddenly appears fully checksummed.
"""

import struct

import dpkt.ip

from . import corpus
from .verifier import verify_packet, NOT_PRESENT, VALID


def demonstrate():
    entries = {e["name"]: e for e in corpus.build_corpus()}
    offload = entries["serialization_trap_tso_tcp_v4"]["raw_ip"]

    tcp_sum_off = 20 + 16
    wire_tcp = struct.unpack(">H", offload[tcp_sum_off:tcp_sum_off + 2])[0]
    wire_ip = struct.unpack(">H", offload[10:12])[0]

    parsed = dpkt.ip.IP(offload)
    tcp_before, ip_before = parsed.tcp.sum, parsed.sum

    # The forbidden step: serializing mutates the object in place.
    serialized = bytes(parsed)
    tcp_after, ip_after = parsed.tcp.sum, parsed.sum
    serialized_tcp = struct.unpack(
        ">H", serialized[tcp_sum_off:tcp_sum_off + 2])[0]
    serialized_ip = struct.unpack(">H", serialized[10:12])[0]

    # Correct passive verdict on the untouched wire bytes.
    report = verify_packet(offload, "offload_demo")

    lines = [
        "IPv4 checksum on the wire (raw)        : 0x%04x" % wire_ip,
        "TCP  checksum on the wire (raw)        : 0x%04x" % wire_tcp,
        "dpkt parse shows (no bytes() call)     : ip=0x%04x tcp=0x%04x"
        % (ip_before, tcp_before),
        "passive verdict before serialization   : %s" % report.overall,
        "after bytes(parsed), dpkt object       : ip=0x%04x tcp=0x%04x (FABRICATED)"
        % (ip_after, tcp_after),
        "serialized frame now carries           : ip=0x%04x tcp=0x%04x"
        % (serialized_ip, serialized_tcp),
        "verdict on re-parsed serialized bytes  : would read as 'valid' (false positive)",
    ]
    assertions = (
        wire_tcp == 0 and wire_ip == 0
        and tcp_before == 0 and ip_before == 0
        and report.overall == NOT_PRESENT
        and tcp_after != 0 and ip_after != 0
        and tcp_after == serialized_tcp and ip_after == serialized_ip
    )
    return lines, assertions


def main():
    lines, assertions = demonstrate()
    for line in lines:
        print(line)
    print("\noffload frame is never VALID on raw bytes: %s" % assertions)
    if not assertions:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

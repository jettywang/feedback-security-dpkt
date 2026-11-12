"""Deterministic packet corpus for the checksum experiment.

Packets are assembled with raw ``struct`` packing (not dpkt serialization) and
checksummed by the independent reference module, so every "valid" sample is
valid by construction against an oracle that never touches dpkt.

Each corpus entry is a dict:
    name, description, kind, frame (Ethernet bytes), raw_ip (IP datagram bytes),
    expect (overall verdict), expect_layers {layer: verdict}, pcap_meta.
"""

import struct

import dpkt.pcap

from . import reference

SRC4 = bytes([192, 0, 2, 10])
DST4 = bytes([198, 51, 100, 7])
SRC6 = b"\x20\x01\x0d\xb8" + b"\x00\x01" * 6
DST6 = b"\x20\x01\x0d\xb8" + b"\x00\x02" * 6

TCP_PROTO = 6
UDP_PROTO = 17
ETH_HDR = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02"


def _tcp_segment(sport, dport, payload, seq=1, ack=1):
    hdr = struct.pack(">HHIIHHHH", sport, dport, seq, ack, (5 << 12) | 0x18,
                      64240, 0, 0)
    return hdr + payload


def _udp_segment(sport, dport, payload):
    hdr = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    return hdr + payload


def _csum(proto, src, dst, segment, version):
    length = len(segment)
    if version == 4:
        pseudo = reference.ipv4_pseudo_header(src, dst, proto, length)
    else:
        pseudo = reference.ipv6_pseudo_header(src, dst, proto, length)
    value = reference.transport_checksum(pseudo, segment, 16 if proto == TCP_PROTO else 6)
    # RFC 768: a computed zero over UDP is transmitted as 0xffff.
    if proto == UDP_PROTO and value == 0:
        value = 0xFFFF
    return value


def _ipv4(proto, payload, src=SRC4, dst=DST4):
    total = 20 + len(payload)
    hdr_no_sum = struct.pack(">BBHHHBBH", 0x45, 0, total, 0x1234, 0x4000, 64,
                             proto, 0) + src + dst
    csum = reference.internet_checksum(hdr_no_sum)
    return hdr_no_sum[:10] + struct.pack(">H", csum) + hdr_no_sum[12:] + payload


def _ipv6(proto, payload, src=SRC6, dst=DST6):
    hdr = struct.pack(">IHBB", 0x60000000, len(payload), proto, 64) + src + dst
    return hdr + payload


def _frame(ethertype, raw_ip):
    return ETH_HDR + struct.pack(">H", ethertype) + raw_ip


def _flip(raw, index):
    b = bytearray(raw)
    b[index] ^= 0x01
    return bytes(b)


def _expect_layers(version, transport, transport_verdict,
                   ipv4_verdict=None):
    layers = {}
    if version == 4:
        layers["ipv4"] = ipv4_verdict if ipv4_verdict else "valid"
    layers[transport] = transport_verdict
    return layers


def _entry(name, kind, raw_ip, version, transport, ethertype, description,
           expect, expect_layers, truncate_to=None, mutate_index=None):
    frame = _frame(ethertype, raw_ip)
    if truncate_to is not None:
        frame = frame[:14 + truncate_to]  # keep Ethernet header, cut IP tail
        raw_ip_out = raw_ip[:truncate_to]
    else:
        raw_ip_out = raw_ip
    return {
        "name": name,
        "description": description,
        "kind": kind,
        "ip_version": version,
        "transport": transport,
        "frame": frame,
        "raw_ip": raw_ip_out,
        "expect": expect,
        "expect_layers": expect_layers,
        "mutate_index": mutate_index,
        "truncate_to": truncate_to,
    }


def build_corpus():
    entries = []

    # ---- valid baselines -------------------------------------------------
    odd_payload = b"odd"          # 3-byte payload => odd TCP/UDP length
    even_payload = b"even12"      # 6 bytes

    cases = [
        # (suffix, version, proto, transport, ethertype, builder, src, dst)
        ("v4_tcp_even", 4, TCP_PROTO, "tcp", 0x0800, _ipv4, SRC4, DST4),
        ("v4_tcp_odd", 4, TCP_PROTO, "tcp", 0x0800, _ipv4, SRC4, DST4),
        ("v4_udp_even", 4, UDP_PROTO, "udp", 0x0800, _ipv4, SRC4, DST4),
        ("v4_udp_odd", 4, UDP_PROTO, "udp", 0x0800, _ipv4, SRC4, DST4),
        ("v6_tcp_even", 6, TCP_PROTO, "tcp", 0x86DD, _ipv6, SRC6, DST6),
        ("v6_tcp_odd", 6, TCP_PROTO, "tcp", 0x86DD, _ipv6, SRC6, DST6),
        ("v6_udp_even", 6, UDP_PROTO, "udp", 0x86DD, _ipv6, SRC6, DST6),
        ("v6_udp_odd", 6, UDP_PROTO, "udp", 0x86DD, _ipv6, SRC6, DST6),
    ]

    valid_packets = {}
    for suffix, version, proto, transport, ethertype, builder, src, dst in cases:
        payload = odd_payload if suffix.endswith("odd") else even_payload
        if proto == TCP_PROTO:
            seg = _tcp_segment(40000, 8080, payload)
            csum_off = 16
        else:
            seg = _udp_segment(40000, 5353, payload)
            csum_off = 6
        csum = _csum(proto, src, dst, seg, version)
        seg = seg[:csum_off] + struct.pack(">H", csum) + seg[csum_off + 2:]
        raw_ip = builder(proto, seg, src, dst)
        valid_packets[suffix] = (raw_ip, ethertype, version, transport,
                                 proto, csum_off)
        entries.append(_entry(
            "valid_" + suffix, "valid", raw_ip, version, transport, ethertype,
            "well-formed %s %s, payload %d bytes, checksums correct by construction"
            % ("IPv%d" % version, transport.upper(), len(payload)),
            "valid", _expect_layers(version, transport, "valid")))

    # ---- single-byte corruption -----------------------------------------
    # Corrupt a payload byte: IP header checksum stays valid, L4 checksum breaks.
    for suffix in ("v4_tcp_odd", "v4_udp_odd", "v6_tcp_odd", "v6_udp_odd"):
        raw_ip, ethertype, version, transport, proto, csum_off = valid_packets[suffix]
        idx = len(raw_ip) - 1  # last payload byte
        broken = _flip(raw_ip, idx)
        layers = _expect_layers(version, transport, "mismatch",
                               ipv4_verdict="valid")
        entries.append(_entry(
            "corrupt_payload_" + suffix, "single_byte_corruption", broken,
            version, transport, ethertype,
            "one payload byte flipped at offset %d; transport checksum must fail" % idx,
            "mismatch", layers, mutate_index=idx))

    # Corrupt an IPv4 header byte (TTL): IP checksum breaks, transport still valid.
    raw_ip, ethertype, version, transport, *_ = valid_packets["v4_tcp_even"]
    broken = _flip(raw_ip, 8)
    entries.append(_entry(
        "corrupt_ipv4_ttl_v4_tcp_even", "single_byte_corruption", broken,
        4, "tcp", ethertype,
        "TTL byte flipped at offset 8; IPv4 header checksum must fail, TCP intact",
        "mismatch", _expect_layers(4, "tcp", "valid", ipv4_verdict="mismatch"),
            mutate_index=8))

    # Corrupt an IPv6 address byte: no IP header checksum exists, TCP breaks.
    raw_ip, ethertype, version, transport, *_ = valid_packets["v6_tcp_even"]
    broken = _flip(raw_ip, 24)  # first source-address byte
    entries.append(_entry(
        "corrupt_v6src_v6_tcp_even", "single_byte_corruption", broken,
        6, "tcp", ethertype,
        "IPv6 source address byte flipped; pseudo-header makes TCP checksum fail",
        "mismatch", _expect_layers(6, "tcp", "mismatch"), mutate_index=24))

    # ---- truncated captures ---------------------------------------------
    # Cut mid TCP header: checksum field bytes themselves are gone.
    raw_ip, ethertype, version, transport, *_ = valid_packets["v4_tcp_even"]
    cut = 20 + 18  # 2 of the 4 checksum bytes missing
    entries.append(_entry(
        "truncated_mid_tcp_v4_tcp_even", "truncated", raw_ip, 4, "tcp",
        ethertype,
        "snap truncation inside TCP header (offset %d); checksum field incomplete" % cut,
        "inconclusive", _expect_layers(4, "tcp", "inconclusive",
                                   ipv4_verdict="inconclusive"),
        truncate_to=cut))

    # Cut inside payload: full headers present but declared length exceeds capture.
    raw_ip, ethertype, version, transport, *_ = valid_packets["v6_udp_odd"]
    full = len(raw_ip)
    cut = full - 2
    entries.append(_entry(
        "truncated_payload_v6_udp_odd", "truncated", raw_ip, 6, "udp",
        ethertype,
        "snap truncation removes 2 payload bytes (IPv6 plen exceeds capture)",
        "inconclusive", _expect_layers(6, "udp", "inconclusive"),
        truncate_to=cut))

    # IPv4 truncation that still leaves the whole IP header intact.
    raw_ip, ethertype, version, transport, *_ = valid_packets["v4_udp_even"]
    cut = len(raw_ip) - 3
    entries.append(_entry(
        "truncated_payload_v4_udp_even", "truncated", raw_ip, 4, "udp",
        ethertype,
        "snap truncation removes 3 bytes; IP total length exceeds capture",
        "inconclusive", _expect_layers(4, "udp", "inconclusive",
                                   ipv4_verdict="inconclusive"),
        truncate_to=cut))

    # ---- IPv4/UDP zero checksum (disabled) and checksum offload ---------
    raw_ip, ethertype, *_ = valid_packets["v4_udp_even"]
    zeroed = raw_ip[:20 + 6] + b"\x00\x00" + raw_ip[20 + 8:]
    entries.append(_entry(
        "zero_udp_checksum_v4", "zero_checksum", zeroed, 4, "udp", ethertype,
        "IPv4 UDP checksum field zero: sender disabled it (RFC 768); not verifiable",
        "not_present", _expect_layers(4, "udp", "not_present")))

    # --- checksum-offload artifacts --------------------------------------
    # Two distinct wire shapes must not be conflated:
    #  (a) only the L4 checksum is zero (NIC L4 offload); the IPv4 header
    #      checksum is still present and independently verifiable.
    #  (b) BOTH the IPv4 header and L4 checksums are zero, the shape of a
    #      locally-captured TSO/GSO segment before the NIC filled anything in.
    # dpkt's serializer recomputes L4 only in shape (b) (it gates on IP.sum==0);
    # over IPv6 there is no IP checksum so it always recomputes a zero L4 sum.

    raw_ip, ethertype, *_ = valid_packets["v4_tcp_even"]
    tcp_zero = raw_ip[:20 + 16] + b"\x00\x00" + raw_ip[20 + 18:]
    entries.append(_entry(
        "offload_l4zero_tcp_v4", "checksum_offload", tcp_zero, 4, "tcp",
        ethertype,
        "L4-only offload: zero TCP checksum, IPv4 header checksum intact",
        "not_present", _expect_layers(4, "tcp", "not_present",
                                      ipv4_verdict="valid")))

    # Full TSO: also zero the IPv4 header checksum (bytes 10-12).
    tso_tcp = tcp_zero[:10] + b"\x00\x00" + tcp_zero[12:]
    entries.append(_entry(
        "offload_tso_tcp_v4", "checksum_offload", tso_tcp, 4, "tcp",
        ethertype,
        "TSO/GSO capture: zero IPv4 header AND zero TCP checksums; "
        "dpkt bytes() would fabricate both",
        "not_present", _expect_layers(4, "tcp", "not_present",
                                      ipv4_verdict="not_present")))

    raw_ip, ethertype, *_ = valid_packets["v4_udp_even"]
    udp_tso = (raw_ip[:10] + b"\x00\x00" + raw_ip[12:20 + 6] + b"\x00\x00"
               + raw_ip[20 + 8:])
    entries.append(_entry(
        "offload_tso_udp_v4", "checksum_offload", udp_tso, 4, "udp",
        ethertype,
        "TSO/GSO capture with zero IPv4 header and zero UDP checksums",
        "not_present", _expect_layers(4, "udp", "not_present",
                                      ipv4_verdict="not_present")))

    raw_ip, ethertype, *_ = valid_packets["v6_tcp_even"]
    tcp_zero6 = raw_ip[:40 + 16] + b"\x00\x00" + raw_ip[40 + 18:]
    entries.append(_entry(
        "offload_l4zero_tcp_v6", "checksum_offload", tcp_zero6, 6, "tcp",
        ethertype,
        "zero TCP checksum over IPv6 (offload); dpkt bytes() always fabricates it",
        "not_present", _expect_layers(6, "tcp", "not_present")))

    raw_ip, ethertype, *_ = valid_packets["v6_udp_even"]
    udp_zero6 = raw_ip[:40 + 6] + b"\x00\x00" + raw_ip[40 + 8:]
    entries.append(_entry(
        "offload_l4zero_udp_v6", "checksum_offload", udp_zero6, 6, "udp",
        ethertype,
        "zero UDP checksum over IPv6: illegal per RFC 8200, commonly an offload artifact",
        "not_present", _expect_layers(6, "udp", "not_present")))

    # ---- dpkt trap demonstration ----------------------------------------
    # The full-TSO frame is the one whose dpkt serialization actually invents
    # checksums (see offload_demo.py).
    entries.append(_entry(
        "serialization_trap_tso_tcp_v4", "serialization_trap", tso_tcp, 4,
        "tcp", ethertype,
        "control sample: bytes() on this TSO frame fabricates both checksums",
        "not_present", _expect_layers(4, "tcp", "not_present",
                                      ipv4_verdict="not_present")))

    return entries


def write_pcap(path, entries):
    """Write frames to a classic little-endian pcap (DLT_EN10MB).

    Frames that are byte-identical (e.g. a control sample reusing an offload
    frame) are written once so every pcap record maps to one corpus entry.
    """
    seen = set()
    with open(path, "wb") as fh:
        writer = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
        ts = 0
        for entry in entries:
            if entry["frame"] in seen:
                continue
            seen.add(entry["frame"])
            writer.writepkt_time(entry["frame"], ts + 1.0)
            ts += 1
    return path


def build_corpus_map():
    return {e["name"]: e for e in build_corpus()}

"""Tests for offline ICMP error quote correlation.

The fixtures build every packet locally; nothing here opens a socket.
"""
import os
import struct
import sys

import dpkt
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'examples'))

import icmp_correlation  # noqa: F401  (ensures module imports standalone)
from icmp_correlation_demo import (  # noqa: E402
    LOCAL, SERVER, ROUTER, build_icmp_error, build_tcp_syn, build_udp,
    tamper_inner_port,
)
from icmp_correlation import (  # noqa: E402
    AMBIGUOUS, UNCORRELATED, UNIQUE, CorrelationError, SentRecord,
    correlate, parse_quote,
)


def _records():
    pkt1 = build_udp(40001, 53, b'query-A-payload-xxxxxxxx', ident=0x1111)
    pkt2 = build_udp(40001, 53, b'query-B-payload-yyyyyyyy', ident=0x2222)
    opts = b'\x01\x44\x08\x05\x00\x00\x00\x00'
    pkt3 = build_udp(40002, 53, b'options-payload-zzzzzz', ident=0x3333,
                     opts=opts)
    big = bytes((i * 7) & 0xff for i in range(600))
    full = build_udp(40003, 500, big, ident=0x4444)
    frag_payload = full[20 + 1480:]
    frag2_hdr = build_udp(40003, 500, frag_payload, ident=0x4444,
                          frag_off=1480)
    frag2 = bytearray(frag2_hdr[:20])
    frag2[2:4] = struct.pack('!H', len(full))
    frag2[10:12] = b'\x00\x00'
    frag2[10:12] = struct.pack('!H', dpkt.in_cksum(bytes(frag2)))
    frag2 = bytes(frag2) + frag_payload
    tcp6 = build_tcp_syn(40009, 80, seq=1000, ident=0x6666, window=65535)
    tcp7 = build_tcp_syn(40009, 80, seq=1000, ident=0x6666, window=8192)
    return [
        SentRecord(1, 1000.0, pkt1),
        SentRecord(2, 1000.25, pkt2),
        SentRecord(3, 1000.5, pkt3),
        SentRecord(4, 1001.0, full[:1500]),
        SentRecord(5, 1001.01, frag2),
        SentRecord(6, 1001.2, tcp6),
        SentRecord(7, 1001.4, tcp7),
    ]


def test_correct_quote_is_unique_with_offsets():
    records = _records()
    original = records[0].ip_bytes
    icmp = build_icmp_error(original)
    result = correlate(icmp, 1000.03, records)
    assert result.verdict == UNIQUE
    candidate = result.candidates[0]
    assert candidate.record.packet_id == 1
    # Quote starts after outer IP(20) + ICMP error header(8).
    assert result.evidence.inner_ip_offset == 28
    assert candidate.matched_bytes == len(original)
    assert candidate.transport_matched is True


def test_forged_port_quote_is_rejected_with_byte_evidence():
    records = _records()
    original = records[0].ip_bytes
    forged = build_icmp_error(original, tamper=tamper_inner_port,
                              src=ROUTER)
    result = correlate(forged, 1000.04, records)
    assert result.verdict == UNCORRELATED
    assert result.candidates == []
    joined = ' '.join(result.reasons)
    # Inner UDP dst port sits at inner offset 22..23 (IHL 20 + 2).
    assert 'inner offset 23' in joined
    assert 'record 1 rejected' in joined
    # The outer source is retained as observation but changes nothing.
    assert result.outer_observation['icmp_type'] == 3


def test_reused_endpoints_exact_quote_still_unique():
    records = _records()
    icmp = build_icmp_error(records[1].ip_bytes)
    result = correlate(icmp, 1000.28, records)
    assert result.verdict == UNIQUE
    assert result.candidates[0].record.packet_id == 2


def test_reused_endpoints_shared_prefix_is_ambiguous():
    records = _records()
    short = records[6].ip_bytes[:28]  # identical prefix for #6 and #7
    icmp = build_icmp_error(short)
    result = correlate(icmp, 1001.43, records)
    assert result.verdict == AMBIGUOUS
    assert sorted(c.record.packet_id for c in result.candidates) == [6, 7]
    for candidate in result.candidates:
        assert candidate.matched_bytes == 28


def test_truncated_quote_inside_inner_header_is_uncorrelated():
    records = _records()
    icmp = build_icmp_error(records[0].ip_bytes, quote_len=12)
    result = correlate(icmp, 1000.05, records)
    assert result.verdict == UNCORRELATED
    assert result.candidates == []
    assert 'minimum 20-byte IPv4 header' in ' '.join(result.reasons)


def test_ip_options_quote_matches_and_reports_option_length():
    records = _records()
    icmp = build_icmp_error(records[2].ip_bytes)
    result = correlate(icmp, 1000.54, records)
    assert result.verdict == UNIQUE
    assert result.candidates[0].record.packet_id == 3
    assert result.evidence.inner_options_length == 8
    assert result.evidence.inner_header_length == 28


def test_non_first_fragment_quote_has_no_transport_evidence():
    records = _records()
    frag2 = records[4].ip_bytes
    assert dpkt.ip.IP(frag2).offset == 1480 // 8
    icmp = build_icmp_error(frag2)
    result = correlate(icmp, 1001.06, records)
    assert result.verdict == UNIQUE
    assert result.candidates[0].record.packet_id == 5
    assert result.evidence.is_first_fragment is False
    assert result.evidence.transport_present is False
    assert result.evidence.inner_checksum_ok is True


def test_time_window_excludes_otherwise_matching_record():
    records = _records()
    icmp = build_icmp_error(records[0].ip_bytes)
    result = correlate(icmp, 1100.0, records, max_window=30.0)
    assert result.verdict == UNCORRELATED
    assert 'outside time window' in ' '.join(result.reasons)
    inside = correlate(icmp, 1000.03, records, max_window=30.0)
    assert inside.verdict == UNIQUE


def test_outer_source_alone_never_drives_verdict():
    records = _records()
    # A "plausible" router source cannot rescue a forged inner reference.
    forged = build_icmp_error(records[0].ip_bytes, tamper=tamper_inner_port)
    result = correlate(forged, 1000.04, records)
    assert result.verdict == UNCORRELATED
    assert result.outer_observation['outer_src'] == ROUTER


def test_non_icmp_outer_packet_raises():
    records = _records()
    tcp = build_tcp_syn(1, 2, 3, 4)
    with pytest.raises(CorrelationError):
        correlate(tcp, 1000.0, records)


def test_parse_quote_rejects_non_ipv4():
    bad = bytes([0x60]) + b'\x00' * 27
    with pytest.raises(CorrelationError):
        parse_quote(bad, 28)


def test_quote_shorter_than_declared_ihl_is_unusable():
    records = _records()
    # IHL claims 24 bytes but only 22 are present.
    mangled = bytearray(records[0].ip_bytes[:22])
    mangled[0] = 0x46
    icmp = build_icmp_error(bytes(mangled))
    result = correlate(icmp, 1000.1, records)
    assert result.verdict == UNCORRELATED
    assert 'inner IHL declares' in ' '.join(result.reasons)


def test_ethernet_framed_input_is_accepted():
    records = _records()
    raw = build_icmp_error(records[0].ip_bytes)
    eth = dpkt.ethernet.Ethernet(
        src=b'\xaa\xbb\xcc\xdd\xee\xff', dst=b'\x11\x22\x33\x44\x55\x66',
        type=dpkt.ethernet.ETH_TYPE_IP, data=raw)
    result = correlate(bytes(eth), 1000.03, records)
    assert result.verdict == UNIQUE
    assert result.candidates[0].record.packet_id == 1


def test_inner_icmp_echo_quote_uses_id_prefix():
    # Inner ICMP echo: id=0x4242, seq=0x0001, followed by payload.
    inner_icmp = struct.pack('!BBHHH', 8, 0, 0, 0x4242, 1) + b'echo-data'
    checksum = dpkt.in_cksum(inner_icmp)
    inner_icmp = inner_icmp[:2] + struct.pack('!H', checksum) + inner_icmp[4:]
    total = 20 + len(inner_icmp)
    header = struct.pack('!BBHHHBBH', 0x45, 0, total, 0x5555, 0, 64,
                         dpkt.ip.IP_PROTO_ICMP, 0) + LOCAL + SERVER
    header = header[:10] + struct.pack('!H', dpkt.in_cksum(header)) + header[12:]
    echo_packet = header + inner_icmp
    records = [SentRecord(1, 1000.0, echo_packet)]

    outer = build_icmp_error(echo_packet, icmp_type=11, code=0)
    result = correlate(outer, 1000.02, records)
    assert result.verdict == UNIQUE
    assert result.evidence.transport_present is True
    assert result.evidence.transport_prefix_length == 4

    # Tamper the echo id (inner offset 20..21): byte evidence must reject it.
    mangled = bytearray(echo_packet)
    mangled[20] ^= 0xff
    forged = build_icmp_error(bytes(mangled), icmp_type=11, code=0)
    forged_result = correlate(forged, 1000.03, records)
    assert forged_result.verdict == UNCORRELATED
    assert 'inner offset 20' in ' '.join(forged_result.reasons)


def test_no_socket_or_network_primitives_used():
    source_path = os.path.join(os.path.dirname(__file__), '..', 'examples',
                               'icmp_correlation.py')
    with open(source_path) as handle:
        source = handle.read()
    for forbidden in ('import socket', 'from socket', 'send(', 'sendto(',
                      'connect(', 'urllib', 'requests'):
        assert forbidden not in source

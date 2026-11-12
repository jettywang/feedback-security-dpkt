"""Tests for the passive checksum verification experiment.

Run with:  python -m pytest checksum_lab/ -v
"""

import copy
import hashlib
import os
import struct

import dpkt.dpkt
import dpkt.ip
import dpkt.ip6
import pytest

from . import corpus, reference
from .offload_demo import demonstrate
from .run_experiment import run
from .verifier import (INCONCLUSIVE, MISMATCH, NOT_PRESENT, VALID,
                       verify_packet)


def test_reference_matches_dpkt_in_cksum_on_odd_and_even_buffers():
    # Independent oracle must agree with dpkt's own implementation, while
    # sharing no code with it.
    for buf in (b"", b"\x01", b"\x01\x02", b"abcdefgh", b"x" * 13,
                bytes(range(255)), b"\xff" * 7):
        assert reference.internet_checksum(buf) == dpkt.dpkt.in_cksum(buf)


def test_reference_roundtrip_property():
    # RFC 1071: when the checksum field sits at its real aligned offset in a
    # complete message, recomputing over the whole message yields zero.
    header = bytearray(b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x06"
                       b"\x00\x00" + b"\x0a" * 8)
    header[10:12] = struct.pack(">H", reference.internet_checksum(bytes(header)))
    assert reference.internet_checksum(bytes(header)) == 0
    assert reference.verify_ones_complement(bytes(header))

    # Appending a checksum to an EVEN-length buffer keeps alignment, so zero
    # holds there as well.
    for payload in (b"", b"ab", b"abcd", b"even-payload"):
        embedded = payload + struct.pack(">H", reference.internet_checksum(payload))
        assert reference.internet_checksum(embedded) == 0


def test_odd_length_appended_checksum_is_not_naively_zero():
    # Document the odd-length trap: a checksum appended after an ODD number of
    # bytes shifts padding alignment, so naive re-sum is non-zero. Real headers
    # place the checksum at a fixed offset (handled by zeroing that field),
    # which is exactly what verifier.transport_checksum does.
    payload = b"abc"
    naive = payload + struct.pack(">H", reference.internet_checksum(payload))
    assert reference.internet_checksum(naive) != 0
    # Correct construction: zero the checksum field at its fixed offset.
    segment = bytearray(b"\x00" * 6 + b"\x00\x00" + payload)
    segment[6:8] = struct.pack(
        ">H", reference.internet_checksum(bytes(segment[:6]) + b"\x00\x00"
                                           + payload))
    assert reference.internet_checksum(bytes(segment)) == 0


def test_corpus_expected_verdicts(tmp_path):
    pcap = tmp_path / "corpus.pcap"
    out = tmp_path / "report.json"
    payload = run(str(pcap), str(out))
    assert payload["summary"]["all_expectations_met"]
    assert payload["summary"]["all_bytes_unchanged"]
    assert not payload["summary"]["failures"]
    assert os.path.getsize(str(pcap)) > 0


@pytest.mark.parametrize("entry", corpus.build_corpus(),
                         ids=lambda e: e["name"])
def test_each_sample_verdict_and_nonmutation(entry):
    raw = entry["raw_ip"]
    raw_digest = hashlib.sha256(raw).digest()
    parsed_before = (dpkt.ip6.IP6(raw) if entry["ip_version"] == 6
                     else dpkt.ip.IP(raw))
    snapshot = copy.deepcopy(parsed_before)

    report = verify_packet(raw, entry["name"])

    assert hashlib.sha256(raw).digest() == raw_digest, "raw bytes changed"
    assert report.overall == entry["expect"]
    got = {v.layer: v.verdict for v in report.verdicts}
    for layer, verdict in entry["expect_layers"].items():
        if layer in got:
            assert got[layer] == verdict

    parsed_after = (dpkt.ip6.IP6(raw) if entry["ip_version"] == 6
                    else dpkt.ip.IP(raw))
    # Field-level comparison without serializing either object.
    for name, _, _ in parsed_before.__hdr__:
        assert getattr(snapshot, name) == getattr(parsed_after, name)


def test_valid_packets_have_full_byte_evidence():
    for entry in corpus.build_corpus():
        if entry["kind"] != "valid":
            continue
        report = verify_packet(entry["raw_ip"], entry["name"])
        assert report.overall == VALID
        for verdict in report.verdicts:
            assert verdict.verdict == VALID
            assert verdict.computed is not None
            assert verdict.stored == verdict.computed
            assert verdict.truncated is False


def test_single_byte_corruption_is_mismatch_never_inconclusive():
    for entry in corpus.build_corpus():
        if entry["kind"] != "single_byte_corruption":
            continue
        report = verify_packet(entry["raw_ip"], entry["name"])
        assert report.overall == MISMATCH
        assert any(v.verdict == MISMATCH for v in report.verdicts)
        assert all(v.verdict != INCONCLUSIVE for v in report.verdicts)


def test_truncation_is_inconclusive_never_valid_or_mismatch():
    for entry in corpus.build_corpus():
        if entry["kind"] != "truncated":
            continue
        report = verify_packet(entry["raw_ip"], entry["name"])
        assert report.overall == INCONCLUSIVE
        assert all(v.verdict == INCONCLUSIVE for v in report.verdicts)


def test_zero_and_offload_checksums_are_not_present_not_valid():
    # The zeroed layer itself must never be VALID; other layers (e.g. the IPv4
    # header in an L4-only offload frame) can still carry a real checksum.
    for entry in corpus.build_corpus():
        if entry["kind"] not in ("zero_checksum", "checksum_offload",
                                 "serialization_trap"):
            continue
        report = verify_packet(entry["raw_ip"], entry["name"])
        assert report.overall == NOT_PRESENT
        for layer, expected in entry["expect_layers"].items():
            verdict = next(v for v in report.verdicts if v.layer == layer)
            assert verdict.verdict == expected
            if expected == NOT_PRESENT:
                assert verdict.computed is None


def test_l4_only_offload_keeps_valid_ipv4_header_checksum():
    entry = next(e for e in corpus.build_corpus()
                 if e["name"] == "offload_l4zero_tcp_v4")
    report = verify_packet(entry["raw_ip"], entry["name"])
    ipv4 = next(v for v in report.verdicts if v.layer == "ipv4")
    tcp = next(v for v in report.verdicts if v.layer == "tcp")
    assert ipv4.verdict == VALID and tcp.verdict == NOT_PRESENT


def test_full_tso_offload_marks_both_layers_not_present():
    entry = next(e for e in corpus.build_corpus()
                 if e["name"] == "offload_tso_tcp_v4")
    report = verify_packet(entry["raw_ip"], entry["name"])
    layers = {v.layer: v.verdict for v in report.verdicts}
    assert layers == {"ipv4": NOT_PRESENT, "tcp": NOT_PRESENT}


def test_ipv4_udp_zero_checksum_classification():
    entry = next(e for e in corpus.build_corpus()
                 if e["name"] == "zero_udp_checksum_v4")
    report = verify_packet(entry["raw_ip"], entry["name"])
    udp = next(v for v in report.verdicts if v.layer == "udp")
    ipv4 = next(v for v in report.verdicts if v.layer == "ipv4")
    assert udp.verdict == NOT_PRESENT
    assert "RFC 768" in udp.reason
    assert ipv4.verdict == VALID


def test_serialization_trap_fabricates_checksum():
    lines, assertions = demonstrate()
    assert assertions
    assert any("FABRICATED" in line for line in lines)


def test_odd_length_uses_rfc1071_padding():
    # 3-byte payload gives an odd-length TCP segment overall (IP hdr excluded).
    entry = next(e for e in corpus.build_corpus()
                 if e["name"] == "valid_v4_tcp_odd")
    segment = entry["raw_ip"][20:]
    assert len(segment) % 2 == 1
    report = verify_packet(entry["raw_ip"], entry["name"])
    assert report.overall == VALID
    # flipping the final odd byte must still be detected
    broken = bytearray(entry["raw_ip"])
    broken[-1] ^= 0xFF
    assert verify_packet(bytes(broken)).overall == MISMATCH


def test_verifier_does_not_call_serializer(monkeypatch):
    import dpkt.tcp
    import dpkt.udp

    def boom(self):
        raise AssertionError("serializer invoked during verification")

    # Seal every serializer that could recompute or rewrite a checksum.
    monkeypatch.setattr(dpkt.ip.IP, "__bytes__", boom)
    monkeypatch.setattr(dpkt.ip6.IP6, "__bytes__", boom)
    monkeypatch.setattr(dpkt.tcp.TCP, "__bytes__", boom)
    monkeypatch.setattr(dpkt.udp.UDP, "__bytes__", boom)

    for name in ("offload_l4zero_tcp_v4", "offload_tso_tcp_v4",
                 "offload_l4zero_udp_v6", "valid_v4_udp_odd",
                 "corrupt_payload_v6_tcp_odd", "truncated_payload_v4_udp_even"):
        entry = next(e for e in corpus.build_corpus() if e["name"] == name)
        report = verify_packet(entry["raw_ip"], entry["name"])
        assert report.overall == entry["expect"]


from .alerting import NON_PASSING, classify_layer, classify_packet


def test_only_valid_is_positive_evidence():
    assert classify_layer("valid")[2] is True
    for verdict in NON_PASSING:
        assert classify_layer(verdict)[2] is False


def test_packet_decisions_partition_corpus_correctly():
    expected_decision = {
        "valid": "pass",
        "single_byte_corruption": "alert",
        "truncated": "no_evidence",
        "checksum_offload": None,      # depends on L4-only vs full TSO shape
        "zero_checksum": "partial_pass",
        "serialization_trap": "no_evidence",
    }
    for entry in corpus.build_corpus():
        report = verify_packet(entry["raw_ip"], entry["name"])
        decision = classify_packet(report)["decision"]
        wanted = expected_decision[entry["kind"]]
        if wanted is not None:
            assert decision == wanted, (entry["name"], decision)
        else:
            assert decision in ("partial_pass", "no_evidence")


def test_never_pass_without_full_byte_evidence():
    for entry in corpus.build_corpus():
        report = verify_packet(entry["raw_ip"], entry["name"])
        decision = classify_packet(report)
        if decision["decision"] == "pass":
            assert all(v.verdict == "valid" and not v.truncated
                       and v.computed is not None for v in report.verdicts)

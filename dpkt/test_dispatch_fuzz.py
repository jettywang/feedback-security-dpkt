# -*- coding: utf-8 -*-
"""Regression tests for the structured Ethernet/IP/transport fuzzing harness.

The tests pin down the four guarantees the harness exists to provide:

1. the seed corpus is made of genuinely legal frames;
2. a legal frame carrying an unknown protocol number is returned as raw
   payload, not rejected or mis-decoded;
3. a deliberately length-check-relaxed parser variant is detected because it
   turns damaged inner data into a normal protocol object;
4. the shrinking step keeps the target layer reachable and never degrades into
   an empty packet that cannot reach that layer.
"""
from __future__ import absolute_import

import json
import os
import random

import pytest

from . import dispatch_fuzz as fuzz
from . import dpkt
from . import ethernet
from . import ip


def _records_by_id(result):
    return {(r['seed'], r['mutation']): r for r in result['records']}


def _find(result, mut_id, kind):
    return next(f for f in result['findings']
                if f.mutation.mut_id == mut_id and f.kind == kind)


# ---------------------------------------------------------------------------
# Seed corpus and single-layer mutation structure
# ---------------------------------------------------------------------------

def test_seeds_are_legal_and_reach_declared_layers():
    for seed in fuzz.build_seeds():
        outcome = fuzz.parse_frame(seed.frame, expected_layers=seed.layers)
        assert outcome.exc_type is None
        assert not outcome.fell_back
        # the terminal raw payload is reported as 'bytes(n)' while the seed
        # template only records the bare 'bytes' marker; a leaf packet such as
        # ICMP.Echo simply has no raw-payload node at all
        observed = tuple('bytes' if fuzz._is_raw_node(name) else name
                         for name in outcome.layers)
        assert observed[:len(seed.layers)] == tuple(seed.layers)
        for layer_name in ('Ethernet', 'IP', seed.target_layer):
            assert fuzz.reaches_layer(outcome, layer_name)


def test_every_mutation_changes_exactly_one_declared_layer():
    rng = random.Random(fuzz.DEFAULT_SEED)
    seeds = fuzz.build_seeds()
    seen = set()
    for seed, mutation in fuzz.generate_mutations(seeds, rng):
        # each (seed, mutation) pair is produced once and stays deterministic
        key = (seed.name, mutation.mut_id)
        assert key not in seen
        seen.add(key)
        assert mutation.layer in ('Ethernet', 'IP', 'TCP', 'UDP')
        assert mutation.field in ('type', 'p', 'hl', 'len', 'off', 'ulen')
        assert len(mutation.frame) > ethernet.ETH_HDR_LEN
    # all three seeds are exercised, on every mutable layer they support
    assert {seed.name for seed in seeds} == {
        name for name, _ in seen}
    assert ('eth_ip_tcp', 'tcp_off_too_small') in seen
    assert ('eth_ip_udp', 'udp_ulen_zero') in seen


def test_length_repair_keeps_target_layer_reachable():
    # The ip.len mutations deliberately rewrite the outer length; even the
    # zero-payload variant must still instantiate IP (the layer being tested)
    # instead of being dropped before dispatch.
    result = fuzz.run_campaign()
    records = _records_by_id(result)
    for seed_name in ('eth_ip_tcp', 'eth_ip_udp', 'eth_ip_icmp'):
        record = records[(seed_name, 'ip_len_zero')]
        assert 'IP' in record['reference']['layers']


# ---------------------------------------------------------------------------
# Unknown protocols stay raw, damaged-but-known layers fall back cleanly
# ---------------------------------------------------------------------------

def test_unknown_ethertype_is_raw_payload():
    result = fuzz.run_campaign()
    record = _records_by_id(result)[('eth_ip_tcp', 'eth_type_unknown')]
    ref = record['reference']
    assert ref['exception_type'] is None
    assert ref['fell_back_to_raw_bytes'] is True
    assert ref['layers'][0] == 'Ethernet'
    assert ref['terminal'].startswith('bytes(')


def test_unknown_ip_protocol_is_raw_payload_inside_ip():
    result = fuzz.run_campaign()
    record = _records_by_id(result)[('eth_ip_tcp', 'ip_proto_unknown')]
    ref = record['reference']
    # IP itself decoded fine; only the transport dispatch fell back to bytes.
    assert ref['exception_type'] is None
    assert ref['layers'][:2] == ['Ethernet', 'IP']
    assert ref['fell_back_to_raw_bytes'] is True
    assert ref['terminal'].startswith('bytes(')


def test_damaged_known_transport_falls_back_instead_of_raising():
    result = fuzz.run_campaign()
    record = _records_by_id(result)[('eth_ip_tcp', 'tcp_off_too_small')]
    ref = record['reference']
    # The reference parser must not let an unexpected exception escape and
    # must hand the damaged segment back as raw bytes.
    assert ref['exception_type'] is None
    assert ref['layers'][:2] == ['Ethernet', 'IP']
    assert ref['fell_back_to_raw_bytes'] is True


# ---------------------------------------------------------------------------
# The relaxed length-check variant must be detected
# ---------------------------------------------------------------------------

def test_relaxed_variant_is_flagged_as_divergence():
    result = fuzz.run_campaign()
    finding = _find(result, 'tcp_off_too_small', 'divergence')
    # reference parser: damaged TCP rejected -> raw bytes fallback
    assert finding.reference['fell_back_to_raw_bytes'] is True
    assert 'TCP' not in finding.reference['layers']
    # relaxed parser: same damaged bytes accepted as a protocol object
    assert finding.candidate['fell_back_to_raw_bytes'] is False
    assert 'RelaxedTCP' in finding.candidate['layers']
    assert finding.candidate['exception_type'] is None


def test_stock_parser_alone_has_no_divergence_against_itself():
    # Sanity check on the predicate: when both parsers reject identically,
    # there is no divergence even though fallback occurred.
    result = fuzz.run_campaign()
    record = _records_by_id(result)[('eth_ip_tcp', 'ip_proto_unknown')]
    ref = fuzz.Outcome(
        tuple(record['reference']['layers']),
        record['reference']['terminal'],
        record['reference']['fell_back_to_raw_bytes'],
        record['reference']['exception_type'], '')
    assert fuzz.is_divergence(ref, ref) is False


def test_proto_swap_is_restored_after_relaxed_parse():
    from . import tcp
    original = ip.IP._protosw[ip.IP_PROTO_TCP]
    frame = fuzz.build_seeds()[0].frame
    fuzz.relaxed_parse(frame)
    assert ip.IP._protosw[ip.IP_PROTO_TCP] is original
    assert ip.IP._protosw[ip.IP_PROTO_TCP] is tcp.TCP


# ---------------------------------------------------------------------------
# Determinism and the shrinking guard against empty / unreachable inputs
# ---------------------------------------------------------------------------

def test_campaign_is_deterministic_under_fixed_seed():
    first = fuzz.run_campaign(seed=fuzz.DEFAULT_SEED)
    second = fuzz.run_campaign(seed=fuzz.DEFAULT_SEED)
    assert [r['mutation'] for r in first['records']] == \
        [r['mutation'] for r in second['records']]
    assert [r['reference']['layers'] for r in first['records']] == \
        [r['reference']['layers'] for r in second['records']]
    assert [f.key for f in first['findings']] == \
        [f.key for f in second['findings']]


def test_shrink_keeps_target_layer_and_reproduces_divergence():
    result = fuzz.run_campaign()
    finding = _find(result, 'tcp_off_too_small', 'divergence')
    original = finding.mutation.frame
    expected = finding.seed.layers

    def interesting(candidate):
        return fuzz.is_divergence(
            fuzz.parse_frame(candidate, expected_layers=expected),
            fuzz.relaxed_parse(candidate, expected_layers=expected))

    minimised = fuzz.shrink(
        original, 'TCP', interesting,
        lambda frame: fuzz.relaxed_parse(frame, expected_layers=expected))

    assert 0 < len(minimised) <= len(original)
    assert len(minimised) < len(original)  # actual reduction happened
    # still reproduces the bug and still reaches the TCP layer
    assert interesting(minimised)
    relaxed_outcome = fuzz.relaxed_parse(minimised, expected_layers=expected)
    assert fuzz.reaches_layer(relaxed_outcome, 'TCP')


def test_shrink_rejects_input_that_cannot_reach_target_layer():
    seed = fuzz.build_seeds()[0]
    # An "interesting" predicate that would accept anything cannot trick the
    # shrinker: the reachability guard runs before it and requires the TCP
    # layer to be instantiated, so an empty/truncated frame is refused.
    frame = seed.frame
    with pytest.raises(ValueError):
        fuzz.shrink(frame[:ethernet.ETH_HDR_LEN], 'TCP',
                    lambda candidate: True, fuzz.parse_frame)


def test_empty_packet_is_never_accepted_as_minimised_finding(tmp_path):
    result = fuzz.run_campaign()
    finding = _find(result, 'tcp_off_too_small', 'divergence')
    expected = finding.seed.layers
    evidence = fuzz.write_evidence(result, output_dir=str(tmp_path))

    minimised_path = os.path.join(
        str(tmp_path), evidence['minimised_sample']['path'])
    original_path = os.path.join(
        str(tmp_path), evidence['original_sample']['path'])
    minimised = open(minimised_path, 'rb').read()
    original = open(original_path, 'rb').read()

    assert len(minimised) > 0
    assert len(original) > len(minimised)
    # the empty frame provably cannot reach the layer and is excluded
    empty_outcome = fuzz.relaxed_parse(b'', expected_layers=expected)
    assert not fuzz.reaches_layer(empty_outcome, 'TCP')
    assert evidence['same_target_layer']['layer'] == 'TCP'
    assert evidence['same_target_layer']['original_reaches_it'] is True
    assert evidence['same_target_layer']['minimised_reaches_it'] is True


# ---------------------------------------------------------------------------
# On-disk evidence: original sample, minimised sample, shared target layer
# ---------------------------------------------------------------------------

def test_evidence_files_are_written_and_consistent(tmp_path):
    result = fuzz.run_campaign()
    evidence = fuzz.write_evidence(result, output_dir=str(tmp_path))

    with open(os.path.join(str(tmp_path), 'evidence.json')) as handle:
        loaded = json.load(handle)
    assert loaded == evidence
    assert loaded['seed_value'] == fuzz.DEFAULT_SEED
    assert loaded['mutation'] == 'tcp_off_too_small'

    for sample_key in ('original_sample', 'minimised_sample'):
        sample = loaded[sample_key]
        payload = open(os.path.join(
            str(tmp_path), sample['path']), 'rb').read()
        assert len(payload) == sample['length']
        # reference parser falls back; relaxed parser builds a TCP object
        assert sample['reference_parser']['fell_back_to_raw_bytes'] is True
        assert sample['relaxed_parser']['fell_back_to_raw_bytes'] is False
        assert 'RelaxedTCP' in sample['relaxed_parser']['layers']


def test_boundary_exceptions_are_recorded_not_swallowed():
    # A frame shorter than the Ethernet header legitimately raises NeedData,
    # an expected boundary error. The harness records its type rather than
    # letting it propagate or silently treating the frame as parsed.
    outcome = fuzz.parse_frame(b'\x00' * 5)
    assert outcome.exc_type == dpkt.NeedData.__name__
    assert outcome.layers == ()
    assert fuzz.is_escape(outcome) is False

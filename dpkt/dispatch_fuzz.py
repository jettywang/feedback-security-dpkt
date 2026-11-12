# -*- coding: utf-8 -*-
"""Structured, seed-based fuzzing for the Ethernet -> IP -> transport dispatch.

This is a small regression harness rather than a generic fuzzer:

* a handful of hand-built, fully legal frames form the seed corpus;
* every mutation changes exactly one protocol field on one layer (a protocol
  number, a header length or a payload length), optionally repairing the
  enclosing length field so that the target layer is actually instantiated;
* the parser outcome is recorded as the stack of layers that were decoded,
  whether the damaged inner data fell back to raw ``bytes``, any exception
  that escaped the documented ``dpkt.UnpackError`` boundary and the fixed
  random seed that made the run reproducible.

The harness also ships a deliberately relaxed parser variant.  A mutation that
the reference parser rejects (falling back to raw bytes) but that the relaxed
parser turns into a normal protocol object is reported as a *divergence*,
i.e. exactly the "damaged inner data mistaken for a protocol object" class of
bug the tool is meant to catch.
"""
from __future__ import absolute_import, print_function

import os
import random

from . import dpkt
from . import ethernet
from . import icmp
from . import ip
from . import tcp
from . import udp

# Fixed seed: the same seed corpus and mutations are generated on every run.
DEFAULT_SEED = 0x5EED

# Exceptions a caller may legitimately have to handle when feeding arbitrary
# bytes to dpkt.  Anything outside this family crossing the Ethernet() entry
# point is recorded as an unexpected parser-boundary escape.
EXPECTED_ERRORS = (dpkt.UnpackError, dpkt.NeedData)

CORPUS_DIR = os.path.join(os.path.dirname(__file__), 'fuzz_corpus')

# Byte offsets (absolute inside an Ethernet frame) of the fields the mutator
# is allowed to touch.  Kept in one place so the mutation rules read like the
# protocol specs instead of magic numbers.
OFF_ETH_TYPE = 12
OFF_IP_VHL = 14
OFF_IP_LEN = 16
OFF_IP_P = 23
OFF_TCP_OFF_FLAGS = 14 + 20 + 12
OFF_UDP_ULEN = 14 + 20 + 4


# ---------------------------------------------------------------------------
# Seed corpus: a small set of legal frames, each annotated with the layers a
# correct parser must walk and the layer that mutations are trying to reach.
# ---------------------------------------------------------------------------

class Seed(object):
    """A legal frame plus the exact layer chain a correct parser produces."""

    def __init__(self, name, frame, layers, target_layer, transport_proto,
                 transport_off=None):
        self.name = name
        self.frame = bytes(frame)
        self.layers = tuple(layers)
        self.target_layer = target_layer
        self.transport_proto = transport_proto
        # Absolute offset of the transport header length field, if the seed
        # has one (TCP data offset / UDP length).
        self.transport_off = transport_off

    def __repr__(self):
        return 'Seed(%s, %d bytes, layers=%s)' % (
            self.name, len(self.frame), '>'.join(self.layers))


def _eth_ip_frame(transport, proto):
    ip_pkt = ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
                   p=proto, data=transport)
    eth = ethernet.Ethernet(dst=b'\x02\x00\x00\x00\x00\x01',
                            src=b'\x02\x00\x00\x00\x00\x02',
                            type=ethernet.ETH_TYPE_IP, data=ip_pkt)
    return bytes(eth)


def build_seeds():
    """Return the small, deterministic corpus of undamaged legal frames."""
    tcp_pkt = tcp.TCP(sport=0x1234, dport=80)
    tcp_pkt._off_flags = (5 << 12) | tcp.TH_ACK
    tcp_pkt.data = b'GET / HTTP/1.0\r\n\r\n'
    tcp_frame = _eth_ip_frame(tcp_pkt, ip.IP_PROTO_TCP)

    udp_pkt = udp.UDP(sport=0x1000, dport=53)
    udp_pkt.data = b'dns-query'
    udp_pkt.ulen = udp.UDP_HDR_LEN + len(udp_pkt.data)
    udp_frame = _eth_ip_frame(udp_pkt, ip.IP_PROTO_UDP)

    icmp_pkt = icmp.ICMP(type=8, code=0)
    icmp_pkt.data = icmp.ICMP.Echo(id=1, seq=1)
    icmp_frame = _eth_ip_frame(icmp_pkt, ip.IP_PROTO_ICMP)

    return [
        Seed('eth_ip_tcp', tcp_frame,
             ('Ethernet', 'IP', 'TCP', 'bytes'), 'TCP', ip.IP_PROTO_TCP,
             transport_off=OFF_TCP_OFF_FLAGS),
        Seed('eth_ip_udp', udp_frame,
             ('Ethernet', 'IP', 'UDP', 'bytes'), 'UDP', ip.IP_PROTO_UDP,
             transport_off=OFF_UDP_ULEN),
        Seed('eth_ip_icmp', icmp_frame,
             ('Ethernet', 'IP', 'ICMP', 'Echo'), 'ICMP',
             ip.IP_PROTO_ICMP),
    ]


# ---------------------------------------------------------------------------
# Structured mutation: each rule mutates one field on one layer.
# ---------------------------------------------------------------------------

class Mutation(object):
    """A single, structured change applied to one layer of a seed frame."""

    def __init__(self, mut_id, layer, field, frame, reaches, note=''):
        self.mut_id = mut_id
        self.layer = layer          # layer whose own field is changed
        self.field = field          # protocol number / header length / ...
        self.frame = bytes(frame)
        # Layer the mutation is designed to exercise (must stay reachable).
        self.reaches = reaches
        self.note = note

    def __repr__(self):
        return 'Mutation(%s on %s.%s -> %s)' % (
            self.mut_id, self.layer, self.field, self.reaches)


def _set_u16(buf, offset, value):
    buf = bytearray(buf)
    buf[offset:offset + 2] = bytes(bytearray((value >> 8, value & 0xff)))
    return bytes(buf)


def _set_u8(buf, offset, value):
    buf = bytearray(buf)
    buf[offset] = value & 0xff
    return bytes(buf)


def _repair_ip_len(frame, payload_len):
    """Rewrite the outer IP total length so the damaged payload still parses.

    This keeps the target layer reachable: dpkt slices ``buf[:ip.len]`` before
    dispatching to the transport protocol, so a stale length would otherwise
    hide the mutation behind a truncated or empty payload.
    """
    ip_hl = (frame[OFF_IP_VHL] & 0x0f) << 2
    return _set_u16(frame, OFF_IP_LEN, ip_hl + payload_len)


def _mutate_ethernet(seed, rng):
    frame = seed.frame
    # An unregistered but valid Ethernet II type (>1500) keeps us on the
    # Ethernet II parsing path while forcing a raw-byte fallback at layer 2.
    unknown_type = rng.choice([0x9000, 0x9999, 0xBEEF])
    yield Mutation('eth_type_unknown', 'Ethernet', 'type',
                   _set_u16(frame, OFF_ETH_TYPE, unknown_type), 'Ethernet',
                   note='unregistered ethertype, expect raw bytes fallback')


def _mutate_ip(seed, rng):
    frame = seed.frame
    # Protocol number: an unassigned IP protocol.  The IP layer still parses,
    # but the transport dispatch must fall back to the raw payload.
    unknown_proto = rng.choice([200, 222, 250])
    yield Mutation('ip_proto_unknown', 'IP', 'p',
                   _set_u8(frame, OFF_IP_P, unknown_proto), 'IP',
                   note='unregistered ip proto, expect raw bytes fallback')

    # Header length fields, expressed in 32-bit words.  Word 4 (16 bytes) is
    # below the minimum 20-byte header and forces an Ethernet-level fallback;
    # word 10 declares 40 bytes of options that are not really present.
    for hl_word, tag in ((4, 'too_small'), (10, 'oversized')):
        vhl = (frame[OFF_IP_VHL] & 0xf0) | hl_word
        yield Mutation('ip_hl_%s' % tag, 'IP', 'hl',
                       _set_u8(frame, OFF_IP_VHL, vhl), 'IP',
                       note='ip header length %s (%d bytes)' %
                            (tag, hl_word << 2))

    # Payload length, with the outer IP total length repaired so the transport
    # layer is still entered with the damaged payload.
    ip_hl = (frame[OFF_IP_VHL] & 0x0f) << 2
    transport = frame[14 + ip_hl:]
    for shrink, tag in ((0, 'zero'), (max(1, len(transport) // 2), 'half')):
        damaged = frame[:14 + ip_hl] + transport[:shrink]
        repaired = _repair_ip_len(damaged, shrink)
        yield Mutation('ip_len_%s' % tag, 'IP', 'len', repaired,
                       seed.target_layer,
                       note='ip payload cut to %d bytes, ip.len repaired' %
                            shrink)


def _mutate_transport(seed, rng):
    if seed.transport_off is None:
        return
    frame = seed.frame
    if seed.transport_proto == ip.IP_PROTO_TCP:
        # TCP data offset in 32-bit words, packed in the high nibble.  Zero is
        # below the mandatory 20-byte header; 15 claims options that do not
        # exist.  Repair ip.len so TCP.unpack still receives the full segment.
        for off_word, tag in ((0, 'too_small'), (15, 'oversized')):
            damaged = _set_u8(frame, seed.transport_off, off_word << 4)
            ip_hl = (damaged[OFF_IP_VHL] & 0x0f) << 2
            payload_len = len(damaged) - 14 - ip_hl
            yield Mutation('tcp_off_%s' % tag, 'TCP', 'off',
                           _repair_ip_len(damaged, payload_len),
                           'TCP', note='tcp data offset %s' % tag)
    elif seed.transport_proto == ip.IP_PROTO_UDP:
        # UDP length: a length shorter than the 8-byte header is invalid.
        for ulen, tag in ((0, 'zero'), (4, 'below_header')):
            damaged = _set_u16(frame, seed.transport_off, ulen)
            yield Mutation('udp_ulen_%s' % tag, 'UDP', 'ulen', damaged,
                           'UDP', note='udp length %s' % tag)


def generate_mutations(seeds, rng):
    """Yield every one-layer mutation for every seed, exactly once each."""
    for seed in seeds:
        for rule in (_mutate_ethernet, _mutate_ip, _mutate_transport):
            for mutation in rule(seed, rng):
                yield seed, mutation


# ---------------------------------------------------------------------------
# Parsing outcome: layer chain, raw fallback, boundary exceptions.
# ---------------------------------------------------------------------------

class Outcome(object):
    """What happened when one frame was fed to one parser implementation."""

    def __init__(self, layers, terminal, fell_back, exc_type, exc_message):
        self.layers = tuple(layers)
        self.terminal = terminal          # 'bytes', packet name, or exception
        self.fell_back = fell_back        # damaged inner data returned raw
        self.exc_type = exc_type          # None, or exception class name
        self.exc_message = exc_message

    @property
    def signature(self):
        return '%s|fallback=%s|exc=%s' % (
            '>'.join(self.layers), self.fell_back, self.exc_type)

    def __repr__(self):
        return 'Outcome(%s)' % self.signature


def layer_chain(packet):
    """Walk the nested ``data`` attributes without touching named aliases.

    Named aliases such as ``eth.ip`` are intentionally avoided: when a layer
    falls back to raw bytes the alias is missing, which itself raises an
    ``AttributeError`` unrelated to the frame under test.
    """
    chain = []
    current = packet
    while isinstance(current, dpkt.Packet):
        chain.append(type(current).__name__)
        current = current.data
    if isinstance(current, (bytes, bytearray)):
        chain.append('bytes(%d)' % len(current))
    else:
        chain.append(type(current).__name__)
    return chain


def _is_raw_node(name):
    # Observed raw nodes look like 'bytes(18)'; the seed template uses the
    # bare marker 'bytes' for the position where raw payload is expected.
    return name == 'bytes' or name.startswith('bytes(')


def _fell_back(chain, expected_layers):
    """Whether an expected packet layer came back as undifferentiated bytes.

    A legal TCP/UDP frame legitimately ends in a ``bytes`` payload, so a bare
    "ends in bytes" check cannot tell fallback apart from success.  Instead we
    walk every position the seed says must hold a decoded packet object and
    verify the observed chain has a packet (not raw bytes) there.  The concrete
    class name is irrelevant, which lets the relaxed parser stand in for TCP.
    """
    if expected_layers is None:
        return any(_is_raw_node(part) for part in chain[:-1])
    for index, expected in enumerate(expected_layers):
        if _is_raw_node(expected):
            continue  # the seed itself expected raw payload at this position
        if index >= len(chain) or _is_raw_node(chain[index]):
            return True
    return False


def parse_frame(frame, parser_cls=ethernet.Ethernet, expected_layers=None):
    """Parse one frame and normalise the result into an :class:`Outcome`."""
    try:
        packet = parser_cls(frame)
    except EXPECTED_ERRORS as exc:
        return Outcome((), 'exception', False,
                       type(exc).__name__, str(exc))
    except Exception as exc:  # noqa: BLE001 - recorded, not swallowed silently
        # An exception outside the documented UnpackError family escaping the
        # Ethernet entry point is a parser-boundary escape worth flagging.
        return Outcome((), 'exception', False,
                       type(exc).__name__, str(exc))

    chain = layer_chain(packet)
    # A raw `bytes` node where a protocol object was expected means the
    # damaged inner layer was handed back as undifferentiated payload.
    fell_back = _fell_back(chain, expected_layers)
    terminal = chain[-1] if chain else 'bytes(0)'
    return Outcome(chain, terminal, fell_back, None, '')


def reaches_layer(outcome, layer_name):
    """True if the parse actually instantiated the requested protocol layer.

    Matching is by packet kind rather than exact class name so the relaxed
    ``RelaxedTCP`` stand-in still counts as reaching the ``TCP`` layer.
    """
    for name in outcome.layers:
        if _is_raw_node(name):
            continue
        if name == layer_name or name.endswith(layer_name):
            return True
    return False


# ---------------------------------------------------------------------------
# Deliberately relaxed transport parser used as the mutation-detection target.
# ---------------------------------------------------------------------------

class RelaxedTCP(tcp.TCP):
    """TCP variant that silently accepts an invalid data offset.

    The reference parser raises ``UnpackError`` for an offset shorter than the
    fixed 20-byte header, which makes IP fall back to raw bytes.  This variant
    clamps the offset to zero instead.  A frame rejected by the reference but
    accepted here as a ``RelaxedTCP`` object demonstrates a length-validation
    regression that the harness must detect.
    """

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        ol = ((self._off_flags >> 12) << 2) - self.__hdr_len__
        if ol < 0:
            ol = 0
        self.opts = buf[self.__hdr_len__:self.__hdr_len__ + ol]
        self.data = buf[self.__hdr_len__ + ol:]


class _ProtoSwap(object):
    """Temporarily install a parser class into the IP dispatch table."""

    def __init__(self, proto_number, replacement):
        self.proto_number = proto_number
        self.replacement = replacement
        self._original = None

    def __enter__(self):
        self._original = ip.IP._protosw.get(self.proto_number)
        ip.IP.set_proto(self.proto_number, self.replacement)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._original is not None:
            ip.IP.set_proto(self.proto_number, self._original)
        return False


def relaxed_parse(frame, expected_layers=None):
    """Parse a frame with the relaxed TCP parser installed."""
    with _ProtoSwap(ip.IP_PROTO_TCP, RelaxedTCP):
        return parse_frame(frame, expected_layers=expected_layers)


# ---------------------------------------------------------------------------
# Findings, delta-debugging shrinker and the campaign driver.
# ---------------------------------------------------------------------------

class Finding(object):
    """A single interesting result produced by the fuzzing campaign."""

    def __init__(self, seed, mutation, reference, candidate, kind):
        self.seed = seed
        self.mutation = mutation
        self.reference = outcome_view(reference)
        self.candidate = outcome_view(candidate)
        self.kind = kind          # 'divergence' or 'escape'

    @property
    def key(self):
        return '%s:%s:%s' % (self.seed.name, self.mutation.mut_id, self.kind)

    def __repr__(self):
        return 'Finding(%s, %s)' % (self.key, self.kind)


def outcome_view(outcome):
    """JSON-serialisable snapshot of an outcome for evidence files."""
    return {
        'layers': list(outcome.layers),
        'terminal': outcome.terminal,
        'fell_back_to_raw_bytes': outcome.fell_back,
        'exception_type': outcome.exc_type,
        'exception_message': outcome.exc_message,
    }


def is_divergence(reference, relaxed):
    """Reference fell back / errored while relaxed produced a real object."""
    reference_object = (not reference.fell_back and
                        reference.exc_type is None)
    relaxed_object = (not relaxed.fell_back and relaxed.exc_type is None)
    return (not reference_object) and relaxed_object


def is_escape(outcome):
    """An exception outside the expected UnpackError family escaped."""
    return outcome.exc_type is not None and \
        outcome.exc_type not in (
            error.__name__ for error in EXPECTED_ERRORS)


def _frame_reaches(frame, layer_name, parser):
    outcome = parser(frame)
    return reaches_layer(outcome, layer_name), outcome


def shrink(frame, target_layer, is_interesting, parser, max_rounds=64):
    """Delta-debug a failing frame while keeping the target layer reachable.

    ``is_interesting`` decides whether a candidate still reproduces the bug.
    A candidate that can no longer instantiate ``target_layer`` is rejected
    even if it is shorter, so the minimiser can never degrade into an empty
    packet that never reaches the layer under test.
    """
    current = bytes(frame)
    reachable, _ = _frame_reaches(current, target_layer, parser)
    if not reachable:
        raise ValueError(
            'starting frame does not reach target layer %r' % target_layer)

    for _ in range(max_rounds):
        n = len(current)
        if n <= 1:
            break
        granularity = 2
        reduced = False
        while granularity <= n:
            chunk = max(1, n // granularity)
            for start in range(0, n, chunk):
                candidate = current[:start] + current[start + chunk:]
                if not candidate:
                    continue  # an empty frame cannot reach any target layer
                reachable, _ = _frame_reaches(
                    candidate, target_layer, parser)
                if not reachable:
                    continue
                if is_interesting(candidate):
                    current = candidate
                    reduced = True
                    break
            if reduced:
                break
            granularity *= 2
        if not reduced:
            break
    return current


def run_campaign(seed=DEFAULT_SEED):
    """Fuzz every structured mutation and collect reproducible findings."""
    rng = random.Random(seed)
    seeds = build_seeds()
    findings = []
    records = []

    for seed_pkt, mutation in generate_mutations(seeds, rng):
        reference = parse_frame(mutation.frame,
                                expected_layers=seed_pkt.layers)
        relaxed = relaxed_parse(mutation.frame,
                                expected_layers=seed_pkt.layers)

        record = {
            'seed': seed_pkt.name,
            'mutation': mutation.mut_id,
            'layer': mutation.layer,
            'field': mutation.field,
            'target_layer': mutation.reaches,
            'note': mutation.note,
            'reference': outcome_view(reference),
            'relaxed': outcome_view(relaxed),
        }
        records.append(record)

        if is_divergence(reference, relaxed):
            findings.append(Finding(seed_pkt, mutation, reference,
                                    relaxed, 'divergence'))
        elif is_escape(reference):
            findings.append(Finding(seed_pkt, mutation, reference,
                                    relaxed, 'escape'))

    return {
        'seed': seed,
        'seeds': seeds,
        'records': records,
        'findings': findings,
    }


# ---------------------------------------------------------------------------
# Evidence on disk: original sample, minimised sample and shared target layer.
# ---------------------------------------------------------------------------

def _write_bytes(path, payload):
    with open(path, 'wb') as handle:
        handle.write(payload)


def write_evidence(result, output_dir=CORPUS_DIR):
    """Persist the first divergence finding and its minimised counterpart."""
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)
    finding = next((f for f in result['findings']
                    if f.kind == 'divergence'), None)
    if finding is None:
        raise AssertionError('no divergence finding to persist')

    original = finding.mutation.frame
    target_layer = finding.mutation.reaches
    expected_layers = finding.seed.layers

    def relaxed_interesting(candidate):
        return is_divergence(
            parse_frame(candidate, expected_layers=expected_layers),
            relaxed_parse(candidate, expected_layers=expected_layers))

    # The reference parser falls back before TCP, so reachability of the
    # target layer must be checked with the same relaxed parser that exposes
    # the bug; otherwise the guard would reject the original finding itself.
    minimised = shrink(original, target_layer, relaxed_interesting,
                       lambda frame: relaxed_parse(
                           frame, expected_layers=expected_layers))

    original_outcome = parse_frame(
        original, expected_layers=expected_layers)
    minimised_outcome = parse_frame(
        minimised, expected_layers=expected_layers)
    original_relaxed = relaxed_parse(
        original, expected_layers=expected_layers)
    minimised_relaxed = relaxed_parse(
        minimised, expected_layers=expected_layers)

    _write_bytes(os.path.join(output_dir, 'original_sample.bin'), original)
    _write_bytes(os.path.join(output_dir, 'minimised_sample.bin'), minimised)

    evidence = {
        'seed_value': result['seed'],
        'seed_name': finding.seed.name,
        'mutation': finding.mutation.mut_id,
        'target_layer': target_layer,
        'original_sample': {
            'path': 'original_sample.bin',
            'length': len(original),
            'reference_parser': outcome_view(original_outcome),
            'relaxed_parser': outcome_view(original_relaxed),
        },
        'minimised_sample': {
            'path': 'minimised_sample.bin',
            'length': len(minimised),
            'reference_parser': outcome_view(minimised_outcome),
            'relaxed_parser': outcome_view(minimised_relaxed),
        },
        'same_target_layer': {
            'layer': target_layer,
            'original_reaches_it':
                reaches_layer(relaxed_parse(original), target_layer),
            'minimised_reaches_it':
                reaches_layer(relaxed_parse(minimised), target_layer),
        },
    }
    import json
    with open(os.path.join(output_dir, 'evidence.json'), 'w') as handle:
        json.dump(evidence, handle, indent=2, sort_keys=True)
    return evidence


def main():  # pragma: no cover - manual entry point
    result = run_campaign()
    print('seed: 0x%x' % result['seed'])
    print('seeds: %d' % len(result['seeds']))
    print('mutations: %d' % len(result['records']))
    print('findings: %d' % len(result['findings']))
    for finding in result['findings']:
        print('  %s' % finding)
    evidence = write_evidence(result)
    print('evidence written to %s' % CORPUS_DIR)
    print('target layer reached by both samples: %s' %
          evidence['same_target_layer'])


if __name__ == '__main__':  # pragma: no cover
    main()

#!/usr/bin/env python3
"""Offline correlation of ICMP error quotes against recorded outbound packets.

The module answers a narrow question for an alarm backend: which, if any,
previously observed outbound datagram is the one quoted inside an ICMP error
message?  It works exclusively on captured bytes (sent packets and later ICMP
messages) and never opens a socket or emits traffic.

Correlation is evidence based:

* the embedded (inner) IP header is parsed directly from the quoted bytes;
* every byte the quote actually contains must equal the same byte range of the
  recorded original datagram (a prefix check, which covers IP options, the
  transport header prefix and any payload that survived);
* the available transport layer prefix (ports / ICMP id) is checked instead of
  assumed when the quote is short;
* the arrival time must fall inside a configurable window after the send;
* multiple survivors of all checks stay *ambiguous* -- incomplete evidence is
  never promoted into a definite attribution.

The outer ICMP source address is recorded as observation only and is never
sufficient on its own to declare the original communication failed.
"""

import struct

import dpkt
from dpkt.compat import compat_ord

# ICMP messages that carry a quote of the offending datagram (RFC 792 / 1122).
ICMP_ERROR_TYPES = {
    3: 'destination-unreachable',
    4: 'source-quench',
    5: 'redirect',
    11: 'time-exceeded',
    12: 'parameter-problem',
}

# Fixed ICMP header length per error type (before the quoted bytes).
_ICMP_HDR_LEN = {3: 8, 4: 8, 5: 8, 11: 8, 12: 8}

# Structured verdicts.
UNIQUE = 'unique'
AMBIGUOUS = 'ambiguous'
UNCORRELATED = 'uncorrelated'

_TRANSPORT_PORT_PROTOS = {dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP,
                          dpkt.ip.IP_PROTO_SCTP}


class CorrelationError(Exception):
    """Raised when the outer packet cannot be inspected at all."""

    def __init__(self, message, evidence=None):
        super(CorrelationError, self).__init__(message)
        self.evidence = evidence


class QuoteEvidence(object):
    """Byte-level facts extracted from the ICMP quote.

    All offsets are absolute byte offsets inside the outer IP datagram so the
    caller can point at the exact evidence in the captured frame.
    """

    def __init__(self):
        self.icmp_quote_offset = None
        self.inner_ip_offset = None
        self.quote_length = 0
        self.available_datagram_length = 0
        self.inner_total_length = None
        self.inner_header_length = None
        self.inner_options_length = 0
        self.fragment_offset = 0
        self.more_fragments = False
        self.is_first_fragment = True
        self.transport_present = False
        self.transport_proto = None
        self.transport_prefix_length = 0
        self.src_port = None
        self.dst_port = None
        self.inner_checksum_ok = None
        self.truncated_inner_header = False
        self.received_transport_prefix = None
        self.received_inner_bytes = None
        self.received_ip_header = None


class Candidate(object):
    """A sent record that survived the byte-level comparison."""

    def __init__(self, record, matched_bytes, time_delta, transport_matched):
        self.record = record
        self.matched_bytes = matched_bytes
        self.time_delta = time_delta
        self.transport_matched = transport_matched


class CorrelationResult(object):
    """Verdict plus the byte evidence supporting it."""

    def __init__(self, verdict, evidence, candidates=None, reasons=None,
                 outer_observation=None):
        self.verdict = verdict
        self.evidence = evidence
        self.candidates = candidates or []
        self.reasons = reasons or []
        # Observation only: never feeds the verdict.
        self.outer_observation = outer_observation or {}

    def __repr__(self):
        ids = [c.record.packet_id for c in self.candidates]
        return 'CorrelationResult(%s, candidates=%s, reasons=%r)' % (
            self.verdict, ids, self.reasons)


class SentRecord(object):
    """One outbound datagram the alarm backend recorded."""

    def __init__(self, packet_id, timestamp, ip_bytes, link_bytes=None):
        self.packet_id = packet_id
        self.timestamp = float(timestamp)
        self.link_bytes = link_bytes
        try:
            self.ip = dpkt.ip.IP(ip_bytes)
        except dpkt.UnpackError as exc:
            raise CorrelationError(
                'sent packet %s is not a parseable IP datagram: %s'
                % (packet_id, exc))
        self.ip_bytes = bytes(self.ip)


def _transport_ports(ip_bytes, l4_offset):
    """Return (src, dst, prefix_length, raw_prefix) for a port carrying proto.

    Prefix length is how many transport bytes are actually available; a short
    quote may expose zero, two or four port bytes.
    """
    available = len(ip_bytes) - l4_offset
    if available <= 0:
        return None, None, 0, b''
    raw = ip_bytes[l4_offset:l4_offset + min(4, available)]
    src = struct.unpack('!H', raw[0:2])[0] if available >= 2 else None
    dst = struct.unpack('!H', raw[2:4])[0] if available >= 4 else None
    return src, dst, len(raw), raw


def _icmp_identity_prefix(ip_bytes, l4_offset):
    """Echo id/seq prefix for inner ICMP (4 bytes when available)."""
    available = len(ip_bytes) - l4_offset
    if available <= 0:
        return 0, b''
    raw = ip_bytes[l4_offset:l4_offset + min(4, available)]
    return len(raw), raw


def parse_outer(frame_or_ip):
    """Extract outer IP/ICMP headers from an Ethernet frame or raw IP packet.

    Returns (outer_ip, observation, icmp_payload_offset, payload).
    Raises CorrelationError for frames that are not ICMP/IP error messages.
    """
    buf = bytes(frame_or_ip)
    # Accept Ethernet or raw IPv4 input.
    if len(buf) >= 1 and (buf[0] >> 4) == 4:
        ip_bytes = buf
    else:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except dpkt.UnpackError as exc:
            raise CorrelationError('outer frame is neither raw IP nor '
                                   'Ethernet: %s' % exc)
        if not isinstance(eth.data, dpkt.ip.IP):
            raise CorrelationError(
                'outer frame does not carry IPv4 (got %s)'
                % eth.data.__class__.__name__)
        ip_bytes = bytes(eth.data)

    try:
        outer_ip = dpkt.ip.IP(ip_bytes)
    except dpkt.UnpackError as exc:
        raise CorrelationError('outer IPv4 header unparseable: %s' % exc)

    if outer_ip.p != dpkt.ip.IP_PROTO_ICMP:
        raise CorrelationError(
            'outer packet protocol is %s, not ICMP(1)' % outer_ip.p)

    icmp_offset = outer_ip.hl * 4
    icmp_bytes = ip_bytes[icmp_offset:]
    if len(icmp_bytes) < 4:
        raise CorrelationError('ICMP header truncated (%d bytes)'
                               % len(icmp_bytes))
    icmp_type, icmp_code, _icmp_sum = struct.unpack('!BBH', icmp_bytes[:4])
    if icmp_type not in ICMP_ERROR_TYPES:
        raise CorrelationError(
            'ICMP type %s is not an error quote (types %s)'
            % (icmp_type, sorted(ICMP_ERROR_TYPES)))

    hdr_len = _ICMP_HDR_LEN.get(icmp_type, 8)
    if len(icmp_bytes) < hdr_len:
        raise CorrelationError('ICMP error header truncated')

    payload_offset = icmp_offset + hdr_len
    payload = ip_bytes[payload_offset:]
    observation = {
        'outer_src': outer_ip.src,
        'outer_dst': outer_ip.dst,
        'icmp_type': icmp_type,
        'icmp_type_name': ICMP_ERROR_TYPES[icmp_type],
        'icmp_code': icmp_code,
        'icmp_checksum_ok': dpkt.in_cksum(icmp_bytes) == 0,
        'outer_ttl': outer_ip.ttl,
    }
    return outer_ip, observation, payload_offset, payload


def parse_quote(quote_bytes, quote_offset):
    """Parse the quoted inner datagram without trusting its length field."""
    ev = QuoteEvidence()
    ev.icmp_quote_offset = quote_offset
    ev.inner_ip_offset = quote_offset
    ev.quote_length = len(quote_bytes)
    ev.received_inner_bytes = bytes(quote_bytes)

    if len(quote_bytes) < 20:
        ev.truncated_inner_header = True
        raise CorrelationError(
            'quote contains %d bytes at offset %d, shorter than the minimum '
            '20-byte IPv4 header' % (len(quote_bytes), quote_offset), ev)

    version_ihl = compat_ord(quote_bytes[0])
    if version_ihl >> 4 != 4:
        raise CorrelationError(
            'quoted header at offset %d is not IPv4 (version=%d)'
            % (quote_offset, version_ihl >> 4), ev)
    ihl = (version_ihl & 0x0f) * 4
    if ihl < 20:
        raise CorrelationError('quoted IHL %d is below 20 bytes' % ihl, ev)
    if len(quote_bytes) < ihl:
        ev.truncated_inner_header = True
        ev.inner_header_length = ihl
        raise CorrelationError(
            'quote ends at %d bytes but inner IHL declares %d bytes (offset '
            '%d)' % (len(quote_bytes), ihl, quote_offset), ev)

    ev.inner_header_length = ihl
    ev.inner_options_length = ihl - 20
    ev.received_ip_header = quote_bytes[:ihl]

    total_len = struct.unpack('!H', quote_bytes[2:4])[0]
    ev.inner_total_length = total_len
    ident = struct.unpack('!H', quote_bytes[4:6])[0]
    flags_frag = struct.unpack('!H', quote_bytes[6:8])[0]
    ev.more_fragments = bool(flags_frag & dpkt.ip.IP_MF)
    ev.fragment_offset = (flags_frag & dpkt.ip.IP_OFFMASK) * 8
    ev.is_first_fragment = ev.fragment_offset == 0
    proto = compat_ord(quote_bytes[9])
    ev.transport_proto = proto
    src = quote_bytes[12:16]
    dst = quote_bytes[16:20]
    hdr_checksum = struct.unpack('!H', quote_bytes[10:12])[0]
    ev.inner_checksum_ok = (
        dpkt.in_cksum(quote_bytes[:ihl]) == 0 or hdr_checksum == 0)

    # The datagram length we can actually compare is the minimum of the
    # declared length and the bytes present in the quote.
    if total_len and total_len >= ihl:
        ev.available_datagram_length = min(total_len, len(quote_bytes))
    else:
        ev.available_datagram_length = len(quote_bytes)

    if ev.is_first_fragment:
        l4_offset = ihl
        if proto in _TRANSPORT_PORT_PROTOS and len(quote_bytes) > l4_offset:
            sp, dp, plen, raw = _transport_ports(quote_bytes, l4_offset)
            ev.transport_present = plen > 0
            ev.src_port = sp
            ev.dst_port = dp
            ev.transport_prefix_length = plen
            ev.received_transport_prefix = raw
        elif proto == dpkt.ip.IP_PROTO_ICMP and len(quote_bytes) > l4_offset:
            plen, raw = _icmp_identity_prefix(quote_bytes, l4_offset)
            ev.transport_present = plen > 0
            ev.transport_prefix_length = plen
            ev.received_transport_prefix = raw
    return ev, (src, dst, proto, ident)


def _compare_record(record, quote_bytes, ev, inner_tuple, icmp_time,
                    max_window):
    """Return a Candidate when every quoted byte matches, else a reason."""
    src, dst, proto, ident = inner_tuple
    ip = record.ip

    if ip.src != src or ip.dst != dst or ip.p != proto:
        return None, '5-tuple address/protocol mismatch'
    if ip.id != ident:
        return None, 'IP identification field mismatch'

    delta = icmp_time - record.timestamp
    if delta < 0:
        return None, 'ICMP observed %.6fs before the send' % (-delta,)
    if max_window is not None and delta > max_window:
        return None, ('outside time window: %.6fs > %.6fs'
                      % (delta, max_window))

    original = record.ip_bytes
    available = ev.available_datagram_length
    if len(original) < available:
        return None, ('original datagram (%d bytes) shorter than quoted '
                      'evidence (%d bytes)' % (len(original), available))

    # Hard byte-prefix comparison over everything the quote contains.
    compared = quote_bytes[:available]
    if original[:available] != compared:
        first = next((idx for idx in range(available)
                      if original[idx] != compared[idx]), available)
        return None, ('byte mismatch at inner offset %d (outer offset %d): '
                      'original %02x != quote %02x'
                      % (first, ev.inner_ip_offset + first,
                         original[first], compared[first]))

    transport_matched = True
    if ev.is_first_fragment and ev.transport_present:
        l4 = ev.inner_header_length
        transport_matched = (
            original[l4:l4 + ev.transport_prefix_length]
            == ev.received_transport_prefix)
        if not transport_matched:
            return None, 'transport prefix mismatch (port/ICMP id bytes)'

    return Candidate(record, available, delta, transport_matched), None


def correlate(frame_or_ip, icmp_timestamp, sent_records, max_window=30.0):
    """Correlate one captured ICMP error against sent packet records.

    Args:
        frame_or_ip: raw Ethernet frame or raw IP bytes of the ICMP message.
        icmp_timestamp: capture time of the ICMP message (seconds, float).
        sent_records: iterable of SentRecord built from outbound captures.
        max_window: maximum seconds between send and ICMP arrival; records
            outside the window cannot be candidates.

    Returns:
        CorrelationResult with verdict UNIQUE, AMBIGUOUS or UNCORRELATED and
        byte-level evidence / rejection reasons.
    """
    _outer, observation, payload_offset, payload = parse_outer(
        frame_or_ip)
    try:
        evidence, inner_tuple = parse_quote(payload, payload_offset)
    except CorrelationError as exc:
        partial = exc.evidence or QuoteEvidence()
        return CorrelationResult(UNCORRELATED, partial,
                                 reasons=['quote unusable: %s' % exc],
                                 outer_observation=observation)

    candidates = []
    reasons = []
    for record in sent_records:
        candidate, reason = _compare_record(
            record, payload, evidence, inner_tuple,
            float(icmp_timestamp), max_window)
        if candidate is not None:
            candidates.append(candidate)
        else:
            reasons.append('record %s rejected: %s'
                           % (record.packet_id, reason))

    if len(candidates) == 1:
        verdict = UNIQUE
    elif len(candidates) > 1:
        verdict = AMBIGUOUS
        reasons.append('%d records share the identical quoted prefix and fit '
                       'the time window' % len(candidates))
    else:
        verdict = UNCORRELATED
        if not reasons:
            reasons.append('no sent record shares the quoted 5-tuple')

    return CorrelationResult(verdict, evidence, candidates=candidates,
                             reasons=reasons, outer_observation=observation)

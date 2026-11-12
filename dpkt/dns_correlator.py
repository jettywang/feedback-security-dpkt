# -*- coding: utf-8 -*-
"""Offline DNS response correlation and contradiction analysis.

This module correlates DNS queries with their responses in a captured packet
stream without relying on the transaction ID alone.  A correlation key is built
from the two communicating endpoints, the DNS transaction ID and the full
question section (every question's name, type and class).  Query names are
case-normalized (DNS names are case-insensitive per RFC 4343) while the
question type, class and the boundary between multiple questions are kept
verbatim.

The analyzer handles several real-world conditions:

* port reuse - the same (ip, port) pair is reused for a new transaction once the
  previous one is finished, so generations are tracked per endpoint pair;
* query retransmission - identical repeated queries extend an existing entry
  instead of creating a new one, and answers to any retransmission are folded
  into the same result;
* response seen before its query - orphan responses are buffered and adopted
  when the matching query arrives;
* multiple different answers - answers are compared on their content, and
  contradictory answer sets are reported together with the originating packet
  numbers;
* correlation window and backlog limits - both are caller configurable.

Different TTLs alone never produce a contradiction: TTLs are deliberately
excluded from the answer fingerprint.

The four possible verdicts are:

* ``MATCHED``        - one or more consistent answers were observed;
* ``CONTRADICTORY``  - at least two answers with different content were seen;
* ``INSUFFICIENT``   - the exchange was never completed (no answer, or an
  orphan response whose query never showed up, or a backlog entry dropped to
  honor ``max_pending``);
* ``OUT_OF_WINDOW``  - an answer arrived outside the configured window.
"""
from __future__ import absolute_import

import heapq
import struct

from . import dpkt
from . import dns as dnsmod
from .dns import DNS
from .ethernet import Ethernet
from .ip import IP
from .ip6 import IP6
from .pcap import DLT_EN10MB, DLT_RAW, Reader
from .udp import UDP

# Public verdict constants.
MATCHED = 'MATCHED'
CONTRADICTORY = 'CONTRADICTORY'
INSUFFICIENT = 'INSUFFICIENT'
OUT_OF_WINDOW = 'OUT_OF_WINDOW'

DEFAULT_WINDOW = 5.0
DEFAULT_MAX_PENDING = 10000

_DNS_PORT = 53


class Endpoints(tuple):
    """Direction-independent 4-tuple ``(src_ip, src_port, dst_ip, dst_port)``.

    The tuple is stored with the lexicographically smaller ``(ip, port)`` side
    first so that a query and its reversed response hash to the same value.
    IP addresses are kept as packed bytes (4 or 16) so IPv4 and IPv6 endpoints
    never collide.
    """

    __slots__ = ()

    def __new__(cls, ip_a, port_a, ip_b, port_b):
        side_a = (bytes(ip_a), int(port_a))
        side_b = (bytes(ip_b), int(port_b))
        if side_a <= side_b:
            first, second = side_a, side_b
        else:
            first, second = side_b, side_a
        return tuple.__new__(cls, (first[0], first[1], second[0], second[1]))

    def direction(self, src_ip, src_port):
        """Return ``1`` when the sender is the first side, ``-1`` otherwise."""
        sender = (bytes(src_ip), int(src_port))
        if sender == (self[0], self[1]):
            return 1
        return -1


def _normalize_name(name):
    """Lowercase a DNS name; everything else about it is preserved."""
    if isinstance(name, bytes):
        return name.lower()
    return name.lower()


def _question_signature(question):
    """Fingerprint one question.

    Only the name is case-folded; type and class are retained, which keeps the
    boundary of a multi-question section intact when the tuples are compared.
    """
    return (_normalize_name(question.name), int(question.type), int(question.cls))


def _questions_signature(dns_pkt):
    return tuple(_question_signature(q) for q in dns_pkt.qd)


def _read_name_at(buf, offset):
    """Read a possibly compressed name directly from a raw message buffer.

    Handles names that mix literal labels with a trailing compression pointer
    (the common on-the-wire shape for CNAME/NS targets inside rdata).
    """
    labels = []
    cursor = offset
    safety = 0
    while True:
        if cursor >= len(buf) or safety > len(buf):
            raise dpkt.NeedData('truncated name')
        length = buf[cursor]
        if length == 0:
            break
        if (length & 0xc0) == 0xc0:
            if cursor + 1 >= len(buf):
                raise dpkt.NeedData('truncated compression pointer')
            pointer = struct.unpack('>H', buf[cursor:cursor + 2])[0] & 0x3fff
            if pointer >= offset:
                raise dpkt.UnpackError('forward or circular compression pointer')
            labels.append(_read_name_at(buf, pointer))
            break
        cursor += 1
        labels.append(buf[cursor:cursor + length])
        cursor += length
        safety += 1
    return b'.'.join(labels)


def _name_types():
    return dnsmod.DNS_NS, dnsmod.DNS_CNAME, dnsmod.DNS_PTR


def _rr_fingerprint(rr, raw, rdata_offset):
    """Content fingerprint of a resource record.

    The TTL is intentionally excluded: two answers that only differ by TTL
    describe the same record and must not be treated as a contradiction.  Names
    embedded in the rdata are resolved in full (following any compression
    pointers, including names made of literal labels plus a trailing pointer)
    and case-folded, so wire representation differences do not create false
    conflicts.  Everything else - owner name, type, class and raw rdata - is
    compared byte for byte.
    """
    owner = _normalize_name(rr.name)
    rdata = bytes(rr.rdata)
    rtype = int(rr.type)
    if rtype in _name_types() and rdata:
        try:
            rdata = _read_name_at(raw, rdata_offset).lower()
        except (dpkt.NeedData, dpkt.UnpackError):
            pass
    elif rtype in (dnsmod.DNS_SOA, dnsmod.DNS_MX, dnsmod.DNS_SRV):
        # These types begin with a fixed-size prefix followed by a name.
        prefix_len = {dnsmod.DNS_SOA: 20, dnsmod.DNS_MX: 2,
                      dnsmod.DNS_SRV: 6}[rtype]
        if len(rdata) > prefix_len:
            try:
                embedded = _read_name_at(raw, rdata_offset + prefix_len).lower()
                rdata = rdata[:prefix_len] + embedded
            except (dpkt.NeedData, dpkt.UnpackError):
                pass
    return owner, rtype, int(rr.cls), rdata


def _answer_fingerprint(dns_pkt, raw):
    """Fingerprint the answer content of a response (answer RRs + rcode).

    RRs are sorted into a canonical multiset so that the same answer set sent in
    a different order still matches.  The rcode is part of the fingerprint
    because NXDOMAIN and a successful answer to the same question are
    contradictory, even when the answer section is empty.
    """
    offsets = _answer_rdata_offsets(raw, dns_pkt)
    records = tuple(sorted(
        _rr_fingerprint(rr, raw, offsets.get(index, 0))
        for index, rr in enumerate(dns_pkt.an)))
    return int(dns_pkt.rcode), records


def _name_end_offset(buf, offset):
    """Return the offset just past the (possibly compressed) name at offset."""
    cursor = offset
    while True:
        if cursor >= len(buf):
            raise dpkt.NeedData('truncated name')
        length = buf[cursor]
        if length == 0:
            return cursor + 1
        if (length & 0xc0) == 0xc0:
            return cursor + 2
        cursor += 1 + length


def _answer_rdata_offsets(raw, dns_pkt):
    """Map each answer-section RR index to its rdata offset in the raw message.

    The question section and every answer RR are walked in order, so offsets are
    derived structurally rather than by searching for byte patterns.
    """
    offsets = {}
    offset = dns_pkt.__hdr_len__
    for _ in dns_pkt.qd:
        offset = _name_end_offset(raw, offset) + 4
    for index, rr in enumerate(dns_pkt.an):
        rdata_start = _name_end_offset(raw, offset) + 10
        offsets[index] = rdata_start
        offset = rdata_start + rr.rlen
    return offsets


class DnsRecord(object):
    """One parsed DNS datagram plus where and when it was observed."""

    __slots__ = ('packet_no', 'timestamp', 'endpoints', 'is_response',
                 'txn_id', 'questions', 'answer', 'rcode', 'direction')

    def __init__(self, packet_no, timestamp, endpoints, is_response, dns_pkt, raw, direction):
        self.packet_no = packet_no
        self.timestamp = float(timestamp)
        self.endpoints = endpoints
        self.is_response = is_response
        self.txn_id = int(dns_pkt.id)
        self.questions = _questions_signature(dns_pkt)
        self.answer = _answer_fingerprint(dns_pkt, raw) if is_response else None
        self.rcode = int(dns_pkt.rcode)
        self.direction = direction

    @property
    def key(self):
        return self.endpoints, self.txn_id, self.questions


class _Pending(object):
    """State kept for one correlation key while the exchange is open."""

    __slots__ = ('key', 'generation', 'query_packets', 'query_times',
                 'response_packets', 'answer_times', 'answers',
                 'anchor_time', 'out_of_window')

    def __init__(self, key, generation, anchor_time):
        self.key = key
        self.generation = generation
        self.query_packets = []
        self.query_times = []
        self.response_packets = []
        self.answer_times = []
        # Ordered mapping of answer fingerprint -> packet numbers carrying it.
        self.answers = {}
        self.anchor_time = anchor_time
        self.out_of_window = False

    def add_query(self, record):
        if record.packet_no not in self.query_packets:
            self.query_packets.append(record.packet_no)
            self.query_times.append(record.timestamp)
            self.query_packets.sort()

    def add_response(self, record):
        if record.packet_no not in self.response_packets:
            self.response_packets.append(record.packet_no)
            self.answer_times.append(record.timestamp)
            self.answers.setdefault(record.answer, []).append(record.packet_no)
            self.response_packets.sort()

    @property
    def has_query(self):
        return bool(self.query_packets)

    @property
    def earliest_time(self):
        candidates = self.query_times + self.answer_times
        return min(candidates) if candidates else self.anchor_time

    @property
    def last_activity(self):
        candidates = self.query_times + self.answer_times
        return max(candidates) if candidates else self.anchor_time


class CorrelationResult(object):
    """Final verdict for one correlated DNS exchange."""

    __slots__ = ('status', 'endpoints', 'txn_id', 'questions', 'generation',
                 'query_packets', 'response_packets', 'answers',
                 'evidence', 'first_seen', 'last_seen')

    def __init__(self, status, pending):
        self.status = status
        self.endpoints = pending.key[0]
        self.txn_id = pending.key[1]
        self.questions = pending.key[2]
        self.generation = pending.generation
        self.query_packets = tuple(pending.query_packets)
        self.response_packets = tuple(pending.response_packets)
        # Mapping answer fingerprint -> packet numbers carrying that answer.
        self.answers = {fingerprint: tuple(packets)
                        for fingerprint, packets in pending.answers.items()}
        # Deterministic per-answer evidence, ordered by the first packet that
        # carried each distinct answer.
        self.evidence = tuple(sorted(
            ((fingerprint, tuple(packets))
             for fingerprint, packets in pending.answers.items()),
            key=lambda item: item[1][0]))
        self.first_seen = pending.earliest_time
        self.last_seen = pending.last_activity

    def __repr__(self):
        return ('CorrelationResult(status=%s, txn_id=0x%04x, queries=%s, responses=%s)' %
                (self.status, self.txn_id, self.query_packets, self.response_packets))


def parse_dns_datagram(packet_no, timestamp, src_ip, src_port, dst_ip, dst_port, udp_payload):
    """Build a :class:`DnsRecord` from one UDP datagram.

    Returns ``None`` when the payload is not a parseable DNS message or carries
    no question section (such messages cannot be correlated on content).
    """
    try:
        dns_pkt = DNS(udp_payload)
    except (dpkt.NeedData, dpkt.UnpackError, dpkt.PackError):
        return None
    if not dns_pkt.qd:
        return None
    endpoints = Endpoints(src_ip, src_port, dst_ip, dst_port)
    direction = endpoints.direction(src_ip, src_port)
    return DnsRecord(packet_no, timestamp, endpoints, bool(dns_pkt.qr),
                     dns_pkt, bytes(udp_payload), direction)


def iter_dns_records(fileobj):
    """Yield :class:`DnsRecord` objects from a classic pcap file object.

    Ethernet (``DLT_EN10MB``) and raw IP (``DLT_RAW``) link layers are
    supported, for both IPv4 and IPv6 UDP/53 traffic.  Non-DNS and unparseable
    packets are skipped.  Packet numbers start at one in capture order.
    """
    reader = Reader(fileobj)
    linktype = reader.datalink()
    if linktype not in (DLT_EN10MB, DLT_RAW):
        raise ValueError('unsupported pcap linktype %s' % linktype)

    packet_no = 0
    for timestamp, frame in reader:
        packet_no += 1
        try:
            if linktype == DLT_EN10MB:
                eth = Ethernet(frame)
                ip_pkt = eth.data
            else:
                ip_pkt = IP(frame) if frame and (frame[0] >> 4) == 4 else IP6(frame)
            if not isinstance(ip_pkt, (IP, IP6)):
                continue
            udp = ip_pkt.data
            if not isinstance(udp, UDP):
                continue
        except (dpkt.NeedData, dpkt.UnpackError, dpkt.PackError):
            continue

        src_ip, dst_ip = ip_pkt.src, ip_pkt.dst
        if udp.sport != _DNS_PORT and udp.dport != _DNS_PORT:
            continue
        record = parse_dns_datagram(packet_no, timestamp,
                                    src_ip, udp.sport, dst_ip, udp.dport,
                                    udp.data)
        if record is not None:
            yield record


class DnsResponseCorrelator(object):
    """Streaming, order-tolerant offline DNS response correlator.

    Args:
        window: maximum allowed time in seconds between a query and any answer
            that belongs to it.  Answers outside the window are reported as
            :data:`OUT_OF_WINDOW`.
        max_pending: maximum number of open correlation keys (including buffered
            orphan responses) kept at once.  When the limit is reached the
            oldest entry is closed as :data:`INSUFFICIENT`; ``None`` disables
            the limit.
    """

    def __init__(self, window=DEFAULT_WINDOW, max_pending=DEFAULT_MAX_PENDING):
        if window < 0:
            raise ValueError('window must be non-negative')
        if max_pending is not None and max_pending <= 0:
            raise ValueError('max_pending must be positive or None')
        self.window = float(window)
        self.max_pending = max_pending
        # key -> _Pending for exchanges still waiting for more evidence.
        self._pending = {}
        # endpoints -> generation of the entry currently open.  When an entry
        # closes and the same endpoint pair reuses the port for a new
        # transaction, the replacement entry gets a fresh generation.
        self._generations = {}
        # (anchor_time, seq, key) heap backing the max_pending eviction policy.
        self._evict_heap = []
        self._evict_seq = 0

    def feed(self, record):
        """Process one :class:`DnsRecord`; return any results closed now."""
        key = record.key
        pending = self._pending.get(key)
        if record.is_response:
            return self._handle_response(record, key, pending)
        evicted = self._handle_query(record, key, pending)
        return evicted

    def _handle_query(self, record, key, pending):
        if pending is None:
            evicted = self._open_pending(key, record.timestamp)
        else:
            evicted = []
        pending = self._pending[key]
        pending.add_query(record)
        # The query may adopt an orphan entry that already buffered answers.
        if pending.has_query and len(pending.answers) > 1:
            return self._close(key)
        return evicted

    def _handle_response(self, record, key, pending):
        if pending is None:
            # Response read before its query: buffer it as an orphan.  No
            # verdict is reached here - the entry stays open so the matching
            # query can adopt every orphaned answer when it is read later, and
            # the final conflict set stays independent of input ordering.
            evicted = self._open_pending(key, record.timestamp)
            self._pending[key].add_response(record)
            return evicted

        if pending.query_packets:
            latest_query = max(pending.query_times)
            if abs(record.timestamp - latest_query) > self.window:
                # This answer cannot belong to the open exchange.  Finalize the
                # existing entry as out-of-window, then buffer the late answer
                # on its own so a genuinely later query can still adopt it.
                pending.out_of_window = True
                closed = self._close(key)
                self._open_pending(key, record.timestamp)
                late_pending = self._pending[key]
                late_pending.add_response(record)
                return closed

        pending.add_response(record)
        # A contradiction can only be declared once the exchange's query has
        # actually been observed; an orphan-only entry keeps buffering answers.
        if pending.has_query and len(pending.answers) > 1:
            # Contradiction established; the verdict is final and independent of
            # any further packets or the order they were read in.
            return self._close(key)
        return []

    def _open_pending(self, key, anchor_time):
        """Open a new entry, evicting the oldest one if the backlog is full.

        Returns the list of results produced by an eviction (usually empty or a
        single :data:`INSUFFICIENT` result).
        """
        evicted = []
        if self.max_pending is not None and len(self._pending) >= self.max_pending:
            evicted = self._evict_oldest()
        endpoints = key[0]
        generation = self._generations.get(endpoints, 0) + 1
        self._generations[endpoints] = generation
        pending = _Pending(key, generation, anchor_time)
        self._pending[key] = pending
        self._evict_seq += 1
        heapq.heappush(self._evict_heap, (anchor_time, self._evict_seq, key))
        return evicted

    def _evict_oldest(self):
        while self._evict_heap:
            _, _, key = heapq.heappop(self._evict_heap)
            pending = self._pending.pop(key, None)
            if pending is not None:
                # Evictions are delivered through the feed() return value, not
                # the flush() backlog, so callers never see them twice.
                return [self._build_result(INSUFFICIENT, pending)]
        return []

    def _close(self, key):
        pending = self._pending.pop(key)
        self._evict_heap = [item for item in self._evict_heap if item[2] != key]
        heapq.heapify(self._evict_heap)
        # Closed on the spot: delivered through the feed() return value and
        # deliberately kept out of the flush() backlog so it is never reported
        # twice.
        return [self._build_result(self._verdict(pending), pending)]

    @staticmethod
    def _verdict(pending):
        if pending.out_of_window:
            return OUT_OF_WINDOW
        if not pending.has_query or not pending.response_packets:
            # An orphan response without its query, or a query that was never
            # answered, does not carry enough evidence for any verdict.
            return INSUFFICIENT
        if len(pending.answers) > 1:
            return CONTRADICTORY
        return MATCHED

    @staticmethod
    def _build_result(status, pending):
        return CorrelationResult(status, pending)

    def flush(self):
        """Close every still-open exchange and return those results.

        Entries without a completed exchange are reported as
        :data:`INSUFFICIENT` (unanswered query or an orphan response whose query
        never arrived).  Exchanges already delivered through :meth:`feed` (a
        contradiction, an out-of-window answer or a backlog eviction) are not
        repeated.  Results are returned in a deterministic order that does not
        depend on the order in which the input packets were fed.
        """
        results = []
        for key in list(self._pending.keys()):
            pending = self._pending.pop(key)
            results.append(self._build_result(self._verdict(pending), pending))
        self._pending.clear()
        self._evict_heap = []
        results.sort(key=lambda r: (r.first_seen, r.endpoints, r.txn_id,
                                    r.generation, r.status))
        return results

    def expire(self, now):
        """Finalize entries whose last activity is older than ``now - window``.

        Optional housekeeping for long-running streams so the backlog does not
        grow without bound.  Entries already holding answers keep their normal
        verdict; unanswered or orphan-only entries become :data:`OUT_OF_WINDOW`.
        Expired entries are removed from the internal backlog, so a subsequent
        :meth:`flush` does not report them again.
        """
        expired = []
        for key, pending in list(self._pending.items()):
            if now - pending.last_activity <= self.window:
                continue
            self._pending.pop(key)
            status = self._verdict(pending)
            if status == INSUFFICIENT:
                status = OUT_OF_WINDOW
            result = self._build_result(status, pending)
            expired.append(result)
        if expired:
            self._evict_heap = [(t, seq, key) for (t, seq, key) in self._evict_heap
                                if key in self._pending]
            heapq.heapify(self._evict_heap)
        return expired


def correlate(records, window=DEFAULT_WINDOW, max_pending=DEFAULT_MAX_PENDING):
    """Convenience wrapper: correlate an iterable of :class:`DnsRecord`.

    Returns every result - those finalized early while feeding (contradictions,
    out-of-window answers and backlog evictions) as well as the remaining
    exchanges closed by the final flush - in one deterministic, order-independent
    sequence.
    """
    correlator = DnsResponseCorrelator(window=window, max_pending=max_pending)
    results = []
    for record in records:
        results.extend(correlator.feed(record))
    results.extend(correlator.flush())
    results.sort(key=lambda r: (r.first_seen, r.endpoints, r.txn_id,
                                r.generation, r.status))
    return results


def correlate_pcap(fileobj, window=DEFAULT_WINDOW, max_pending=DEFAULT_MAX_PENDING):
    """Correlate every DNS exchange in an open classic pcap file object."""
    return correlate(iter_dns_records(fileobj), window=window, max_pending=max_pending)


# ---------------------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------------------

CLIENT_IP = b'\x0a\x00\x00\x01'
SERVER_IP = b'\x08\x08\x08\x08'
OTHER_SERVER_IP = b'\x08\x08\x04\x04'
CLIENT_PORT = 40000
SERVER_PORT = _DNS_PORT


def _question(name, qtype=dnsmod.DNS_A, qcls=dnsmod.DNS_IN):
    return DNS.Q(name=name, type=qtype, cls=qcls)


def _rr(name, rtype=dnsmod.DNS_A, rcls=dnsmod.DNS_IN, ttl=300, rdata=b'\x01\x02\x03\x04'):
    return DNS.RR(name=name, type=rtype, cls=rcls, ttl=ttl, rdata=rdata)


def _dns_query(txn_id, questions, op=dnsmod.DNS_RD):
    pkt = DNS(id=txn_id, op=op)
    pkt.qr = 0
    pkt.qd = list(questions)
    pkt.an = []
    pkt.ns = []
    pkt.ar = []
    return pkt


def _dns_response(txn_id, questions, answers, rcode=dnsmod.DNS_RCODE_NOERR, ttl=300):
    pkt = DNS(id=txn_id, op=0)
    pkt.qr = 1
    pkt.rcode = rcode
    pkt.qd = list(questions)
    pkt.an = list(answers)
    pkt.ns = []
    pkt.ar = []
    for rr in pkt.an:
        rr.ttl = ttl
    return pkt


def _record(packet_no, timestamp, dns_pkt, from_client=True,
            client_ip=CLIENT_IP, server_ip=SERVER_IP,
            client_port=CLIENT_PORT, server_port=SERVER_PORT):
    raw = bytes(dns_pkt)
    if from_client:
        return parse_dns_datagram(packet_no, timestamp,
                                  client_ip, client_port, server_ip, server_port, raw)
    return parse_dns_datagram(packet_no, timestamp,
                              server_ip, server_port, client_ip, client_port, raw)


def _query_record(packet_no, timestamp, txn_id, name='example.com', **kwargs):
    return _record(packet_no, timestamp,
                   _dns_query(txn_id, [_question(name)]), True, **kwargs)


def _response_record(packet_no, timestamp, txn_id, rdata, name='example.com',
                     rcode=dnsmod.DNS_RCODE_NOERR, ttl=300, **kwargs):
    answers = [] if rdata is None else [_rr(name, rdata=rdata, ttl=ttl)]
    dns_pkt = _dns_response(txn_id, [_question(name)], answers, rcode=rcode, ttl=ttl)
    return _record(packet_no, timestamp, dns_pkt, False, **kwargs)


def _summary(results):
    return [(r.status, r.txn_id, r.query_packets, r.response_packets,
             tuple(sorted(pkts for _, pkts in r.evidence)))
            for r in results]


def test_endpoints_are_direction_independent():
    forward = Endpoints(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)
    reverse = Endpoints(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)
    assert forward == reverse
    assert hash(forward) == hash(reverse)
    # The lexicographically smaller side (server: (8.8.8.8, 53)) is stored
    # first, so direction is independent of constructor argument order.
    assert forward[0] == SERVER_IP and forward[1] == SERVER_PORT
    assert forward.direction(SERVER_IP, SERVER_PORT) == 1
    assert forward.direction(CLIENT_IP, CLIENT_PORT) == -1


def test_case_insensitive_name_but_type_class_boundaries_kept():
    lower = _query_record(1, 0.0, 0x1111, 'example.com')
    upper = _query_record(2, 0.1, 0x1111, 'ExAmPlE.CoM')
    assert lower.key == upper.key

    different_type = _record(3, 0.2,
                             _dns_query(0x1111, [_question('example.com', dnsmod.DNS_AAAA)]),
                             True)
    assert different_type.key != lower.key

    different_class = _record(4, 0.3,
                              _dns_query(0x1111, [_question('example.com', qcls=dnsmod.DNS_CHAOS)]),
                              True)
    assert different_class.key != lower.key

    single = _dns_query(0x2222, [_question('a.example'), _question('b.example')])
    swapped = _dns_query(0x2222, [_question('b.example'), _question('a.example')])
    single_rec = _record(5, 0.4, single, True)
    swapped_rec = _record(6, 0.5, swapped, True)
    assert single_rec.key != swapped_rec.key
    assert len(single_rec.questions) == 2


def test_matched_exchange_and_ttl_only_difference():
    records = [
        _query_record(1, 0.0, 0x3333),
        _response_record(2, 0.05, 0x3333, b'\x01\x02\x03\x04', ttl=300),
        _response_record(3, 0.08, 0x3333, b'\x01\x02\x03\x04', ttl=60),
    ]
    results = correlate(records)
    assert len(results) == 1
    result = results[0]
    assert result.status == MATCHED
    assert result.query_packets == (1,)
    assert result.response_packets == (2, 3)
    assert len(result.answers) == 1


def test_legitimate_retransmission_folds_into_one_exchange():
    records = [
        _query_record(1, 0.0, 0x4444),
        _query_record(2, 0.5, 0x4444),
        _response_record(3, 0.55, 0x4444, b'\x05\x06\x07\x08'),
        _response_record(4, 0.60, 0x4444, b'\x05\x06\x07\x08'),
    ]
    results = correlate(records)
    assert len(results) == 1
    result = results[0]
    assert result.status == MATCHED
    assert result.query_packets == (1, 2)
    assert result.response_packets == (3, 4)


def test_contradictory_answers_are_detected_with_evidence():
    records = [
        _query_record(1, 0.0, 0x5555),
        _response_record(2, 0.02, 0x5555, b'\x01\x02\x03\x04'),
        _response_record(3, 0.04, 0x5555, b'\x09\x09\x09\x09'),
    ]
    results = correlate(records)
    assert len(results) == 1
    result = results[0]
    assert result.status == CONTRADICTORY
    assert result.response_packets == (2, 3)
    evidence_packets = sorted(pkts for _, pkts in result.evidence)
    assert evidence_packets == [(2,), (3,)]


def test_nxdomain_contradicts_a_productive_answer():
    records = [
        _query_record(1, 0.0, 0x6666),
        _response_record(2, 0.02, 0x6666, None,
                         rcode=dnsmod.DNS_RCODE_NXDOMAIN),
        _response_record(3, 0.04, 0x6666, b'\x0a\x0b\x0c\x0d',
                         rcode=dnsmod.DNS_RCODE_NOERR),
    ]
    results = correlate(records)
    assert len(results) == 1
    assert results[0].status == CONTRADICTORY


def test_response_before_query_is_adopted():
    records = [
        _response_record(1, 0.0, 0x7777, b'\x01\x02\x03\x04'),
        _query_record(2, 0.03, 0x7777),
    ]
    results = correlate(records)
    assert len(results) == 1
    result = results[0]
    assert result.status == MATCHED
    assert result.query_packets == (2,)
    assert result.response_packets == (1,)


def test_orphan_response_without_query_is_insufficient():
    records = [_response_record(1, 0.0, 0x8888, b'\x01\x02\x03\x04')]
    results = correlate(records)
    assert len(results) == 1
    assert results[0].status == INSUFFICIENT
    assert results[0].response_packets == (1,)


def test_unanswered_query_is_insufficient():
    records = [_query_record(1, 0.0, 0x9999)]
    results = correlate(records)
    assert len(results) == 1
    assert results[0].status == INSUFFICIENT
    assert results[0].query_packets == (1,)


def test_out_of_window_response():
    correlator = DnsResponseCorrelator(window=1.0)
    correlator.feed(_query_record(1, 0.0, 0xaaaa))
    closed = correlator.feed(_response_record(2, 2.5, 0xaaaa, b'\x01\x02\x03\x04'))
    assert len(closed) == 1
    assert closed[0].status == OUT_OF_WINDOW
    assert closed[0].query_packets == (1,)
    assert correlator.flush()


def test_response_inside_window_boundary_matches():
    records = [
        _query_record(1, 0.0, 0xabab),
        _response_record(2, 1.0, 0xabab, b'\x01\x02\x03\x04'),
    ]
    results = correlate(records, window=1.0)
    assert results[0].status == MATCHED


def test_expire_closes_idle_entries():
    correlator = DnsResponseCorrelator(window=1.0)
    correlator.feed(_query_record(1, 0.0, 0xacac))
    expired = correlator.expire(now=5.0)
    assert len(expired) == 1
    assert expired[0].status == OUT_OF_WINDOW
    assert correlator.flush() == []


def test_same_txn_id_two_endpoint_pairs_are_separate_flows():
    txn_id = 0x1234
    records = [
        _query_record(1, 0.0, txn_id, server_ip=SERVER_IP),
        _query_record(2, 0.01, txn_id, server_ip=OTHER_SERVER_IP),
        _response_record(3, 0.02, txn_id, b'\x01\x02\x03\x04', server_ip=SERVER_IP),
        _response_record(4, 0.03, txn_id, b'\x09\x09\x09\x09', server_ip=OTHER_SERVER_IP),
    ]
    results = correlate(records)
    assert len(results) == 2
    assert all(r.status == MATCHED for r in results)
    assert {r.response_packets for r in results} == {(3,), (4,)}


def test_port_reuse_starts_a_new_generation():
    txn_id = 0x1357
    correlator = DnsResponseCorrelator()
    correlator.feed(_query_record(1, 0.0, txn_id))
    correlator.feed(_response_record(2, 0.02, txn_id, b'\x01\x02\x03\x04'))
    first = correlator.flush()[0]
    assert first.status == MATCHED

    correlator.feed(_query_record(3, 10.0, txn_id))
    correlator.feed(_response_record(4, 10.02, txn_id, b'\x09\x09\x09\x09'))
    second = correlator.flush()[0]
    assert second.status == MATCHED
    assert second.generation == first.generation + 1
    assert second.query_packets == (3,)


def test_max_pending_evicts_oldest_as_insufficient():
    correlator = DnsResponseCorrelator(max_pending=2)
    correlator.feed(_query_record(1, 0.0, 0x0001))
    correlator.feed(_query_record(2, 1.0, 0x0002))
    evicted = correlator.feed(_query_record(3, 2.0, 0x0003))
    assert len(evicted) == 1
    assert evicted[0].status == INSUFFICIENT
    assert evicted[0].txn_id == 0x0001
    rest = correlator.flush()
    assert {r.txn_id for r in rest} == {0x0002, 0x0003}


def test_reordering_input_keeps_verdict_and_source_packets_identical():
    txn_id = 0x2468
    ordered = [
        _query_record(1, 0.0, txn_id),
        _query_record(2, 0.3, txn_id),
        _response_record(3, 0.32, txn_id, b'\x01\x02\x03\x04'),
        _response_record(4, 0.35, txn_id, b'\x05\x05\x05\x05'),
    ]
    shuffled = [ordered[i] for i in (3, 1, 0, 2)]

    def signature(results):
        return [(r.status, r.txn_id, r.query_packets,
                 tuple(sorted((fp, tuple(pkts)) for fp, pkts in r.evidence)))
                for r in results]

    first = correlate(ordered)
    second = correlate(shuffled)
    assert signature(first) == signature(second)
    assert first[0].status == CONTRADICTORY
    assert sorted(pkts for _, pkts in first[0].evidence) == [(3,), (4,)]


def test_contradiction_survives_reordering_with_orphan_response():
    txn_id = 0x3579
    ordered = [
        _query_record(1, 1.0, txn_id),
        _response_record(2, 1.05, txn_id, b'\x01\x02\x03\x04'),
        _response_record(3, 1.10, txn_id, b'\x0a\x0b\x0c\x0d'),
    ]
    shuffled = [ordered[2], ordered[0], ordered[1]]
    first = correlate(ordered)
    second = correlate(shuffled)
    assert len(first) == len(second) == 1
    assert first[0].status == second[0].status == CONTRADICTORY
    assert first[0].evidence == second[0].evidence
    assert sorted(pkts for _, pkts in first[0].evidence) == [(2,), (3,)]


def _ethernet_udp_frame(src_ip, src_port, dst_ip, dst_port, payload):
    udp = UDP(sport=src_port, dport=dst_port, data=payload)
    ip_pkt = IP(src=src_ip, dst=dst_ip, p=17, data=udp)
    eth = Ethernet(data=ip_pkt)
    return bytes(eth)


def test_pcap_roundtrip_correlation():
    import io
    from . import pcap

    txn_id = 0x4680
    query = bytes(_dns_query(txn_id, [_question('www.example.com')]))
    good = bytes(_dns_response(txn_id, [_question('www.example.com')],
                               [_rr('www.example.com', rdata=b'\x01\x02\x03\x04')]))
    bad = bytes(_dns_response(txn_id, [_question('www.example.com')],
                              [_rr('www.example.com', rdata=b'\x09\x09\x09\x09')]))

    frames = [
        (0.0, _ethernet_udp_frame(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, query)),
        (0.02, _ethernet_udp_frame(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT, good)),
        (0.04, _ethernet_udp_frame(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT, bad)),
    ]
    buf = io.BytesIO()
    writer = pcap.Writer(buf)
    for timestamp, frame in frames:
        writer.writepkt(frame, timestamp)
    buf.seek(0)

    results = correlate_pcap(buf)
    assert len(results) == 1
    result = results[0]
    assert result.status == CONTRADICTORY
    assert result.response_packets == (2, 3)
    assert result.questions[0][0] == 'www.example.com'


def test_malformed_datagram_is_skipped():
    assert parse_dns_datagram(1, 0.0, CLIENT_IP, CLIENT_PORT,
                              SERVER_IP, SERVER_PORT, b'\x00' * 4) is None
    no_question = DNS(id=1, op=0)
    no_question.qr = 0
    no_question.qd = []
    no_question.an = []
    no_question.ns = []
    no_question.ar = []
    assert parse_dns_datagram(2, 0.1, CLIENT_IP, CLIENT_PORT,
                              SERVER_IP, SERVER_PORT, bytes(no_question)) is None


def test_invalid_constructor_arguments():
    try:
        DnsResponseCorrelator(window=-1)
    except ValueError:
        pass
    else:
        raise AssertionError('negative window must raise')
    try:
        DnsResponseCorrelator(max_pending=0)
    except ValueError:
        pass
    else:
        raise AssertionError('zero max_pending must raise')


def test_answer_set_order_does_not_create_conflict():
    txn_id = 0x5a5a
    first_answers = [
        _rr('example.com', rdata=b'\x01\x02\x03\x04'),
        _rr('example.com', rdata=b'\x05\x06\x07\x08'),
    ]
    # Same RRs, different order and different TTLs.
    second_answers = [
        _rr('example.com', rdata=b'\x05\x06\x07\x08', ttl=120),
        _rr('example.com', rdata=b'\x01\x02\x03\x04', ttl=90),
    ]
    records = [
        _record(1, 0.0, _dns_query(txn_id, [_question('example.com')]), True),
        _record(2, 0.02, _dns_response(txn_id, [_question('example.com')], first_answers), False),
        _record(3, 0.04, _dns_response(txn_id, [_question('example.com')], second_answers), False),
    ]
    results = correlate(records)
    assert len(results) == 1
    assert results[0].status == MATCHED
    assert len(results[0].answers) == 1


def test_compressed_cname_case_difference_is_not_a_conflict():
    # dpkt compresses the CNAME target when re-packing, so this also exercises
    # the compression-pointer path of the RR fingerprint.
    txn_id = 0x6b6b
    question_a = _question('WWW.Example.COM')
    question_b = _question('www.example.com')
    cname_a = DNS.RR(name='WWW.Example.COM', type=dnsmod.DNS_CNAME,
                     cls=dnsmod.DNS_IN, ttl=300, cname='Target.Example.COM')
    cname_b = DNS.RR(name='www.example.com', type=dnsmod.DNS_CNAME,
                     cls=dnsmod.DNS_IN, ttl=120, cname='target.example.com')
    records = [
        _record(1, 0.0, _dns_query(txn_id, [question_a]), True),
        _record(2, 0.02, _dns_response(txn_id, [question_a], [cname_a]), False),
        _record(3, 0.04, _dns_response(txn_id, [question_b], [cname_b]), False),
    ]
    results = correlate(records)
    assert len(results) == 1
    assert results[0].status == MATCHED


def test_multiple_questions_correlate_as_one_boundary_preserving_key():
    txn_id = 0x7c7c
    questions = [_question('a.example', dnsmod.DNS_A),
                 _question('b.example', dnsmod.DNS_AAAA)]
    answers = [_rr('a.example', rdata=b'\x01\x02\x03\x04')]
    records = [
        _record(1, 0.0, _dns_query(txn_id, questions), True),
        _record(2, 0.02, _dns_response(txn_id, questions, answers), False),
    ]
    results = correlate(records)
    assert len(results) == 1
    result = results[0]
    assert result.status == MATCHED
    assert result.questions == tuple(
        (_normalize_name(q.name), q.type, q.cls) for q in questions)


def test_orphan_contradiction_resolves_when_query_arrives_later():
    txn_id = 0x8d8d
    # Both conflicting answers are fed before the query, in reverse order.
    records = [
        _response_record(2, 1.10, txn_id, b'\x0a\x0b\x0c\x0d'),
        _response_record(1, 1.05, txn_id, b'\x01\x02\x03\x04'),
        _query_record(3, 1.20, txn_id),
    ]
    results = correlate(records)
    assert len(results) == 1
    result = results[0]
    assert result.status == CONTRADICTORY
    assert result.query_packets == (3,)
    assert result.response_packets == (1, 2)
    assert sorted(pkts for _, pkts in result.evidence) == [(1,), (2,)]

# -*- coding: utf-8 -*-
"""Offline TCP connection-attempt summary for alert triage.

This module turns a stream of captured IPv4/TCP packets into a list of
*connection attempts*, each labelled with one of three verdicts:

* :data:`TCP_SUCCESS` -- a handshake completed (normal connection);
* :data:`TCP_REJECTED` -- the attempt was explicitly refused, normally by a
  RST segment (typical of failed probes);
* :data:`TCP_UNKNOWN` -- not enough evidence in the capture to decide, for
  example when only one direction was recorded or the capture ends while the
  handshake is still in flight.

Only IP/TCP header metadata is read.  Application payloads are never inspected
and no packets are ever transmitted; the analyser is strictly offline.

The analyser is deliberately conservative so that a one-sided capture can
never be misreported as a scan: an unanswered SYN or a segment that belongs to
a handshake which started before the capture remains :data:`TCP_UNKNOWN`,
because silence on the wire is not proof of a rejection.

Design notes
------------

* A *canonical* four-tuple (the two (IP, port) endpoints sorted so that the
  direction does not matter) identifies one conversation.  When the same
  four-tuple is reused after the previous conversation has reached a terminal
  state, a fresh *generation* is opened, which keeps rapid four-tuple reuse
  from merging distinct attempts.
* Retransmissions of the same opening SYN (identical sequence number) extend
  the existing attempt instead of starting a new one, so one logical attempt
  is counted no matter how many times its SYN is repeated.
* The window is advanced by packet timestamps.  Idle attempts are finalized
  once ``idle_timeout`` passes without activity.  A late packet that arrives
  within ``late_tolerance`` of the current watermark can *revive* a finalized
  attempt and correct its earlier verdict; older late packets are ignored.
* Every verdict carries the 1-based packet numbers of the segments that
  support it, so an alert can be traced back to the raw capture.
"""
from __future__ import print_function
from __future__ import absolute_import

from . import dpkt
from . import ethernet
from . import ip as ipmod
from . import pcap as pcapmod
from . import tcp as tcpmod
from .utils import inet_to_str

# Verdict labels.
TCP_SUCCESS = 'success'      # a completed handshake was observed
TCP_REJECTED = 'rejected'    # an explicit RST refused the attempt
TCP_UNKNOWN = 'unknown'      # the capture does not contain enough evidence

_VERDICTS = (TCP_SUCCESS, TCP_REJECTED, TCP_UNKNOWN)

# Human-readable explanations of why an attempt could not be decided.
REASON_MID_CAPTURE = 'no SYN observed; segment belongs to an existing or unknown connection'
REASON_SYN_ONLY = 'SYN sent but no response observed in capture window'
REASON_INCOMPLETE = 'handshake started but did not complete within capture window'
REASON_REJECTED = 'RST received before the handshake completed'
REASON_ESTABLISHED = 'three-way handshake completed'
REASON_SIMULTANEOUS = 'simultaneous open completed in both directions'

_SEQ_SPACE = 1 << 32


class Endpoint(object):
    """One side of a TCP conversation, identified by IP address and port.

    Attributes:
        ip:    raw 4-byte IPv4 address.
        port:  TCP port number.
    """

    __slots__ = ('ip', 'port')

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def key(self):
        """Return the hashable identity of the endpoint."""
        return self.ip, self.port

    def copy(self):
        return Endpoint(self.ip, self.port)

    def __eq__(self, other):
        return isinstance(other, Endpoint) and self.key() == other.key()

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.key())

    def __lt__(self, other):
        return self.key() < other.key()

    def __repr__(self):
        return '%s:%d' % (inet_to_str(self.ip), self.port)


class TCPAttempt(object):
    """A single TCP connection attempt and the evidence gathered for it.

    Attributes:
        initiator:  :class:`Endpoint` that sent the first observed SYN, or
                    ``None`` when no SYN was ever seen.
        responder:  :class:`Endpoint` on the other side, or ``None``.
        generation: zero-based reuse counter for the canonical four-tuple.
        verdict:    one of :data:`TCP_SUCCESS`, :data:`TCP_REJECTED` or
                    :data:`TCP_UNKNOWN`.
        reason:     short string explaining the verdict.
        established: ``True`` once a full handshake was observed.
        simultaneous: ``True`` for a simultaneous-open handshake.
        first_packet: 1-based number of the first packet of the attempt.
        last_packet:   1-based number of the most recent packet.
        evidence:   packet numbers supporting the current verdict.
        syn_retransmits: packet numbers of retransmitted opening SYNs.
        packets:    all packet numbers attributed to the attempt.
        first_ts / last_ts: timestamps of the first and last packets.
        finalized:  whether the window has already closed on the attempt.
    """

    def __init__(self, initiator=None, responder=None, generation=0):
        self.initiator = initiator
        self.responder = responder
        self.generation = generation
        self.verdict = TCP_UNKNOWN
        self.reason = None
        self.established = False
        self.simultaneous = False
        self.first_packet = None
        self.last_packet = None
        self.evidence = []
        self.syn_retransmits = []
        self.packets = []
        self.first_ts = None
        self.last_ts = None
        self.finalized = False

        # Opening sequence numbers per direction (relative to initiator).
        self._init_syn_seq = None
        self._resp_syn_seq = None
        # Directional handshake bookkeeping.
        self._init_syn_pkt = None
        self._resp_synack_pkt = None
        self._init_ack_pkt = None
        self._resp_syn_pkt = None      # responder's own SYN (simultaneous open)
        self._resp_ack_pkt = None      # ACK of the responder's SYN
        self._rst_pkts = []

    @property
    def key(self):
        """Canonical, direction-independent four-tuple of the attempt."""
        if self.initiator is None:
            return None
        a = self.initiator.key()
        b = self.responder.key() if self.responder is not None else None
        return tuple(sorted((a, b)))

    def to_dict(self):
        """Return a plain-dict view suitable for serialization or alerting."""
        return {
            'initiator': None if self.initiator is None else repr(self.initiator),
            'responder': None if self.responder is None else repr(self.responder),
            'generation': self.generation,
            'verdict': self.verdict,
            'reason': self.reason,
            'established': self.established,
            'simultaneous': self.simultaneous,
            'first_packet': self.first_packet,
            'last_packet': self.last_packet,
            'evidence': list(self.evidence),
            'syn_retransmits': list(self.syn_retransmits),
            'packets': list(self.packets),
            'finalized': self.finalized,
        }

    def __repr__(self):
        return 'TCPAttempt(%s -> %s, gen=%d, verdict=%s, evidence=%s)' % (
            self.initiator, self.responder, self.generation, self.verdict, self.evidence)


class TCPAttemptSummary(object):
    """Stateful summarizer of TCP connection attempts in an offline capture.

    Feed every captured packet, in capture order, to :meth:`process`.  At any
    point :meth:`attempts` lists the attempts known so far and :meth:`summary`
    returns aggregate counters suitable for alerting.  Call :meth:`flush` at
    end of stream to close attempts that never saw further traffic.

    Args:
        idle_timeout:    seconds of inactivity after which an open attempt is
                         finalized.
        late_tolerance:  maximum number of seconds a late packet may trail the
                         watermark and still correct a finalized verdict.
    """

    def __init__(self, idle_timeout=120.0, late_tolerance=30.0):
        if idle_timeout < 0 or late_tolerance < 0:
            raise ValueError('timeouts must be non-negative')
        self.idle_timeout = float(idle_timeout)
        self.late_tolerance = float(late_tolerance)

        self._active = {}      # canonical key -> current TCPAttempt
        self._finalized = {}   # (canonical key, generation) -> TCPAttempt
        self._generations = {}  # canonical key -> next generation number
        self._watermark = None

        self.packet_count = 0      # packets inspected (all protocols)
        self.tcp_packet_count = 0  # packets carrying a non-fragmented TCP header
        self.skipped_packets = 0   # non-IP/TCP or fragmented packets
        self.malformed_packets = 0
        self.stale_packets = 0     # late packets beyond late_tolerance
        self._ordered = []         # attempts in first-seen order

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def process(self, packet, ts=None, packet_num=None):
        """Ingest one captured packet and update attempt state.

        Args:
            packet: a raw IPv4 datagram (``bytes``), a :class:`dpkt.ip.IP`,
                    or a raw Ethernet frame / :class:`dpkt.ethernet.Ethernet`
                    whose payload is IPv4.
            ts:     packet timestamp in seconds.  When omitted the packet
                    number is used as a monotonic clock.
            packet_num: explicit 1-based packet number; by default packets are
                    numbered in call order.

        Returns:
            The :class:`TCPAttempt` updated by the packet, or ``None`` when the
            packet was not usable TCP metadata.
        """
        self.packet_count += 1
        num = self.packet_count if packet_num is None else packet_num
        when = float(num) if ts is None else float(ts)

        parsed = self._parse_tcp(packet)
        if parsed is None:
            return None
        src_ip, dst_ip, tcp = parsed
        self.tcp_packet_count += 1

        # The watermark is the most recent event time.  Idle attempts are
        # finalized first; the locate step then decides whether a late packet
        # still falls within late_tolerance and is allowed to revive one.
        if self._watermark is None:
            self._watermark = when
        elif when > self._watermark:
            self._watermark = when
        self._expire_idle(when)

        src = Endpoint(src_ip, tcp.sport)
        dst = Endpoint(dst_ip, tcp.dport)
        canonical = tuple(sorted((src.key(), dst.key())))

        attempt = self._locate(canonical, src, dst, tcp, when, num)
        if attempt is None:
            self.stale_packets += 1
            return None

        self._update(attempt, src, dst, tcp, when, num)
        return attempt

    def flush(self):
        """Finalize every still-open attempt using the current watermark."""
        if self._watermark is None:
            return
        for attempt in list(self._active.values()):
            self._finalize(attempt)

    def attempts(self, include_finalized=True):
        """Return attempts in first-seen order.

        Args:
            include_finalized: when False, only currently-open attempts are
                    returned.
        """
        if include_finalized:
            return list(self._ordered)
        return [a for a in self._ordered if not a.finalized]

    def summary(self):
        """Aggregate the current state into alerting counters and targets."""
        counts = dict((v, 0) for v in _VERDICTS)
        rejected_targets = {}
        for attempt in self._ordered:
            counts[attempt.verdict] += 1
            if attempt.verdict == TCP_REJECTED and attempt.responder is not None:
                target = repr(attempt.responder)
                rejected_targets[target] = rejected_targets.get(target, 0) + 1
        return {
            'total_attempts': len(self._ordered),
            'success': counts[TCP_SUCCESS],
            'rejected': counts[TCP_REJECTED],
            'unknown': counts[TCP_UNKNOWN],
            'rejected_targets': rejected_targets,
            'tcp_packets': self.tcp_packet_count,
            'stale_packets': self.stale_packets,
            'skipped_packets': self.skipped_packets,
            'malformed_packets': self.malformed_packets,
        }

    # ------------------------------------------------------------------
    # Packet parsing -- headers only, payload is never touched.
    # ------------------------------------------------------------------
    def _parse_tcp(self, packet):
        if isinstance(packet, (bytes, bytearray)):
            # Heuristic: an Ethernet frame starts with a 14-byte header, an IPv4
            # datagram starts with the nibble 0x4.
            if len(packet) >= 1 and (packet[0] >> 4) == 4:
                packet = ipmod.IP(bytes(packet))
            else:
                try:
                    frame = ethernet.Ethernet(bytes(packet))
                except dpkt.UnpackError:
                    self.malformed_packets += 1
                    return None
                packet = frame.data
        elif isinstance(packet, ethernet.Ethernet):
            packet = packet.data

        if not isinstance(packet, ipmod.IP):
            self.skipped_packets += 1
            return None
        if packet.p != ipmod.IP_PROTO_TCP:
            self.skipped_packets += 1
            return None
        # Non-first fragments do not carry a full TCP header.
        if packet.mf or packet.offset:
            self.skipped_packets += 1
            return None
        if not isinstance(packet.data, tcpmod.TCP):
            self.malformed_packets += 1
            return None
        if packet.data.off < 5:
            self.malformed_packets += 1
            return None
        return packet.src, packet.dst, packet.data

    # ------------------------------------------------------------------
    # Attempt lifecycle and windowing.
    # ------------------------------------------------------------------
    def _expire_idle(self, now):
        if self.idle_timeout <= 0:
            return
        for attempt in list(self._active.values()):
            if now - attempt.last_ts >= self.idle_timeout:
                self._finalize(attempt)

    def _finalize(self, attempt):
        attempt.finalized = True
        self._reevaluate(attempt)
        if attempt.key in self._active and self._active[attempt.key] is attempt:
            del self._active[attempt.key]
        self._finalized[(attempt.key, attempt.generation)] = attempt

    def _revive(self, attempt):
        attempt.finalized = False
        self._finalized.pop((attempt.key, attempt.generation), None)
        self._active[attempt.key] = attempt

    def _next_generation(self, canonical):
        gen = self._generations.get(canonical, 0)
        self._generations[canonical] = gen + 1
        return gen

    def _locate(self, canonical, src, dst, tcp, when, num):
        """Find the attempt a packet belongs to, handling reuse and late data."""
        flags = tcp.flags
        is_syn = bool(flags & tcpmod.TH_SYN)

        active = self._active.get(canonical)
        if active is not None:
            return active

        last_gen = self._generations.get(canonical, 0) - 1
        previous = self._finalized.get((canonical, last_gen))
        in_window = when + self.late_tolerance >= self._watermark

        if previous is not None:
            if in_window:
                # The conversation is closed but still inside the correction
                # window.  A late segment (including a retransmitted SYN-ACK)
                # revives it; a fresh SYN from the original initiator reuses
                # the four-tuple and starts a new generation.
                if is_syn and not (flags & tcpmod.TH_ACK) and \
                        previous.initiator is not None and src == previous.initiator:
                    pass  # fall through to four-tuple reuse below
                else:
                    self._revive(previous)
                    return previous
            else:
                # Closed and beyond late_tolerance: the packet cannot change
                # any prior conclusion, so ignore it.
                return None

        if is_syn:
            # A brand-new SYN (or a reuse SYN) opens a fresh generation.
            gen = self._next_generation(canonical)
            attempt = TCPAttempt(generation=gen)
            self._active[canonical] = attempt
            self._ordered.append(attempt)
            return attempt

        # A non-SYN segment with no conversation at all.  Record it as an
        # attempt whose opening happened before (or outside) the capture.
        attempt = TCPAttempt(generation=self._next_generation(canonical))
        attempt.first_packet = num
        attempt.first_ts = when
        attempt.initiator = src.copy()
        attempt.responder = dst.copy()
        attempt.verdict = TCP_UNKNOWN
        attempt.reason = REASON_MID_CAPTURE
        attempt.evidence = [num]
        self._active[canonical] = attempt
        self._ordered.append(attempt)
        return attempt

    # ------------------------------------------------------------------
    # State machine.
    # ------------------------------------------------------------------
    def _note_packet(self, attempt, when, num):
        attempt.packets.append(num)
        attempt.last_packet = num
        attempt.last_ts = when
        if attempt.first_packet is None:
            attempt.first_packet = num
            attempt.first_ts = when

    def _update(self, attempt, src, dst, tcp, when, num):
        flags = tcp.flags
        is_syn = bool(flags & tcpmod.TH_SYN)
        is_ack = bool(flags & tcpmod.TH_ACK)
        is_rst = bool(flags & tcpmod.TH_RST)

        self._note_packet(attempt, when, num)

        if is_rst:
            attempt._rst_pkts.append(num)
            if not attempt.established:
                # An explicit refusal while the handshake is still open.
                attempt.verdict = TCP_REJECTED
                attempt.reason = REASON_REJECTED
                attempt.evidence = self._reject_evidence(attempt, num)
            else:
                # RST after a completed handshake does not undo the success.
                attempt.evidence = self._success_evidence(attempt)
            return

        if is_syn:
            self._handle_syn(attempt, src, dst, tcp, num, is_ack)
            self._reevaluate(attempt)
            return

        if is_ack:
            self._handle_ack(attempt, src, dst, tcp, num)
            self._reevaluate(attempt)
            return

        # Pure data/control segments (FIN, PSH, ...) refresh liveness only.
        self._reevaluate(attempt)

    def _handle_syn(self, attempt, src, dst, tcp, num, is_ack):
        if attempt.initiator is None:
            # First SYN of the conversation.
            attempt.initiator = src.copy()
            attempt.responder = dst.copy()
            attempt._init_syn_seq = tcp.seq
            attempt._init_syn_pkt = num
            return

        from_initiator = (src == attempt.initiator)

        if from_initiator:
            if tcp.seq == attempt._init_syn_seq:
                # Retransmission of the same opening SYN: one attempt only.
                if num not in attempt.syn_retransmits and num != attempt._init_syn_pkt:
                    attempt.syn_retransmits.append(num)
            else:
                # A different ISN on an open four-tuple reuses it for a fresh
                # connection before the old one closed: reset all handshake
                # evidence so stale segments cannot decide the new attempt.
                attempt._init_syn_seq = tcp.seq
                attempt._init_syn_pkt = num
                attempt._resp_syn_seq = None
                attempt._resp_synack_pkt = None
                attempt._init_ack_pkt = None
                attempt._resp_syn_pkt = None
                attempt._resp_ack_pkt = None
                attempt._rst_pkts = []
                attempt.established = False
                attempt.simultaneous = False
                attempt.evidence = [num]
            return

        # Segment from the responder side.
        if is_ack:
            # SYN-ACK (retransmissions share the responder ISN).
            if attempt._resp_syn_seq is None:
                attempt._resp_syn_seq = tcp.seq
                attempt._resp_synack_pkt = num
            elif tcp.seq == attempt._resp_syn_seq and num != attempt._resp_synack_pkt:
                attempt.syn_retransmits.append(num)
        else:
            # A bare SYN from the responder while the initiator's SYN is open:
            # this is a simultaneous open.
            attempt.simultaneous = True
            attempt._resp_syn_seq = tcp.seq
            attempt._resp_syn_pkt = num

    def _handle_ack(self, attempt, src, dst, tcp, num):
        if attempt.initiator is None:
            # ACK with no SYN anywhere: mid-capture join, stays unknown.
            attempt.initiator = src.copy()
            attempt.responder = dst.copy()
            attempt.verdict = TCP_UNKNOWN
            attempt.reason = REASON_MID_CAPTURE
            attempt.evidence = [attempt.first_packet]
            return

        if src == attempt.initiator:
            if attempt.simultaneous:
                # In a simultaneous open the initiator ACKs the responder's SYN.
                if attempt._resp_syn_seq is not None and \
                        tcp.ack == (attempt._resp_syn_seq + 1) % _SEQ_SPACE:
                    attempt._init_ack_pkt = num
            elif attempt._resp_synack_pkt is not None:
                # Final ACK of a normal three-way handshake, validated against
                # the responder's ISN.
                if tcp.ack == (attempt._resp_syn_seq + 1) % _SEQ_SPACE:
                    attempt._init_ack_pkt = num
        else:
            # Responder side.  In a simultaneous open it ACKs the initiator's
            # bare SYN; otherwise its ACKs merely confirm an established flow.
            if attempt.simultaneous and attempt._init_syn_seq is not None:
                if tcp.ack == (attempt._init_syn_seq + 1) % _SEQ_SPACE:
                    attempt._resp_ack_pkt = num
            elif attempt._resp_synack_pkt is not None:
                attempt._resp_ack_pkt = num

    def _success_evidence(self, attempt):
        if attempt.simultaneous:
            pkts = [attempt._init_syn_pkt, attempt._resp_syn_pkt,
                    attempt._init_ack_pkt, attempt._resp_ack_pkt]
        else:
            pkts = [attempt._init_syn_pkt, attempt._resp_synack_pkt,
                    attempt._init_ack_pkt]
        return [p for p in pkts if p is not None]

    def _reject_evidence(self, attempt, rst_pkt):
        pkts = [attempt._init_syn_pkt, attempt._resp_synack_pkt, rst_pkt]
        return [p for p in pkts if p is not None]

    def _reevaluate(self, attempt):
        """Recompute the verdict from the raw directional state."""
        if attempt._rst_pkts and not attempt.established:
            attempt.verdict = TCP_REJECTED
            attempt.reason = REASON_REJECTED
            attempt.evidence = self._reject_evidence(attempt, attempt._rst_pkts[-1])
            return

        if attempt.simultaneous:
            complete = (attempt._init_syn_pkt is not None and
                        attempt._resp_syn_pkt is not None and
                        attempt._init_ack_pkt is not None and
                        attempt._resp_ack_pkt is not None)
            if complete:
                attempt.established = True
                attempt.verdict = TCP_SUCCESS
                attempt.reason = REASON_SIMULTANEOUS
                attempt.evidence = self._success_evidence(attempt)
                return

        normal_complete = (attempt._init_syn_pkt is not None and
                           attempt._resp_synack_pkt is not None and
                           attempt._init_ack_pkt is not None)
        if normal_complete:
            attempt.established = True
            attempt.verdict = TCP_SUCCESS
            attempt.reason = REASON_ESTABLISHED
            attempt.evidence = self._success_evidence(attempt)
            return

        # Not established: distinguish "never started here" from "in flight".
        if attempt._init_syn_pkt is None:
            attempt.verdict = TCP_UNKNOWN
            attempt.reason = REASON_MID_CAPTURE
        elif attempt._resp_synack_pkt is None and not attempt.simultaneous:
            attempt.verdict = TCP_UNKNOWN
            attempt.reason = REASON_SYN_ONLY
        else:
            attempt.verdict = TCP_UNKNOWN
            attempt.reason = REASON_INCOMPLETE
        if not attempt.evidence:
            attempt.evidence = [p for p in (attempt.first_packet,) if p is not None]


def summarize_pcap(fileobj, idle_timeout=120.0, late_tolerance=30.0):
    """Convenience helper: summarize TCP attempts from a pcap file or path.

    Only IP/TCP header metadata is read.  Link layers other than Ethernet and
    non-TCP packets are skipped.

    Args:
        fileobj: an open binary file or a filesystem path to a classic pcap.
        idle_timeout, late_tolerance: see :class:`TCPAttemptSummary`.

    Returns:
        The populated :class:`TCPAttemptSummary`.
    """
    summarizer = TCPAttemptSummary(idle_timeout=idle_timeout,
                                   late_tolerance=late_tolerance)
    opened = False
    if isinstance(fileobj, (bytes, str)):
        fileobj = open(fileobj, 'rb')
        opened = True
    try:
        reader = pcapmod.Reader(fileobj)
        for ts, buf in reader:
            summarizer.process(buf, ts=ts)
        summarizer.flush()
    finally:
        if opened:
            fileobj.close()
    return summarizer


# ---------------------------------------------------------------------------
# Tests -- synthetic, fully bidirectional packet streams (no payload, no I/O).
# ---------------------------------------------------------------------------
CLIENT_IP = b'\x0a\x00\x00\x01'
SERVER_IP = b'\x0a\x00\x00\x02'
CLIENT_PORT = 40000
SERVER_PORT = 80


def _tcp_packet(src_ip, src_port, dst_ip, dst_port, seq, ack, flags):
    """Build an Ethernet/IP/TCP frame carrying no application payload."""
    tcp_seg = tcpmod.TCP(sport=src_port, dport=dst_port, seq=seq, ack=ack,
                         off=5, flags=flags, win=65535, sum=0)
    ip_pkt = ipmod.IP(src=src_ip, dst=dst_ip, p=ipmod.IP_PROTO_TCP,
                      id=0, ttl=64, data=tcp_seg)
    # Encode the sender in the source MAC so tests can strip one direction.
    src_mac = b'\x02' + b'\x00' * 5 if src_ip == CLIENT_IP else b'\x03' + b'\x00' * 5
    frame = ethernet.Ethernet(src=src_mac, dst=b'\x01' * 6,
                              type=ethernet.ETH_TYPE_IP, data=ip_pkt)
    return bytes(frame)


def _handshake(ts0=1.0, client_port=CLIENT_PORT):
    """A normal three-way handshake plus one data ACK from the responder."""
    isn_c, isn_s = 1000, 5000
    return [
        (ts0, _tcp_packet(CLIENT_IP, client_port, SERVER_IP, SERVER_PORT,
                          isn_c, 0, tcpmod.TH_SYN)),
        (ts0 + 0.01, _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, client_port,
                                 isn_s, isn_c + 1, tcpmod.TH_SYN | tcpmod.TH_ACK)),
        (ts0 + 0.02, _tcp_packet(CLIENT_IP, client_port, SERVER_IP, SERVER_PORT,
                                 isn_c + 1, isn_s + 1, tcpmod.TH_ACK)),
    ]


def _rejected(ts0=10.0, client_port=CLIENT_PORT + 1):
    """A SYN probe that the server refuses with a RST/ACK."""
    isn_c = 2000
    return [
        (ts0, _tcp_packet(CLIENT_IP, client_port, SERVER_IP, SERVER_PORT,
                          isn_c, 0, tcpmod.TH_SYN)),
        (ts0 + 0.01, _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, client_port,
                                 0, isn_c + 1, tcpmod.TH_RST | tcpmod.TH_ACK)),
    ]


def _syn_only(ts0=20.0, client_port=CLIENT_PORT + 2):
    """A SYN with no response at all in the capture."""
    return [
        (ts0, _tcp_packet(CLIENT_IP, client_port, SERVER_IP, SERVER_PORT,
                          3000, 0, tcpmod.TH_SYN)),
    ]


def _run(packets, **kwargs):
    summarizer = TCPAttemptSummary(**kwargs)
    for ts, buf in packets:
        summarizer.process(buf, ts=ts)
    summarizer.flush()
    return summarizer


def _find(summarizer, client_port):
    for attempt in summarizer.attempts():
        if attempt.initiator is not None and \
                attempt.initiator.ip == CLIENT_IP and \
                attempt.initiator.port == client_port:
            return attempt
    raise AssertionError('attempt for client port %d not found' % client_port)


def test_three_verdicts_and_evidence():
    # One synthetic bidirectional capture showing all three outcomes.
    packets = _handshake(client_port=CLIENT_PORT) + \
        _rejected(client_port=CLIENT_PORT + 1) + \
        _syn_only(client_port=CLIENT_PORT + 2)
    summarizer = _run(packets)

    summary = summarizer.summary()
    assert summary['total_attempts'] == 3
    assert summary['success'] == 1
    assert summary['rejected'] == 1
    assert summary['unknown'] == 1
    assert summary['rejected_targets'] == {'10.0.0.2:80': 1}

    ok = _find(summarizer, CLIENT_PORT)
    assert ok.verdict == TCP_SUCCESS
    assert ok.established is True
    assert ok.evidence == [1, 2, 3]  # SYN, SYN-ACK, ACK

    refused = _find(summarizer, CLIENT_PORT + 1)
    assert refused.verdict == TCP_REJECTED
    assert refused.reason == REASON_REJECTED
    assert refused.evidence == [4, 5]  # SYN then RST

    probe = _find(summarizer, CLIENT_PORT + 2)
    assert probe.verdict == TCP_UNKNOWN
    assert probe.reason == REASON_SYN_ONLY
    assert probe.evidence == [6]


def test_removing_return_path_degrades_to_unknown():
    # The same successful handshake, but with every responder (server) packet
    # removed, as happens with a one-directional capture point.
    full = _handshake(client_port=CLIENT_PORT)
    server_mac = b'\x03' + b'\x00' * 5
    one_sided = [(ts, buf) for (ts, buf) in full if buf[6:12] != server_mac]
    # Only the client->server SYN and final ACK survive.
    assert len(one_sided) == 2

    summarizer = _run(one_sided)
    attempts = summarizer.attempts()
    # The late client ACK cannot match a SYN-ACK, so it joins the same
    # mid-capture conversation rather than proving a failure.
    assert len(attempts) == 1
    attempt = attempts[0]
    assert attempt.verdict == TCP_UNKNOWN
    assert attempt.verdict != TCP_REJECTED  # never mistaken for a scan failure
    assert 1 in attempt.evidence


def test_syn_retransmit_counts_once():
    isn_c = 7000
    packets = [
        (1.0, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn_c, 0, tcpmod.TH_SYN)),
        (2.0, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn_c, 0, tcpmod.TH_SYN)),  # identical retransmit
        (3.0, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn_c, 0, tcpmod.TH_SYN)),  # again
    ]
    summarizer = _run(packets)
    assert summarizer.summary()['total_attempts'] == 1
    attempt = summarizer.attempts()[0]
    assert attempt.syn_retransmits == [2, 3]
    assert attempt.verdict == TCP_UNKNOWN
    assert attempt.packets == [1, 2, 3]


def test_retransmitted_syn_then_success():
    isn_c, isn_s = 8000, 9000
    packets = [
        (1.0, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn_c, 0, tcpmod.TH_SYN)),
        (2.0, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn_c, 0, tcpmod.TH_SYN)),
        (3.0, _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                          isn_s, isn_c + 1, tcpmod.TH_SYN | tcpmod.TH_ACK)),
        (4.0, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn_c + 1, isn_s + 1, tcpmod.TH_ACK)),
    ]
    summarizer = _run(packets)
    attempt = summarizer.attempts()[0]
    assert attempt.verdict == TCP_SUCCESS
    assert attempt.syn_retransmits == [2]
    assert attempt.evidence == [1, 3, 4]


def test_simultaneous_open():
    isn_a, isn_b = 111, 222
    packets = [
        (1.0, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn_a, 0, tcpmod.TH_SYN)),
        (1.1, _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                          isn_b, 0, tcpmod.TH_SYN)),
        (1.2, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn_a + 1, isn_b + 1, tcpmod.TH_ACK)),
        (1.3, _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                          isn_b + 1, isn_a + 1, tcpmod.TH_ACK)),
    ]
    summarizer = _run(packets)
    attempt = summarizer.attempts()[0]
    assert attempt.simultaneous is True
    assert attempt.verdict == TCP_SUCCESS
    assert attempt.evidence == [1, 2, 3, 4]


def test_ack_without_syn_is_unknown_not_rejected():
    packets = [
        (1.0, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          500, 600, tcpmod.TH_ACK)),
        (2.0, _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                          600, 501, tcpmod.TH_ACK)),
    ]
    summarizer = _run(packets)
    attempt = summarizer.attempts()[0]
    assert attempt.verdict == TCP_UNKNOWN
    assert attempt.reason == REASON_MID_CAPTURE
    assert attempt.evidence == [1]


def test_fast_four_tuple_reuse_uses_generations():
    # First conversation completes and closes; the same four-tuple is reused.
    first = _handshake(ts0=1.0, client_port=CLIENT_PORT)
    isn_c2 = 4444
    reused = [
        (100.0, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                            isn_c2, 0, tcpmod.TH_SYN)),
        (100.01, _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                             0, isn_c2 + 1, tcpmod.TH_RST | tcpmod.TH_ACK)),
    ]
    summarizer = _run(first + reused, idle_timeout=10.0)
    attempts = summarizer.attempts()
    assert len(attempts) == 2
    assert attempts[0].generation == 0 and attempts[0].verdict == TCP_SUCCESS
    assert attempts[1].generation == 1 and attempts[1].verdict == TCP_REJECTED
    # Distinct evidence despite identical four-tuples.
    assert attempts[0].key == attempts[1].key
    assert attempts[0].evidence != attempts[1].evidence


def test_late_packet_revises_verdict_within_tolerance():
    isn_c, isn_s = 6000, 7000
    summarizer = TCPAttemptSummary(idle_timeout=5.0, late_tolerance=2.0)
    # SYN at t=1, then unrelated traffic pushes the watermark forward so the
    # attempt expires and is finalized as unknown at t=10.
    summarizer.process(
        _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                    isn_c, 0, tcpmod.TH_SYN), ts=1.0)
    other = _tcp_packet(b'\x0a\x00\x00\x09', 1234, SERVER_IP, 9999,
                        1, 0, tcpmod.TH_ACK)
    summarizer.process(other, ts=10.0)
    attempt = summarizer.attempts()[0]
    assert attempt.finalized is True
    assert attempt.verdict == TCP_UNKNOWN

    # A late SYN-ACK at t=11 is within late_tolerance of the watermark (10)...
    # it trails by 1s, so it must revive and eventually complete the handshake.
    summarizer.process(
        _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                    isn_s, isn_c + 1, tcpmod.TH_SYN | tcpmod.TH_ACK), ts=11.0)
    summarizer.process(
        _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                    isn_c + 1, isn_s + 1, tcpmod.TH_ACK), ts=11.1)
    summarizer.flush()
    assert attempt.verdict == TCP_SUCCESS
    assert attempt.evidence == [1, 3, 4]


def test_too_late_packet_is_ignored():
    isn_c = 8000
    summarizer = TCPAttemptSummary(idle_timeout=1.0, late_tolerance=1.0)
    summarizer.process(
        _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                    isn_c, 0, tcpmod.TH_SYN), ts=1.0)
    summarizer.process(
        _tcp_packet(b'\x0a\x00\x00\x09', 1234, SERVER_IP, 9999,
                    1, 0, tcpmod.TH_ACK), ts=50.0)
    # RST arrives 49s behind the watermark: beyond tolerance, must be ignored.
    result = summarizer.process(
        _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                    0, isn_c + 1, tcpmod.TH_RST | tcpmod.TH_ACK), ts=1.0 + 0.5)
    assert result is None
    summarizer.flush()
    assert summarizer.stale_packets >= 1
    assert summarizer.attempts()[0].verdict == TCP_UNKNOWN


def test_non_tcp_and_fragments_are_skipped():
    from . import udp
    summarizer = TCPAttemptSummary()
    udp_frame = ethernet.Ethernet(
        src=b'\x00' * 6, dst=b'\x01' * 6, type=ethernet.ETH_TYPE_IP,
        data=ipmod.IP(src=CLIENT_IP, dst=SERVER_IP, p=ipmod.IP_PROTO_UDP,
                      data=udp.UDP(sport=1, dport=2)))
    assert summarizer.process(bytes(udp_frame), ts=1.0) is None

    frag = ipmod.IP(src=CLIENT_IP, dst=SERVER_IP, p=ipmod.IP_PROTO_TCP, mf=1,
                    data=tcpmod.TCP(sport=1, dport=2, flags=tcpmod.TH_SYN))
    assert summarizer.process(frag, ts=2.0) is None
    assert summarizer.skipped_packets == 2
    assert summarizer.summary()['total_attempts'] == 0


def test_to_dict_and_endpoint_ordering():
    summarizer = _run(_handshake())
    attempt = summarizer.attempts()[0]
    as_dict = attempt.to_dict()
    assert as_dict['verdict'] == TCP_SUCCESS
    assert as_dict['evidence'] == [1, 2, 3]
    assert as_dict['initiator'] == '10.0.0.1:40000'
    assert as_dict['responder'] == '10.0.0.2:80'
    # Canonical key is independent of packet direction.
    assert Endpoint(CLIENT_IP, 1) < Endpoint(SERVER_IP, 1)
    assert attempt.key == tuple(sorted(
        ((CLIENT_IP, CLIENT_PORT), (SERVER_IP, SERVER_PORT))))


def test_invalid_timeout_rejected():
    import pytest
    with pytest.raises(ValueError):
        TCPAttemptSummary(idle_timeout=-1)
    with pytest.raises(ValueError):
        TCPAttemptSummary(late_tolerance=-5)


def test_rst_after_establishment_keeps_success():
    isn_c, isn_s = 9000, 9500
    packets = [
        (1.0, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn_c, 0, tcpmod.TH_SYN)),
        (1.1, _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                          isn_s, isn_c + 1, tcpmod.TH_SYN | tcpmod.TH_ACK)),
        (1.2, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn_c + 1, isn_s + 1, tcpmod.TH_ACK)),
        (50.0, _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                           isn_s + 1, isn_c + 1, tcpmod.TH_RST)),
    ]
    summarizer = _run(packets, idle_timeout=120.0)
    attempt = summarizer.attempts()[0]
    assert attempt.verdict == TCP_SUCCESS
    assert attempt.established is True
    assert 4 in attempt.packets


def test_wrong_final_ack_does_not_complete():
    isn_c, isn_s = 3030, 4040
    packets = [
        (1.0, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn_c, 0, tcpmod.TH_SYN)),
        (1.1, _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                          isn_s, isn_c + 1, tcpmod.TH_SYN | tcpmod.TH_ACK)),
        # ACK number does not match responder ISN+1.
        (1.2, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn_c + 1, 7, tcpmod.TH_ACK)),
    ]
    summarizer = _run(packets)
    attempt = summarizer.attempts()[0]
    assert attempt.verdict == TCP_UNKNOWN
    assert attempt.reason == REASON_INCOMPLETE


def test_raw_ip_and_ip_object_inputs():
    isn_c, isn_s = 5151, 6262
    tcp_seg = tcpmod.TCP(sport=CLIENT_PORT, dport=SERVER_PORT, seq=isn_c,
                         ack=0, off=5, flags=tcpmod.TH_SYN)
    ip_pkt = ipmod.IP(src=CLIENT_IP, dst=SERVER_IP, p=ipmod.IP_PROTO_TCP,
                      data=tcp_seg)
    summarizer = TCPAttemptSummary()
    assert summarizer.process(ip_pkt, ts=1.0) is not None
    assert summarizer.process(bytes(ip_pkt), ts=2.0) is not None  # retransmit
    summarizer.flush()
    attempt = summarizer.attempts()[0]
    assert attempt.syn_retransmits == [2]


def test_inflight_reuse_clears_stale_rst_state():
    # First SYN is refused; before the tuple closes the client reopens it with a
    # new ISN and completes a normal handshake.  The stale RST must not decide
    # the second, successful attempt sharing the same four-tuple.
    isn1, isn2, isn_s = 1000, 2000, 9000
    packets = [
        (1.0, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn1, 0, tcpmod.TH_SYN)),
        (1.1, _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                          0, isn1 + 1, tcpmod.TH_RST | tcpmod.TH_ACK)),
        (1.2, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn2, 0, tcpmod.TH_SYN)),
        (1.3, _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                          isn_s, isn2 + 1, tcpmod.TH_SYN | tcpmod.TH_ACK)),
        (1.4, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn2 + 1, isn_s + 1, tcpmod.TH_ACK)),
    ]
    summarizer = _run(packets, idle_timeout=120.0)
    attempt = summarizer.attempts()[0]
    assert attempt.verdict == TCP_SUCCESS
    assert attempt.established is True
    assert attempt._init_syn_pkt == 3
    assert attempt.evidence == [3, 4, 5]


def test_synack_retransmit_is_deduped():
    isn_c, isn_s = 7171, 8282
    packets = [
        (1.0, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn_c, 0, tcpmod.TH_SYN)),
        (1.1, _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                          isn_s, isn_c + 1, tcpmod.TH_SYN | tcpmod.TH_ACK)),
        (1.2, _tcp_packet(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
                          isn_s, isn_c + 1, tcpmod.TH_SYN | tcpmod.TH_ACK)),
        (1.3, _tcp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
                          isn_c + 1, isn_s + 1, tcpmod.TH_ACK)),
    ]
    summarizer = _run(packets)
    attempt = summarizer.attempts()[0]
    assert attempt.verdict == TCP_SUCCESS
    assert attempt.syn_retransmits == [3]
    assert attempt.evidence == [1, 2, 4]

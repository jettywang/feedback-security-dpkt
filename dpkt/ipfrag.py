# -*- coding: utf-8 -*-
"""IPv4 fragment reassembly with explicit overlap / conflict reporting.

Offline traffic analysis must reassemble IPv4 fragments before transport
protocols such as UDP can be decoded.  Overlapping fragments are a classic
evasion technique: different operating systems select different bytes from
an overlap, so an analyzer that silently picks one copy may be shown a
benevolent datagram while the target receives another one.  This module
therefore never hands a reassembled payload to a higher layer unless every
overlapping byte is unambiguous.

Fragments are aggregated by the IPv4 reassembly identity tuple
``(src, dst, protocol, identification)``.  The wall clock is never read:
callers supply every timestamp, which keeps analysis of capture files
deterministic and re-playable.
"""
from __future__ import absolute_import

from collections import deque, namedtuple

from .ip import IP, IP_LEN_MAX, IP_PROTO_UDP

# Reassembly outcomes.  Every result carries one of these statuses.
COMPLETE = 'complete'    # all bytes present and every overlap agreed
PENDING = 'pending'      # more fragments are needed
CONFLICT = 'conflict'    # overlapping or malformed fragments disagree
EXPIRED = 'expired'      # the reassembly deadline passed before completion
LIMIT = 'limit'          # a configured cache / fragment cap was reached

DEFAULT_FRAGMENT_TIMEOUT = 30.0
DEFAULT_MAX_GROUPS = 1024
DEFAULT_MAX_FRAGMENTS = 64

# The IP fragment offset field counts 8-byte blocks.
OFFSET_UNIT = 8


class FragmentKey(namedtuple('FragmentKey', 'src dst proto id')):
    """Identity of an IPv4 datagram under reassembly."""

    __slots__ = ()

    def __repr__(self):
        return 'FragmentKey(src=%r, dst=%r, proto=%d, id=%d)' % (
            self.src, self.dst, self.proto, self.id)


class FragmentResult(object):
    """Outcome of feeding one fragment to :class:`IPFragmentReassembler`.

    Attributes:
        key: :class:`FragmentKey` the fragment belongs to.
        status: one of :data:`COMPLETE`, :data:`PENDING`, :data:`CONFLICT`,
            :data:`EXPIRED` or :data:`LIMIT`.
        payload: the fully reassembled IP payload when ``status`` is
            :data:`COMPLETE`, otherwise ``None``.  A conflicting datagram is
            never returned here.
        reason: human readable explanation for non-complete statuses.
        gaps: tuple of ``(start, end)`` byte ranges still missing.
        generation: how often the key has been reused after an expiry.
        fragments: number of fragments stored for the current generation.
        total_len: reassembled payload length in bytes once the final
            fragment has been seen, otherwise ``None``.
        retransmission: ``True`` when a fragment (or the whole datagram)
            arrived again after completion.
    """

    __slots__ = ('key', 'status', 'payload', 'reason', 'gaps', 'generation',
                 'fragments', 'total_len', 'retransmission')

    def __init__(self, key, status, payload=None, reason=None, gaps=(),
                 generation=0, fragments=0, total_len=None,
                 retransmission=False):
        self.key = key
        self.status = status
        self.payload = payload
        self.reason = reason
        self.gaps = tuple(gaps)
        self.generation = generation
        self.fragments = fragments
        self.total_len = total_len
        self.retransmission = retransmission

    @property
    def is_complete(self):
        return self.status == COMPLETE

    def __repr__(self):
        return ('FragmentResult(key=%r, status=%r, reason=%r, fragments=%d, '
                'total_len=%r)') % (self.key, self.status, self.reason,
                                    self.fragments, self.total_len)


class _FragmentGroup(object):
    """Reassembly state for one :class:`FragmentKey` generation."""

    __slots__ = ('key', 'generation', 'buffer', 'covered', 'total_len',
                 'final_seen', 'first_seen', 'last_seen', 'terminal_ts',
                 'status', 'reason', 'fragments', 'first_payload',
                 'retransmission')

    def __init__(self, key, generation, now):
        self.key = key
        self.generation = generation
        self.buffer = bytearray()
        self.covered = bytearray()
        self.total_len = None
        self.final_seen = False
        self.first_seen = now
        self.last_seen = now
        self.terminal_ts = None
        self.status = PENDING
        self.reason = None
        self.fragments = 0
        self.first_payload = None
        self.retransmission = False

    @property
    def done(self):
        return self.status != PENDING

    def _conflict(self, reason):
        # A conflict is terminal: later fragments cannot un-poison the group
        # and no payload must ever be handed to a transport decoder.
        self.status = CONFLICT
        self.reason = reason
        self.terminal_ts = self.last_seen

    def add_fragment(self, offset, payload, more_fragments, max_fragments):
        start = offset * OFFSET_UNIT
        end = start + len(payload)

        if self.status == CONFLICT:
            return self.status, self.reason
        if self.fragments >= max_fragments:
            return LIMIT, ('per-group fragment limit of %d reached'
                           % max_fragments)

        if more_fragments and len(payload) % OFFSET_UNIT != 0:
            # RFC 791: every fragment except the last one must carry a
            # payload whose length is a multiple of 8 bytes.
            self._conflict('non-final fragment at offset %d has a payload '
                           'length (%d) that is not a multiple of 8 bytes'
                           % (offset, len(payload)))
            return self.status, self.reason
        if end > IP_LEN_MAX:
            self._conflict('fragment at offset %d extends past the maximum '
                           'IPv4 datagram length (%d)' % (offset, IP_LEN_MAX))
            return self.status, self.reason

        if not more_fragments:
            total = end
            if self.total_len is None:
                self.total_len = total
                self.final_seen = True
            elif self.total_len != total:
                # Two final fragments claiming different datagram lengths
                # cannot describe the same datagram.
                self._conflict('total length conflict: final fragment at '
                               'offset %d implies %d bytes, expected %d'
                               % (offset, total, self.total_len))
                return self.status, self.reason
        elif self.final_seen and end > self.total_len:
            self._conflict('fragment at offset %d extends past the finalized '
                           'datagram length of %d bytes'
                           % (offset, self.total_len))
            return self.status, self.reason

        if offset == 0 and payload:
            if self.first_payload is None:
                self.first_payload = bytes(payload)
            elif self.first_payload != bytes(payload):
                # A second, different offset-zero fragment means the
                # identification was reused or an attacker is trying to
                # replace the transport header.
                self._conflict('duplicate first fragment with different '
                               'payload (identification reuse or overlap '
                               'attack)')
                return self.status, self.reason

        duplicate = True
        if end > len(self.buffer):
            grow = end - len(self.buffer)
            self.buffer.extend(b'\x00' * grow)
            self.covered.extend(b'\x00' * grow)

        if b'\x01' in self.covered[start:end]:
            # Only covered positions can conflict; untouched bytes still hold
            # the zeroes the buffer was grown with.
            for index in range(start, end):
                if self.covered[index] and self.buffer[index] != \
                        payload[index - start]:
                    self._conflict('overlapping fragments disagree at byte '
                                   '%d (offset %d)' % (index, offset))
                    return self.status, self.reason
            # Same bytes in the overlap: the fragment is a benign
            # retransmission / duplicate and simply extends coverage.

        # Write only previously uncovered bytes; assigning into a bytearray
        # slice wholesale would erase earlier coverage on a retransmission.
        for index, byte in enumerate(payload):
            position = start + index
            if not self.covered[position]:
                self.buffer[position] = byte
                duplicate = False
            self.covered[position] = 1
        if duplicate:
            # Every byte was already present with identical content.
            self.retransmission = True
        self.fragments += 1

        if self.final_seen and len(self.buffer) == self.total_len and \
                b'\x00' not in self.covered:
            self.status = COMPLETE
            self.terminal_ts = self.last_seen
        return self.status, self.reason

    def gaps(self):
        if self.total_len is not None:
            upper = self.total_len
        else:
            upper = len(self.covered)
        missing = []
        start = None
        for index in range(upper):
            if index < len(self.covered) and self.covered[index]:
                if start is not None:
                    missing.append((start, index))
                    start = None
            elif start is None:
                start = index
        if start is not None:
            missing.append((start, upper))
        return missing


class IPFragmentReassembler(object):
    """Stateful, time-driven IPv4 fragment reassembly analyzer.

    Args:
        fragment_timeout: seconds a reassembly group may remain incomplete
            before it expires.
        max_groups: maximum number of groups kept in the cache.
        max_fragments_per_group: maximum fragments accepted per group.

    Time is supplied by the caller through the ``ts`` argument of
    :meth:`add` and :meth:`sweep`, so the analyzer never depends on the
    system clock and can process pcap files at any speed.
    """

    def __init__(self, fragment_timeout=DEFAULT_FRAGMENT_TIMEOUT,
                 max_groups=DEFAULT_MAX_GROUPS,
                 max_fragments_per_group=DEFAULT_MAX_FRAGMENTS):
        if fragment_timeout <= 0:
            raise ValueError('fragment_timeout must be positive')
        if max_groups <= 0 or max_fragments_per_group <= 0:
            raise ValueError('cache limits must be positive')
        self.fragment_timeout = float(fragment_timeout)
        self.max_groups = max_groups
        self.max_fragments_per_group = max_fragments_per_group
        self._groups = {}
        self._generations = {}
        # Terminal events that cannot be returned by add() directly, such as
        # groups evicted by the global cache cap.
        self._events = deque()

    def __len__(self):
        return len(self._groups)

    @property
    def groups(self):
        """Mapping of :class:`FragmentKey` to internal reassembly state."""
        return dict(self._groups)

    def drain_events(self):
        """Return and clear terminal events generated by background expiry.

        Returns:
            list of :class:`FragmentResult` for groups removed by cache
            pressure or by key reuse, in removal order.
        """
        events = list(self._events)
        self._events.clear()
        return events

    def sweep(self, now):
        """Remove every group whose deadline has passed.

        Incomplete groups are reported as :data:`EXPIRED`; already terminal
        groups (complete or conflicting) are removed silently because their
        outcome was previously returned by :meth:`add`.

        Returns:
            list of :class:`FragmentResult` for expired incomplete groups.
        """
        now = float(now)
        expired = []
        for key in list(self._groups):
            group = self._groups[key]
            deadline = group.terminal_ts if group.done else group.last_seen
            if now - deadline > self.fragment_timeout:
                del self._groups[key]
                self._generations[key] = group.generation + 1
                if not group.done:
                    expired.append(self._result(
                        group, EXPIRED,
                        reason='fragment reassembly timed out after %.1f '
                               'seconds' % self.fragment_timeout))
        return expired

    def clear(self):
        self._groups.clear()
        self._generations.clear()
        self._events.clear()

    def add(self, ip, ts):
        """Process one IPv4 packet.

        Args:
            ip: a :class:`dpkt.ip.IP` instance, or raw IPv4 bytes that will
                be parsed into one.
            ts: caller supplied capture timestamp (seconds).

        Returns:
            :class:`FragmentResult`.  Non-fragmented packets produce an
            immediate :data:`COMPLETE` result without touching the cache.
        """
        if not isinstance(ip, IP):
            ip = IP(ip)
        now = float(ts)
        key = FragmentKey(bytes(ip.src), bytes(ip.dst), ip.p, ip.id)
        payload = bytes(ip.data)
        more_fragments = bool(ip.mf)

        if not more_fragments and ip.offset == 0:
            # Unfragmented datagram: nothing to aggregate, nothing to hide.
            return FragmentResult(key, COMPLETE, payload=payload,
                                  total_len=len(payload), fragments=1)

        group = self._groups.get(key)
        if group is not None and \
                now - (group.terminal_ts if group.done else group.last_seen) \
                > self.fragment_timeout:
            # The identification is free for reuse once the previous
            # generation has aged out.
            self._retire(group, now)
            group = None

        if group is None:
            self._evict_if_full()
            generation = self._generations.get(key, 0)
            group = _FragmentGroup(key, generation, now)
            self._groups[key] = group
            self._generations[key] = generation

        status, reason = group.add_fragment(
            ip.offset, payload, more_fragments, self.max_fragments_per_group)
        group.last_seen = now
        return self._result(group, status, reason=reason)

    def _retire(self, group, now):
        del self._groups[group.key]
        if not group.done:
            # A new generation of the same (src, dst, proto, id) tuple
            # started before the old one completed or aged out in the
            # normal sweep: surface the abandoned state explicitly.
            self._events.append(self._result(
                group, EXPIRED,
                reason='identification reused before the previous '
                       'generation completed'))
        self._generations[group.key] = group.generation + 1

    def _evict_if_full(self):
        if len(self._groups) < self.max_groups:
            return
        # Prefer dropping the oldest still-pending group; terminal groups
        # already delivered their result and may be removed silently.
        candidates = sorted(self._groups.values(),
                            key=lambda g: g.last_seen)
        victim = None
        for candidate in candidates:
            if not candidate.done:
                victim = candidate
                break
        if victim is None:
            victim = candidates[0]
            del self._groups[victim.key]
            return
        del self._groups[victim.key]
        self._events.append(self._result(
            victim, EXPIRED,
            reason='group cache limit of %d datagrams reached'
                   % self.max_groups))

    def _result(self, group, status, reason=None):
        payload = None
        if status == COMPLETE:
            payload = bytes(group.buffer)
        return FragmentResult(
            group.key, status, payload=payload, reason=reason,
            gaps=group.gaps(), generation=group.generation,
            fragments=group.fragments, total_len=group.total_len,
            retransmission=group.retransmission)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _fragment(ip_id, offset, payload, more_fragments,
              src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
              proto=IP_PROTO_UDP):
    return IP(src=src, dst=dst, p=proto, id=ip_id, offset=offset,
              mf=1 if more_fragments else 0, data=payload)


def _udp_payload(seed, size):
    return bytes(((seed + index) & 0xff) for index in range(size))


def test_unfragmented_datagram_is_complete_without_cache():
    reassembler = IPFragmentReassembler()
    result = reassembler.add(_fragment(1, 0, b'plain udp', False), 1.0)
    assert result.status == COMPLETE
    assert result.payload == b'plain udp'
    assert result.generation == 0
    assert len(reassembler) == 0


def test_legal_fragments_reassemble_in_every_arrival_order():
    payload = _udp_payload(7, 40)
    pieces = [payload[0:16], payload[16:32], payload[32:40]]
    order = [0, 2, 4]

    import itertools
    for permutation in itertools.permutations(range(3)):
        reassembler = IPFragmentReassembler()
        result = None
        for step, piece_index in enumerate(permutation):
            piece = pieces[piece_index]
            last = piece_index == 2
            result = reassembler.add(
                _fragment(0x1234, order[piece_index], piece, not last),
                1.0 + step * 0.01)
        assert result.status == COMPLETE
        assert result.payload == payload
        assert result.total_len == 40
        assert result.gaps == ()


def test_final_fragment_may_arrive_first():
    payload = _udp_payload(3, 24)
    reassembler = IPFragmentReassembler()
    first = reassembler.add(_fragment(9, 2, payload[16:24], False), 1.0)
    assert first.status == PENDING
    assert first.total_len == 24
    middle = reassembler.add(_fragment(9, 1, payload[8:16], True), 1.1)
    assert middle.status == PENDING
    done = reassembler.add(_fragment(9, 0, payload[0:8], True), 1.2)
    assert done.status == COMPLETE
    assert done.payload == payload


def test_identical_overlap_is_merged():
    payload = _udp_payload(11, 40)
    reassembler = IPFragmentReassembler()
    reassembler.add(_fragment(5, 0, payload[0:16], True), 1.0)
    # Final fragment starting at byte 8 whose first 8 bytes repeat the
    # first fragment verbatim and whose remaining bytes add the tail.
    retransmission = payload[8:16] + payload[16:40]
    result = reassembler.add(_fragment(5, 1, retransmission, False), 1.1)
    assert result.status == COMPLETE
    assert result.payload == payload


def test_identical_retransmission_before_completion_still_merges():
    payload = _udp_payload(13, 32)
    reassembler = IPFragmentReassembler()
    reassembler.add(_fragment(5, 0, payload[0:16], True), 1.0)
    # Exact duplicate of the first fragment.
    duplicate = reassembler.add(
        _fragment(5, 0, payload[0:16], True), 1.1)
    assert duplicate.status == PENDING
    reassembler.add(_fragment(5, 2, payload[16:24], True), 1.2)
    result = reassembler.add(_fragment(5, 3, payload[24:32], False), 1.3)
    assert result.status == COMPLETE
    assert result.payload == payload


def test_conflicting_overlap_never_yields_payload():
    payload = _udp_payload(11, 24)
    evil = bytearray(payload)
    evil[12] ^= 0xff
    reassembler = IPFragmentReassembler()
    reassembler.add(_fragment(5, 0, payload[0:16], True), 1.0)
    result = reassembler.add(_fragment(5, 1, bytes(evil[8:24]), False), 1.1)
    assert result.status == CONFLICT
    assert result.payload is None
    assert 'disagree at byte 12' in result.reason
    # The poisoned group stays terminal and cannot be repaired.
    again = reassembler.add(_fragment(5, 1, payload[8:24], False), 1.2)
    assert again.status == CONFLICT
    assert again.payload is None


def test_duplicate_first_fragment_identical_is_duplicate():
    payload = _udp_payload(2, 24)
    reassembler = IPFragmentReassembler()
    reassembler.add(_fragment(6, 0, payload[0:8], True), 1.0)
    reassembler.add(_fragment(6, 0, payload[0:8], True), 1.1)
    result = reassembler.add(_fragment(6, 1, payload[8:24], False), 1.2)
    assert result.status == COMPLETE
    assert result.payload == payload


def test_duplicate_first_fragment_different_is_conflict():
    payload = _udp_payload(2, 24)
    replaced = bytearray(payload)
    replaced[0] ^= 0x01
    reassembler = IPFragmentReassembler()
    reassembler.add(_fragment(6, 0, payload[0:8], True), 1.0)
    result = reassembler.add(_fragment(6, 0, bytes(replaced[0:8]), True), 1.1)
    assert result.status == CONFLICT
    assert result.payload is None
    assert 'duplicate first fragment' in result.reason


def test_two_samples_same_first_fragment_different_continuation():
    # Both evasion samples carry byte-identical first fragments, so any
    # classifier that only looks at fragment 0 cannot tell them apart.
    shared_head = _udp_payload(20, 16)
    benign_tail = _udp_payload(40, 16)
    benign_datagram = shared_head + benign_tail

    evil_tail = bytearray(benign_tail)
    evil_tail[0] ^= 0x5a  # first byte of the overlapping continuation

    sample_a = [
        _fragment(0x4242, 0, shared_head, True),
        _fragment(0x4242, 2, benign_tail, False),
    ]
    sample_b = [
        _fragment(0x4242, 0, shared_head, True),
        _fragment(0x4242, 1, bytes(evil_tail), False),
    ]
    assert bytes(sample_a[0].data) == bytes(sample_b[0].data)

    reassembler_a = IPFragmentReassembler()
    result_a = reassembler_a.add(sample_a[0], 1.0)
    assert result_a.status == PENDING
    result_a = reassembler_a.add(sample_a[1], 1.1)
    assert result_a.status == COMPLETE
    assert result_a.payload == benign_datagram

    reassembler_b = IPFragmentReassembler()
    reassembler_b.add(sample_b[0], 1.0)
    result_b = reassembler_b.add(sample_b[1], 1.1)
    # The identical first fragment must not make the conflicting sample
    # look like the benign, complete request.
    assert result_b.status == CONFLICT
    assert result_b.payload is None
    assert result_b.total_len is None or result_b.gaps or result_b.reason


def test_total_length_conflict():
    reassembler = IPFragmentReassembler()
    reassembler.add(_fragment(8, 0, b'a' * 16, True), 1.0)
    reassembler.add(_fragment(8, 2, b'b' * 8, True), 1.1)
    reassembler.add(_fragment(8, 4, b'c' * 8, True), 1.2)
    # First final fragment lands at byte 48, leaving bytes 40..47 missing.
    first_final = reassembler.add(
        _fragment(8, 6, b'd' * 8, False), 1.3)
    assert first_final.status == PENDING
    assert first_final.total_len == 56
    # Another final fragment at the same offset implies a longer datagram.
    result = reassembler.add(
        _fragment(8, 6, b'd' * 8 + b'extra!!!', False), 1.4)
    assert result.status == CONFLICT
    assert 'total length conflict' in result.reason
    assert result.payload is None


def test_unaligned_non_final_fragment_is_conflict():
    reassembler = IPFragmentReassembler()
    result = reassembler.add(_fragment(4, 1, b'seven!!', True), 1.0)
    assert result.status == CONFLICT
    assert 'multiple of 8' in result.reason


def test_expiry_and_identification_reuse():
    payload_one = _udp_payload(1, 24)
    payload_two = _udp_payload(99, 24)
    reassembler = IPFragmentReassembler(fragment_timeout=5.0)

    reassembler.add(_fragment(7, 0, payload_one[0:8], True), 0.0)
    reassembler.add(_fragment(7, 2, payload_one[16:24], True), 0.1)
    expired = reassembler.sweep(10.0)
    assert len(expired) == 1
    assert expired[0].status == EXPIRED
    assert expired[0].gaps == ((8, 16),)
    assert 7 not in [g.key.id for g in reassembler.groups]

    # The id is reusable after expiry; the new generation starts at 1.
    result = reassembler.add(_fragment(7, 0, payload_two[0:8], True), 6.0)
    assert result.generation == 1
    result = reassembler.add(_fragment(7, 1, payload_two[8:24], False), 6.1)
    assert result.status == COMPLETE
    assert result.payload == payload_two
    assert result.generation == 1


def test_identification_reuse_within_timeout_conflicts_on_first_fragment():
    payload_one = _udp_payload(1, 24)
    reassembler = IPFragmentReassembler(fragment_timeout=30.0)
    reassembler.add(_fragment(7, 0, payload_one[0:8], True), 0.0)
    # A new, different datagram reusing the id before the old one expired:
    # the differing first fragment cannot be silently accepted.
    result = reassembler.add(_fragment(7, 0, b'TOTALLY!', True), 1.0)
    assert result.status == CONFLICT
    assert 'duplicate first fragment' in result.reason
    assert reassembler.drain_events() == []


def test_late_add_after_timeout_retires_old_generation_via_event():
    payload_one = _udp_payload(1, 24)
    payload_two = _udp_payload(99, 16)
    reassembler = IPFragmentReassembler(fragment_timeout=5.0)
    reassembler.add(_fragment(7, 0, payload_one[0:8], True), 0.0)
    # No explicit sweep: the stale group is retired lazily on the next add.
    new_head = reassembler.add(
        _fragment(7, 0, payload_two[0:8], True), 6.0)
    assert new_head.generation == 1
    assert new_head.status == PENDING
    events = reassembler.drain_events()
    assert len(events) == 1
    assert events[0].status == EXPIRED
    assert 'identification reused' in events[0].reason
    done = reassembler.add(_fragment(7, 1, payload_two[8:16], False), 6.1)
    assert done.status == COMPLETE
    assert done.payload == payload_two


def test_completed_datagram_handles_retransmission():
    payload = _udp_payload(5, 16)
    reassembler = IPFragmentReassembler()
    reassembler.add(_fragment(3, 0, payload[0:8], True), 0.0)
    done = reassembler.add(_fragment(3, 1, payload[8:16], False), 0.1)
    assert done.status == COMPLETE
    again = reassembler.add(_fragment(3, 1, payload[8:16], False), 0.2)
    assert again.status == COMPLETE
    assert again.payload == payload
    assert again.retransmission is True
    # A genuinely new fragment on a still-pending group is not a retransmit.
    other = IPFragmentReassembler()
    other.add(_fragment(9, 0, payload[0:8], True), 0.0)
    fresh = other.add(_fragment(9, 1, payload[8:16], False), 0.1)
    assert fresh.retransmission is False


def test_per_group_fragment_limit():
    reassembler = IPFragmentReassembler(max_fragments_per_group=2)
    reassembler.add(_fragment(2, 0, b'a' * 8, True), 0.0)
    reassembler.add(_fragment(2, 1, b'b' * 8, True), 0.1)
    result = reassembler.add(_fragment(2, 2, b'c' * 8, True), 0.2)
    assert result.status == LIMIT
    assert 'per-group fragment limit' in result.reason


def test_global_group_cache_limit_emits_expiry_events():
    reassembler = IPFragmentReassembler(max_groups=2)
    reassembler.add(_fragment(1, 0, b'a' * 8, True), 0.0)
    reassembler.add(_fragment(2, 0, b'b' * 8, True), 0.1)
    reassembler.add(_fragment(3, 0, b'c' * 8, True), 0.2)
    events = reassembler.drain_events()
    assert len(events) == 1
    assert events[0].status == EXPIRED
    assert 'cache limit' in events[0].reason
    assert events[0].key.id == 1
    assert len(reassembler) == 2


def test_sweep_removes_terminal_groups_silently():
    reassembler = IPFragmentReassembler(fragment_timeout=1.0)
    payload = _udp_payload(8, 16)
    reassembler.add(_fragment(4, 0, payload[0:8], True), 0.0)
    reassembler.add(_fragment(4, 1, payload[8:16], False), 0.1)
    assert reassembler.sweep(2.0) == []
    assert len(reassembler) == 0
    assert reassembler.drain_events() == []


def test_accepts_raw_ipv4_bytes():
    payload = _udp_payload(6, 16)
    packet = bytes(_fragment(11, 0, payload[0:8], True))
    reassembler = IPFragmentReassembler()
    result = reassembler.add(packet, 0.0)
    assert result.status == PENDING
    assert result.key.id == 11


def test_udp_decoder_only_sees_unambiguous_payload():
    from .udp import UDP
    head = b'\x03\xe8\x00\x35\x00\x18\x00\x00'  # 8-byte UDP header
    body_a = b'A' * 16
    benign = head + body_a
    evil_tail = bytearray(benign[8:24])
    evil_tail[0] ^= 0x5a  # byte 8 disagrees inside the overlapping region

    reassembler = IPFragmentReassembler()
    reassembler.add(_fragment(21, 0, benign[0:16], True), 0.0)
    clean = reassembler.add(_fragment(21, 2, benign[16:24], False), 0.1)
    assert clean.status == COMPLETE
    udp = UDP(clean.payload)
    assert udp.sport == 1000
    assert udp.data == body_a

    poisoned_assembler = IPFragmentReassembler()
    poisoned_assembler.add(_fragment(21, 0, benign[0:16], True), 0.0)
    # Starts at byte 8: its first 8 bytes overlap the first fragment and
    # disagree at byte 8, so no datagram may be handed to UDP.
    poisoned = poisoned_assembler.add(
        _fragment(21, 1, bytes(evil_tail), False), 0.1)
    assert poisoned.status == CONFLICT
    assert poisoned.payload is None

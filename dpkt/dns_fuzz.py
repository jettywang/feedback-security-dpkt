# -*- coding: utf-8 -*-
"""Structured, reproducible fuzz tests for the DNS decode path.

Not random bytes at the constructor: seeds are legal queries and responses
that use compression pointers; mutations target pointer targets, label
boundaries, record counts, RDLEN fields and names embedded in RDATA.

Outcomes are classified as:
  ok          - parsed and every consumption boundary checks out
  needdata    - dpkt.NeedData (clean truncation signal)
  reject      - dpkt.UnpackError (clean format rejection)
  unexpected  - any other exception escaping the decode path
  boundary    - parsed, but consumed bytes are inconsistent
                (rdata-short / txt-overrun / trailing-bytes)
  unbounded   - parse did not finish within the step time budget

Everything is deterministic: fixed seed, bounded step count, stdlib only.

Run via pytest:  python3 -m pytest dpkt/dns_fuzz.py
Report mode:     python3 -m dpkt.dns_fuzz
"""
from __future__ import absolute_import, print_function

import binascii
import codecs
import random
import signal
import struct
from collections import Counter
from contextlib import contextmanager

from . import dpkt
from . import dns as dns_mod
from .compat import compat_ord
from .dns import DNS, define_testdata, unpack_name

SEED = 0xD45EED
STEPS = 500
TIME_LIMIT = 0.5  # seconds; a parse of a <=200B message takes microseconds

# failure classes observed on the stock decoder; anything outside this set
# fails the campaign test.  Each entry is documented in test_known_findings.
KNOWN_FINDINGS = {
    ('unexpected', 'UnicodeDecodeError'),
    ('boundary', 'rdata-short'),
    ('boundary', 'txt-overrun'),
    ('boundary', 'trailing-bytes'),
}

CIRCULAR_PTR_PACKET = (
    b'\xc0\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    b'\x07example\x03com\xc0\x00')
TRUNCATED_NAME_PACKET = (
    struct.pack('>HHHHHH', 1, 0x0100, 1, 0, 0, 0) + b'\x03ww')


# ---------------------------------------------------------------- seeds

def build_seeds():
    td = define_testdata()
    seeds = {}
    for name in ('a_resp', 'aaaa_resp', 'cname_resp', 'mx_resp', 'null_resp',
                 'opt_resp', 'ptr_resp', 'soa_resp', 'srv_resp', 'txt_resp'):
        seeds[name] = getattr(td, name)
    # legal plain query: question section of a_resp, flags -> standard query
    _, qend = unpack_name(td.a_resp, 12)
    q = bytearray(td.a_resp[:qend + 4])
    q[2:4] = struct.pack('>H', dns_mod.DNS_RD)
    q[6:12] = b'\x00' * 6
    seeds['query'] = bytes(q)
    return seeds


SEEDS = build_seeds()


# ------------------------------------------------------- structure scan

class Sites(object):
    """Offsets of the mutable structures inside a DNS message."""

    def __init__(self):
        self.pointers = []      # first byte of each 0xC0 compression pointer
        self.labels = []        # label-length bytes
        self.rdlens = []        # rdlen fields
        self.rdata_names = []   # name fields embedded in RDATA
        self.rdata_bytes = []   # every RDATA byte offset
        self.bounds = set()     # record boundaries (truncation points)
        self.end = 0            # offset just past the last consumed byte


def _scan_name(buf, off, sites, depth=0):
    if depth > 32:
        raise dpkt.UnpackError('name too deep')
    while True:
        if off >= len(buf):
            raise dpkt.NeedData()
        n = compat_ord(buf[off])
        if n == 0:
            return off + 1
        if (n & 0xc0) == 0xc0:
            sites.pointers.append(off)
            return off + 2
        if (n & 0xc0) != 0x00:
            raise dpkt.UnpackError('bad label bits')
        sites.labels.append(off)
        off += 1 + n


def scan(buf):
    """Walk a message like DNS.unpack does and record mutation sites.

    Returns None when the buffer does not parse structurally; mutators
    treat that as 'no sites here' and leave other mutators to try.
    """
    if len(buf) < 12:
        return None
    sites = Sites()
    qd, an, ns, ar = struct.unpack('>HHHH', buf[4:12])
    off = 12
    try:
        for _ in range(qd):
            off = _scan_name(buf, off, sites)
            sites.bounds.add(off + 4)
            off += 4
        for _ in range(an + ns + ar):
            off = _scan_name(buf, off, sites)
            rtype = struct.unpack('>H', buf[off:off + 2])[0]
            rdlen = struct.unpack('>H', buf[off + 8:off + 10])[0]
            sites.rdlens.append(off + 8)
            rdata = off + 10
            if rtype in (dns_mod.DNS_NS, dns_mod.DNS_CNAME, dns_mod.DNS_PTR):
                sites.rdata_names.append(rdata)
                _scan_name(buf, rdata, sites)
            elif rtype == dns_mod.DNS_MX:
                sites.rdata_names.append(rdata + 2)
                _scan_name(buf, rdata + 2, sites)
            elif rtype == dns_mod.DNS_SRV:
                sites.rdata_names.append(rdata + 6)
                _scan_name(buf, rdata + 6, sites)
            elif rtype == dns_mod.DNS_SOA:
                sites.rdata_names.append(rdata)
                nxt = _scan_name(buf, rdata, sites)
                sites.rdata_names.append(nxt)
                _scan_name(buf, nxt, sites)
            sites.rdata_bytes.extend(range(rdata, min(rdata + rdlen, len(buf))))
            off = rdata + rdlen
            sites.bounds.add(off)
    except (dpkt.UnpackError, struct.error, IndexError):
        return None
    sites.end = off
    return sites


# ------------------------------------------------------------- mutators

def _set(buf, off, data):
    return buf[:off] + data + buf[off + len(data):]


def _one_byte(val):
    return bytes(bytearray([val]))


def mut_pointer_target(buf, rng):
    """Rewrite a compression pointer target: self, forward, header, EOF."""
    sites = scan(buf)
    if not sites or not sites.pointers:
        return None
    off = rng.choice(sites.pointers)
    targets = [0, 1, 11, 12, off, off + 1, len(buf) - 1, len(buf), 0x3fff]
    if sites.labels:
        targets.append(rng.choice(sites.labels))
    return _set(buf, off, struct.pack('>H', 0xc000 | (rng.choice(targets) & 0x3fff)))


def mut_label_length(buf, rng):
    """Corrupt a label-length byte across the 0x3f/0x40/0xc0 boundaries."""
    sites = scan(buf)
    if not sites or not sites.labels:
        return None
    off = rng.choice(sites.labels)
    return _set(buf, off, _one_byte(rng.choice(
        (0, 1, 2, 63, 64, 65, 127, 128, 191, 192, 255))))


def mut_count(buf, rng):
    """Mutate qd/an/ns/ar record counts."""
    if len(buf) < 12:
        return None
    off = 2 * rng.randrange(2, 6)
    cur = struct.unpack('>H', buf[off:off + 2])[0]
    val = rng.choice((0, 1, 2, cur + 1, cur + 2, 0x100, 0x7fff, 0xffff))
    return _set(buf, off, struct.pack('>H', val & 0xffff))


def mut_rdlen(buf, rng):
    """Mutate an RDLEN field around the actual bytes remaining."""
    sites = scan(buf)
    if not sites or not sites.rdlens:
        return None
    off = rng.choice(sites.rdlens)
    cur = struct.unpack('>H', buf[off:off + 2])[0]
    remaining = len(buf) - (off + 2)
    val = rng.choice((0, 1, max(0, cur - 1), cur + 1,
                      max(0, remaining - 1), remaining, remaining + 1, 0xffff))
    return _set(buf, off, struct.pack('>H', val & 0xffff))


def mut_rdata_name(buf, rng):
    """Mutate a name embedded in RDATA (MX/NS/CNAME/PTR/SRV/SOA)."""
    sites = scan(buf)
    if not sites or not sites.rdata_names:
        return None
    off = rng.choice(sites.rdata_names)
    if off >= len(buf):
        return None
    choice = rng.randrange(3)
    if choice == 0:  # replace name start with a pointer to somewhere odd
        tgt = rng.choice((0, 12, off, len(buf) - 1, 0x3fff))
        return _set(buf, off, struct.pack('>H', 0xc000 | (tgt & 0x3fff)))
    if choice == 1:  # corrupt the first label-length byte of the name
        return _set(buf, off, _one_byte(rng.choice((0, 63, 64, 192, 255))))
    return buf[:off] + buf[off + 1:]  # drop a byte, desyncing rdlen


def mut_truncate(buf, rng):
    """Cut the buffer at (or one byte around) a record boundary."""
    sites = scan(buf)
    points = sorted(sites.bounds) if sites else []
    points.append(len(buf))
    cut = max(0, rng.choice(points) + rng.choice((-2, -1, 0, 1)))
    if cut >= len(buf):
        return None
    return buf[:cut]


def mut_extend(buf, rng):
    """Append trailing garbage the parser never asked for."""
    return buf + bytes(bytearray(rng.randrange(256)
                                 for _ in range(rng.randrange(1, 5))))


def mut_byte(buf, rng):
    """Flip one bit inside a structured region (label/pointer/rdlen/rdata)."""
    sites = scan(buf)
    pools = []
    if sites:
        pools = [p for p in (sites.labels, sites.pointers,
                             sites.rdlens, sites.rdata_bytes) if p]
    if not pools:
        if not buf:
            return None
        off = rng.randrange(len(buf))
    else:
        off = rng.choice(rng.choice(pools))
    return _set(buf, off, _one_byte(compat_ord(buf[off]) ^ (1 << rng.randrange(8))))


MUTATORS = (mut_pointer_target, mut_label_length, mut_count, mut_rdlen,
            mut_rdata_name, mut_truncate, mut_extend, mut_byte)


# ---------------------------------------------------------- time budget

class _Timeout(Exception):
    pass


def _on_alarm(signum, frame):
    raise _Timeout()


@contextmanager
def _time_limit(seconds):
    if not hasattr(signal, 'setitimer'):
        yield
        return
    prev = signal.signal(signal.SIGALRM, _on_alarm)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prev)


# --------------------------------------------------------- classification

def _boundary_check(d, buf):
    """Invariants for a parse that claims success.  Returns None or a
    short string naming the first consumption inconsistency found."""
    for section in ('an', 'ns', 'ar'):
        for rr in getattr(d, section):
            if len(rr.rdata) != rr.rlen:
                return 'rdata-short'      # rdlen > bytes actually left
            if rr.type in (dns_mod.DNS_TXT, dns_mod.DNS_HINFO):
                rdata, pos = rr.rdata, 0
                while pos < len(rdata):
                    n = compat_ord(rdata[pos])
                    if pos + 1 + n > len(rdata):
                        return 'txt-overrun'  # char-string len past rdlen
                    pos += 1 + n
    sites = scan(buf)
    if sites and sites.end < len(buf):
        return 'trailing-bytes'           # parser silently dropped bytes
    return None


def classify(buf):
    """Run the decode path once and classify the outcome."""
    try:
        with _time_limit(TIME_LIMIT):
            d = DNS(bytes(buf))
    except _Timeout:
        return 'unbounded', 'parse exceeded %ss budget' % TIME_LIMIT
    except dpkt.NeedData:
        return 'needdata', 'truncated'
    except dpkt.UnpackError:
        return 'reject', 'format'
    except Exception as e:
        return 'unexpected', type(e).__name__
    bad = _boundary_check(d, bytes(buf))
    if bad:
        return 'boundary', bad
    return 'ok', ''


# ------------------------------------------------------------- campaign

def run_campaign(seed=SEED, steps=STEPS):
    """Fixed-seed, bounded-step structured mutation campaign."""
    rng = random.Random(seed)
    seeds = list(SEEDS.values())
    stats = Counter()
    failures = []
    for _ in range(steps):
        buf = rng.choice(seeds)
        for _ in range(rng.randint(1, 3)):
            for _attempt in range(4):
                new = rng.choice(MUTATORS)(buf, rng)
                if new is not None:
                    buf = new
                    break
        cat, detail = classify(buf)
        stats[(cat, detail)] += 1
        if cat in ('unexpected', 'boundary', 'unbounded'):
            failures.append((cat, detail, buf))
    return stats, failures


# ------------------------------------------------------------ shrinking

def failure_predicate(cat, detail, require_pointer):
    """keep() is True while a candidate preserves the original failure
    class; for compression-related failures the candidate must still
    contain a live compression pointer (verified structurally via scan)
    so the reference relation survives minimization."""
    def keep(cand):
        if not cand:
            return False
        if classify(cand) != (cat, detail):
            return False
        if require_pointer:
            sites = scan(cand)
            if not sites or not sites.pointers:
                return False
        return True
    return keep


def shrink(buf, keep):
    """Greedy minimization: delete chunks, then zero windows (zeroing
    keeps every offset intact, which preserves length conflicts)."""
    buf = bytes(buf)
    improved = True
    while improved:
        improved = False
        for chunk in (len(buf) // 2, len(buf) // 4, len(buf) // 8, 4, 2, 1):
            if chunk < 1:
                continue
            i = 0
            while i < len(buf):
                cand = buf[:i] + buf[i + chunk:]
                if keep(cand):
                    buf = cand
                    improved = True
                else:
                    i += chunk
        for chunk in (8, 4, 2, 1):
            i = 0
            while i + chunk <= len(buf):
                cand = buf[:i] + b'\x00' * chunk + buf[i + chunk:]
                if cand != buf and keep(cand):
                    buf = cand
                    improved = True
                i += chunk
    return buf


# ------------------------------------------------------ offset explainer

def _hex(b):
    h = binascii.hexlify(b).decode('ascii')
    return ' '.join(h[i:i + 2] for i in range(0, len(h), 2))


def _explain_name(buf, off, lines, prefix):
    while True:
        if off >= len(buf):
            lines.append('%04x  --           %s: name runs past end of buffer' % (off, prefix))
            return off
        n = compat_ord(buf[off])
        if n == 0:
            lines.append('%04x  00           %s: root label (name ends)' % (off, prefix))
            return off + 1
        if (n & 0xc0) == 0xc0:
            if off + 2 > len(buf):
                lines.append('%04x  %02x         %s: pointer missing its second byte' % (off, n, prefix))
                return off + 2
            ptr = struct.unpack('>H', buf[off:off + 2])[0] & 0x3fff
            if ptr >= len(buf):
                note = 'INVALID: past end of buffer'
            elif ptr >= off:
                note = 'INVALID: not a backward reference'
            else:
                note = 'ok, backward reference'
            lines.append('%04x  %-12s %s: pointer -> 0x%04x (%s)' % (off, _hex(buf[off:off + 2]), prefix, ptr, note))
            return off + 2
        if (n & 0xc0) != 0x00:
            lines.append('%04x  %02x           %s: invalid label-length bits 0x%02x' % (off, n, prefix, n))
            return off + 1
        label = buf[off + 1:off + 1 + n]
        lines.append('%04x  %-12s %s: label len=%d %r' % (off, _hex(buf[off:off + 1 + n]), prefix, n, label))
        if len(label) < n:
            lines.append('      ^ label body truncated: %d of %d bytes present' % (len(label), n))
            return off + 1 + n
        off += 1 + n


def explain(buf):
    """Annotate a message byte-by-byte with offsets; used to document
    minimal failing samples."""
    buf = bytes(buf)
    lines = []
    if len(buf) < 12:
        lines.append('%04x  %-12s header truncated: %d of 12 bytes' % (0, _hex(buf), len(buf)))
        return '\n'.join(lines)
    ident, op, qd, an, ns, ar = struct.unpack('>HHHHHH', buf[:12])
    lines.append('%04x  %-12s id=%d op=0x%04x' % (0, _hex(buf[0:4]), ident, op))
    lines.append('%04x  %-12s qd=%d an=%d ns=%d ar=%d' % (4, _hex(buf[4:12]), qd, an, ns, ar))
    off = 12
    for i in range(qd):
        off = _explain_name(buf, off, lines, 'q%d' % i)
        if off + 4 > len(buf):
            lines.append('%04x  q%d: qtype/qclass truncated (%d of 4 bytes)' % (off, i, len(buf) - off))
            return '\n'.join(lines)
        qt, qc = struct.unpack('>HH', buf[off:off + 4])
        lines.append('%04x  %-12s q%d: type=%d class=%d' % (off, _hex(buf[off:off + 4]), i, qt, qc))
        off += 4
    for sec, cnt in (('an', an), ('ns', ns), ('ar', ar)):
        for i in range(cnt):
            off = _explain_name(buf, off, lines, '%s%d name' % (sec, i))
            if off + 10 > len(buf):
                lines.append('%04x  %s%d: fixed RR fields truncated (%d of 10 bytes)' % (off, sec, i, len(buf) - off))
                return '\n'.join(lines)
            rtype, rclass, ttl, rdlen = struct.unpack('>HHIH', buf[off:off + 10])
            lines.append('%04x  %-12s %s%d: type=%d class=%d ttl=%d rdlen=%d'
                         % (off, _hex(buf[off:off + 10]), sec, i, rtype, rclass, ttl, rdlen))
            rdata = buf[off + 10:off + 10 + rdlen]
            note = '' if len(rdata) == rdlen else \
                '  <-- SHORT: declared %d, only %d bytes remain' % (rdlen, len(rdata))
            lines.append('%04x  %-12s rdata%s' % (off + 10, _hex(rdata), note))
            off += 10 + rdlen
    if off < len(buf):
        lines.append('%04x  %-12s trailing: %d bytes never consumed' % (off, _hex(buf[off:]), len(buf) - off))
    elif off > len(buf):
        lines.append('%04x  parser stopped %d bytes past end of buffer' % (len(buf), off - len(buf)))
    return '\n'.join(lines)


# ------------------------------------------------------- planted bugs

def _buggy_unpack_name_no_guard(buf, off):
    """Planted bug: backward-pointer guard removed, so circular
    compression references are followed forever."""
    name = []
    saved_off = 0
    start_off = off
    name_length = 0
    while True:
        if off >= len(buf):
            raise dpkt.NeedData()
        n = compat_ord(buf[off])
        if n == 0:
            off += 1
            break
        elif (n & 0xc0) == 0xc0:
            ptr = struct.unpack('>H', buf[off:off + 2])[0] & 0x3fff
            # BUG: `if ptr >= start_off: raise UnpackError` deleted
            off += 2
            if not saved_off:
                saved_off = off
            start_off = off = ptr
        elif (n & 0xc0) == 0x00:
            off += 1
            name.append(buf[off:off + n])
            name_length += n + 1
            if name_length > 255:
                raise dpkt.UnpackError('name longer than 255 bytes')
            off += n
        else:
            raise dpkt.UnpackError('Invalid label length %02x' % n)
    if not saved_off:
        saved_off = off
    return codecs.decode(b'.'.join(name), 'utf-8'), saved_off


def _buggy_unpack_name_no_needdata(buf, off):
    """Planted bug: truncation check removed, so a name running past
    the buffer raises a raw IndexError instead of NeedData."""
    name = []
    saved_off = 0
    start_off = off
    name_length = 0
    while True:
        # BUG: `if off >= len(buf): raise NeedData()` deleted
        n = compat_ord(buf[off])
        if n == 0:
            off += 1
            break
        elif (n & 0xc0) == 0xc0:
            ptr = struct.unpack('>H', buf[off:off + 2])[0] & 0x3fff
            if ptr >= start_off:
                raise dpkt.UnpackError('Invalid label compression pointer')
            off += 2
            if not saved_off:
                saved_off = off
            start_off = off = ptr
        elif (n & 0xc0) == 0x00:
            off += 1
            name.append(buf[off:off + n])
            name_length += n + 1
            if name_length > 255:
                raise dpkt.UnpackError('name longer than 255 bytes')
            off += n
        else:
            raise dpkt.UnpackError('Invalid label length %02x' % n)
    if not saved_off:
        saved_off = off
    return codecs.decode(b'.'.join(name), 'utf-8'), saved_off


class _planted(object):
    """Context manager swapping dns_mod.unpack_name for a buggy one."""

    def __init__(self, buggy):
        self.buggy = buggy

    def __enter__(self):
        self.original = dns_mod.unpack_name
        dns_mod.unpack_name = self.buggy

    def __exit__(self, *exc):
        dns_mod.unpack_name = self.original
        return False


# ---------------------------------------------------------------- tests

def test_valid_compressed_roundtrip():
    """Counterexample guard: legal packets WITH compression pointers must
    keep parsing and re-serializing byte-identically, so the harness can
    never be 'fixed' by rejecting every pointer-bearing packet."""
    for name, buf in SEEDS.items():
        cat, detail = classify(buf)
        assert (cat, detail) == ('ok', ''), (name, cat, detail)
        assert bytes(DNS(buf)) == buf, name
        if name != 'query' and name != 'opt_resp':
            assert b'\xc0' in buf, name  # seeds really exercise pointers


def test_fuzz_campaign_reproducible():
    """Fixed seed + bounded steps: two runs agree exactly, and every
    failure found on the stock decoder is a documented known class."""
    stats1, failures1 = run_campaign()
    stats2, _ = run_campaign()
    assert stats1 == stats2
    unknown = {(c, d) for c, d, _ in failures1} - KNOWN_FINDINGS
    assert not unknown, 'new failure classes: %r' % (unknown,)
    assert not any(c == 'unbounded' for c, _, _ in failures1)


def test_planted_bug_unbounded_processing():
    """Evidence the harness catches a planted bug: with the backward
    pointer guard removed, the fuzzer itself produces inputs that loop
    forever and are flagged 'unbounded' by the time budget."""
    # targeted: stock rejects the circular packet, planted bug hangs on it
    assert classify(CIRCULAR_PTR_PACKET)[0] == 'reject'
    with _planted(_buggy_unpack_name_no_guard):
        cat, _ = classify(CIRCULAR_PTR_PACKET)
        assert cat == 'unbounded'
        # campaign-level: the mutators rediscover hangs on their own
        stats, _ = run_campaign(seed=SEED, steps=120)
        assert any(cat == 'unbounded' for (cat, _) in stats), stats


def test_planted_bug_unexpected_exception():
    """Evidence #2: with the truncation check removed, a raw IndexError
    escapes the decode path and is classified 'unexpected' instead of
    the correct 'needdata'."""
    assert classify(TRUNCATED_NAME_PACKET)[0] == 'needdata'
    with _planted(_buggy_unpack_name_no_needdata):
        assert classify(TRUNCATED_NAME_PACKET) == ('unexpected', 'IndexError')


def test_shrink_preserves_failure_class():
    """A failing sample shrinks while keeping both its failure class and
    its live compression pointer."""
    buf = bytearray(SEEDS['a_resp'])
    sites = scan(bytes(buf))
    buf[10:12] = b'\x00\x00'  # drop ar count so the OPT RR becomes slack
    rdlen_off = sites.rdlens[0]
    buf[rdlen_off:rdlen_off + 2] = struct.pack('>H', 0x00f0)  # 240 > remaining
    buf = bytes(buf)
    cat, detail = classify(buf)
    assert (cat, detail) == ('boundary', 'rdata-short')
    small = shrink(buf, failure_predicate(cat, detail, require_pointer=True))
    assert len(small) < len(buf)
    assert classify(small) == (cat, detail)
    assert scan(small).pointers  # compression reference relation preserved


def test_known_findings():
    """Characterize the stock decoder's current boundary/exceptions so a
    future fix (or regression) is visible."""
    # rdlen larger than the bytes remaining: silently short rdata
    buf = bytearray(SEEDS['a_resp'])
    buf[10:12] = b'\x00\x00'
    rdlen_off = scan(bytes(buf)).rdlens[0]
    buf[rdlen_off:rdlen_off + 2] = struct.pack('>H', 0x00f0)
    assert classify(bytes(buf)) == ('boundary', 'rdata-short')

    # TXT char-string length byte overrunning rdlen: silently accepted
    buf = bytearray(SEEDS['txt_resp'])
    sites = scan(bytes(buf))
    rdata_off = sites.rdata_bytes[0]
    buf[rdata_off] = 0x40  # claims 64 bytes, rdlen is 16
    assert classify(bytes(buf)) == ('boundary', 'txt-overrun')

    # public unpack_name leaks struct.error on a 1-byte truncated pointer
    # instead of NeedData/UnpackError like every other truncation
    try:
        unpack_name(b'\x03www\xc0', 0)
    except struct.error:
        pass
    else:
        raise AssertionError('expected struct.error to leak')

    # non-UTF-8 label bytes escape DNS() as UnicodeDecodeError
    pkt = struct.pack('>HHHHHH', 1, 0x0100, 1, 0, 0, 0)
    pkt += b'\x02\xff\xfe\x00' + struct.pack('>HH', 1, 1)
    assert classify(pkt) == ('unexpected', 'UnicodeDecodeError')


# -------------------------------------------------------------- report

def _report(stats, failures):
    print('campaign: seed=0x%x steps=%d' % (SEED, STEPS))
    for (cat, detail), n in sorted(stats.items()):
        print('  %-10s %-16s %d' % (cat, detail or '-', n))
    seen = set()
    for cat, detail, buf in failures:
        if (cat, detail) in seen:
            continue
        seen.add((cat, detail))
        orig_sites = scan(buf)
        keep = failure_predicate(cat, detail,
                                 require_pointer=bool(orig_sites and orig_sites.pointers))
        small = shrink(buf, keep)
        print('\n=== minimal sample: %s/%s (%d -> %d bytes) ==='
              % (cat, detail, len(buf), len(small)))
        print(explain(small))


if __name__ == '__main__':
    _stats, _failures = run_campaign()
    _report(_stats, _failures)

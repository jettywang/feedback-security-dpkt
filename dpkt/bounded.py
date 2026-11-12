# -*- coding: utf-8 -*-
"""Bounded, non-seekable ingestion of libpcap and single-section pcapng files.

The :class:`Reader` in :mod:`dpkt.pcap` and :mod:`dpkt.pcapng` feed the length
fields found in untrusted capture files directly to ``fileobj.read()``.  A
hostile ``caplen`` / block length therefore makes the reader allocate and read
an arbitrarily large buffer, and a truncated capture is mistaken for a clean
end of file (the reader simply stops yielding packets).

This module provides a defensive entry point for a packet-capture scanning
service:

* the underlying stream may return only a few bytes per ``read()`` and must not
  support ``seek()``;
* per-packet, per-block and total-input byte budgets are enforced *before* the
  bytes are requested, so a malicious length field can never trigger a giant
  allocation;
* clean end of file, a half header, a short payload and a budget rejection are
  reported as distinct, layered errors that carry the absolute file offset.

The whole capture is never buffered: only one bounded record at a time is held
in memory.
"""
from __future__ import absolute_import, print_function

from struct import unpack as struct_unpack
from decimal import Decimal

from . import dpkt
from . import pcap
from . import pcapng

# Failure layers.  They identify which structural element was being consumed
# when an error was raised, which is what a scanner needs in its diagnostics.
LAYER_FILE_HEADER = 'file-header'
LAYER_PACKET_HEADER = 'packet-header'
LAYER_PACKET_PAYLOAD = 'packet-payload'
LAYER_SECTION = 'section-header-block'
LAYER_INTERFACE = 'interface-description-block'
LAYER_BLOCK_HEADER = 'block-header'
LAYER_BLOCK_BODY = 'block-body'
LAYER_INPUT = 'input'

# Default budgets.  They are deliberately generous for ordinary captures but
# keep a single allocation comfortably bounded.
DEFAULT_MAX_PACKET = 1 << 16   # 64 KiB captured bytes per packet
DEFAULT_MAX_BLOCK = 1 << 22    # 4 MiB per pcapng block
DEFAULT_MAX_TOTAL = 1 << 30    # 1 GiB total input


class CaptureError(dpkt.Error):
    """Base class for every error raised by the bounded reader."""

    def __init__(self, message, offset, layer):
        super(CaptureError, self).__init__(message)
        self.offset = offset
        self.layer = layer


class CaptureFormatError(CaptureError, ValueError):
    """The capture violates its format specification (bad magic, length, ...)."""


class TruncatedHeaderError(CaptureError):
    """A fixed-size header/block-header was cut off in the middle."""


class TruncatedPayloadError(CaptureError):
    """A declared variable-size body (packet data, block body) is incomplete."""


class LimitExceededError(CaptureError):
    """A configured byte budget was exceeded before the data was requested."""


class BoundedStream(object):
    """Stream wrapper that enforces a total byte budget and tolerates short reads.

    ``stream`` only needs a ``read(n)`` method; ``seek`` is never used.  Every
    request made to the underlying stream is recorded in :attr:`read_requests`
    so tests can prove that no read ever asks for an unbounded amount of data.
    """

    def __init__(self, stream, max_total=DEFAULT_MAX_TOTAL):
        self._stream = stream
        self.max_total = max_total
        self._offset = 0
        self._pushback = b''
        self._budget_hit = False
        self._buffered_bytes = 0
        self.read_requests = []

    @property
    def offset(self):
        """Absolute number of bytes consumed from the capture so far."""
        return self._offset

    def _raw_read(self, size):
        # Record the size asked of the real stream and clamp it to what remains
        # of the total budget, so an over-budget request can never be issued.
        self.read_requests.append(size)
        remaining = self.max_total - self._offset - self._buffered_bytes
        if remaining <= 0:
            self._budget_hit = True
            return b''
        chunk = self._stream.read(min(size, remaining))
        self._buffered_bytes += len(chunk)
        return chunk

    def read(self, size, layer=LAYER_INPUT):
        """Return up to ``size`` bytes, serving buffered bytes first.

        The request size is always explicit and bounded.  Hitting the total
        budget raises :class:`LimitExceededError`; the underlying stream ending
        early simply returns fewer bytes (callers using :meth:`read_exact` turn
        that into the appropriate truncation error).
        """
        if size < 0:
            raise ValueError('bounded reads require an explicit, non-negative size')

        self._budget_hit = False
        self._buffered_bytes = 0
        result = bytearray()
        if self._pushback:
            take = min(size, len(self._pushback))
            result += self._pushback[:take]
            self._pushback = self._pushback[take:]
            size -= take

        while size > 0:
            chunk = self._raw_read(size)
            if not chunk:
                break
            result += chunk
            size -= len(chunk)

        data = bytes(result)
        self._offset += len(data)
        if size > 0 and (self._budget_hit or self._offset >= self.max_total):
            # report the budget boundary, which equals the consumed offset
            boundary = min(self._offset, self.max_total)
            raise LimitExceededError(
                'total input limit of %d bytes exceeded at offset %d'
                % (self.max_total, boundary), boundary, layer)
        return data

    def push_back(self, data):
        """Return bytes to the front of the stream (used for format sniffing)."""
        if data:
            self._pushback = data + self._pushback
            self._offset -= len(data)

    def read_exact(self, size, layer, truncated, offset=None):
        """Read exactly ``size`` bytes or raise a truncation error.

        ``truncated`` is the exception class to raise when the stream ends with
        fewer than ``size`` bytes available (:class:`TruncatedHeaderError` for a
        fixed header, :class:`TruncatedPayloadError` for a variable body).
        """
        if offset is None:
            offset = self._offset
        data = self.read(size, layer=layer)
        if len(data) < size:
            raise truncated(
                'expected %d bytes at offset %d but only %d were available'
                % (size, offset, len(data)), offset, layer)
        return data

    def read_header(self, size, layer, offset=None):
        return self.read_exact(size, layer, TruncatedHeaderError, offset)

    def read_body(self, size, layer, offset=None):
        return self.read_exact(size, layer, TruncatedPayloadError, offset)


class BoundedReader(object):
    """Bounded, pypcap-compatible reader for libpcap and single-section pcapng.

    Iterating yields ``(timestamp, packet_bytes)`` tuples, preserving the native
    time precision and link type of each format.  A truncated or hostile capture
    raises a :class:`CaptureError` subclass rather than silently yielding fewer
    packets.
    """

    def __init__(self, fileobj, max_packet=DEFAULT_MAX_PACKET,
                 max_block=DEFAULT_MAX_BLOCK, max_total=DEFAULT_MAX_TOTAL):
        self.name = getattr(fileobj, 'name',
                            '<%s>' % fileobj.__class__.__name__)
        self._stream = BoundedStream(fileobj, max_total=max_total)
        self.max_packet = max_packet
        self.max_block = max_block
        self.max_total = max_total

        magic = self._sniff_magic()
        if magic in pcap.MAGIC_TO_PKT_HDR:
            self._format = 'pcap'
            self._init_pcap(magic)
        elif magic == pcapng.PCAPNG_BT_SHB:
            self._format = 'pcapng'
            self._init_pcapng()
        else:
            raise CaptureFormatError(
                'unknown capture magic 0x%08x at offset 0' % magic,
                0, LAYER_FILE_HEADER)

        self.filter = ''
        self.__iter = iter(self)

    # ------------------------------------------------------------------
    # Public, pypcap-compatible surface
    # ------------------------------------------------------------------
    def datalink(self):
        return self._linktype

    def setfilter(self, value, optimize=1):
        raise NotImplementedError

    def readpkts(self):
        return list(self)

    def __next__(self):
        return next(self.__iter)
    next = __next__  # Python 2 compatibility

    def dispatch(self, cnt, callback, *args):
        processed = 0
        if cnt > 0:
            for _ in range(cnt):
                try:
                    ts, pkt = next(self.__iter)
                except StopIteration:
                    break
                callback(ts, pkt, *args)
                processed += 1
        else:
            for ts, pkt in self:
                callback(ts, pkt, *args)
                processed += 1
        return processed

    def loop(self, callback, *args):
        self.dispatch(0, callback, *args)

    def __iter__(self):
        if self._format == 'pcap':
            return self._iter_pcap()
        return self._iter_pcapng()

    # ------------------------------------------------------------------
    # Format detection
    # ------------------------------------------------------------------
    def _sniff_magic(self):
        head = self._stream.read(4, layer=LAYER_FILE_HEADER)
        if not head:
            raise TruncatedHeaderError(
                'empty capture: missing file header at offset 0',
                0, LAYER_FILE_HEADER)
        if len(head) < 4:
            raise TruncatedHeaderError(
                'incomplete file magic: only %d of 4 bytes at offset 0'
                % len(head), 0, LAYER_FILE_HEADER)
        magic = struct_unpack('>I', head)[0]
        self._stream.push_back(head)
        return magic

    # ------------------------------------------------------------------
    # Classic libpcap
    # ------------------------------------------------------------------
    def _init_pcap(self, magic):
        stream = self._stream
        raw_file_hdr = stream.read_header(
            pcap.FileHdr.__hdr_len__, LAYER_FILE_HEADER)

        if magic in (pcap.PMUDPCT_MAGIC, pcap.PMUDPCT_MAGIC_NANO,
                     pcap.PACPDOM_MAGIC):
            file_hdr = pcap.LEFileHdr(raw_file_hdr)
        else:
            file_hdr = pcap.FileHdr(raw_file_hdr)

        self._linktype = file_hdr.linktype
        self.dloff = pcap.dltoff.get(self._linktype, 0)
        self.snaplen = file_hdr.snaplen
        self._pkt_hdr_cls = pcap.MAGIC_TO_PKT_HDR[magic]
        self._pkt_hdr_len = self._pkt_hdr_cls.__hdr_len__
        if magic in (pcap.TCPDUMP_MAGIC_NANO, pcap.PMUDPCT_MAGIC_NANO):
            self._divisor = Decimal('1E9')
        else:
            self._divisor = 1000000

    def _iter_pcap(self):
        stream = self._stream
        while True:
            record_offset = stream.offset
            head = stream.read(self._pkt_hdr_len, layer=LAYER_PACKET_HEADER)
            if not head:
                return  # clean end of file, exactly on a record boundary
            if len(head) < self._pkt_hdr_len:
                raise TruncatedHeaderError(
                    'pcap packet header needs %d bytes but %d were available '
                    'at offset %d' % (self._pkt_hdr_len, len(head),
                                      record_offset),
                    record_offset, LAYER_PACKET_HEADER)

            hdr = self._pkt_hdr_cls(head)
            caplen = struct_unpack(
                self._pkt_hdr_cls.__hdr_fmt__[0] + 'I', head[8:12])[0]
            if caplen > self.max_packet:
                raise LimitExceededError(
                    'pcap caplen %d at offset %d exceeds packet limit %d'
                    % (caplen, record_offset, self.max_packet),
                    record_offset, LAYER_PACKET_PAYLOAD)

            payload = stream.read_body(caplen, LAYER_PACKET_PAYLOAD,
                                       offset=record_offset)
            timestamp = hdr.tv_sec + (hdr.tv_usec / self._divisor)
            yield (timestamp, payload)
    # ------------------------------------------------------------------
    # pcapng (single section)
    # ------------------------------------------------------------------
    def _init_pcapng(self):
        stream = self._stream
        shb_offset = stream.offset
        head = stream.read_header(8, LAYER_SECTION, offset=shb_offset)
        # Byte order is resolved from the byte-order magic inside the body.
        self._little_endian = self._detect_endianness(head, shb_offset)
        endian = '<' if self._little_endian else '>'
        _, block_total = struct_unpack(endian + 'II', head)

        if block_total < 12:
            raise CaptureFormatError(
                'pcapng block length %d at offset %d is smaller than the 12 '
                'byte minimum' % (block_total, shb_offset),
                shb_offset, LAYER_SECTION)
        if block_total > self.max_block:
            raise LimitExceededError(
                'pcapng block length %d at offset %d exceeds block limit %d'
                % (block_total, shb_offset, self.max_block),
                shb_offset, LAYER_SECTION)

        body = stream.read_body(block_total - 8, LAYER_BLOCK_BODY,
                                offset=shb_offset)
        block = head + body
        try:
            shb = (pcapng.SectionHeaderBlockLE(block)
                   if self._little_endian
                   else pcapng.SectionHeaderBlock(block))
        except dpkt.UnpackError as exc:
            raise CaptureFormatError(
                'malformed section header block at offset %d: %s'
                % (shb_offset, exc), shb_offset, LAYER_SECTION)

        if shb.v_major != pcapng.PCAPNG_VERSION_MAJOR:
            raise CaptureFormatError(
                'unsupported pcapng version %d.%d at offset %d'
                % (shb.v_major, shb.v_minor, shb_offset),
                shb_offset, LAYER_SECTION)

        idb = self._read_first_idb()
        self._linktype = idb.linktype
        self.dloff = pcapng.dltoff.get(self._linktype, 0)
        self.snaplen = idb.snaplen

        self._divisor = 1000000
        self._tsoffset = 0
        for opt in idb.opts:
            if opt.code == pcapng.PCAPNG_OPT_IF_TSRESOL:
                opt_val = struct_unpack('b', opt.data)[0]
                base = 2 if opt_val & 0b10000000 else 10
                self._divisor = base ** (opt_val & 0b01111111)
            elif opt.code == pcapng.PCAPNG_OPT_IF_TSOFFSET:
                self._tsoffset = struct_unpack(
                    '<q' if self._little_endian else '>q', opt.data)[0]

    def _detect_endianness(self, generic_head, offset):
        # The byte-order magic lives at bytes 8..12 of the SHB body.
        bom_head = self._stream.read_header(4, LAYER_SECTION, offset=offset + 8)
        bom = struct_unpack('>I', bom_head)[0]
        self._stream.push_back(bom_head)
        if bom == pcapng.BYTE_ORDER_MAGIC_LE:
            return True
        if bom == pcapng.BYTE_ORDER_MAGIC:
            return False
        raise CaptureFormatError(
            'unknown pcapng byte-order magic 0x%08x at offset %d'
            % (bom, offset + 8), offset + 8, LAYER_SECTION)

    def _read_block_header(self):
        """Return ``(offset, block_type, block_total)`` for the next block."""
        stream = self._stream
        offset = stream.offset
        head = stream.read(8, layer=LAYER_BLOCK_HEADER)
        if not head:
            return None
        if len(head) < 8:
            raise TruncatedHeaderError(
                'pcapng block header needs 8 bytes but %d were available at '
                'offset %d' % (len(head), offset),
                offset, LAYER_BLOCK_HEADER)

        endian = '<' if self._little_endian else '>'
        block_type, block_total = struct_unpack(endian + 'II', head)
        if block_total < 12:
            raise CaptureFormatError(
                'pcapng block length %d at offset %d is smaller than the 12 '
                'byte minimum' % (block_total, offset),
                offset, LAYER_BLOCK_HEADER)
        if block_total > self.max_block:
            raise LimitExceededError(
                'pcapng block length %d at offset %d exceeds block limit %d'
                % (block_total, offset, self.max_block),
                offset, LAYER_BLOCK_HEADER)
        return offset, block_type, block_total, head

    def _read_first_idb(self):
        while True:
            header = self._read_block_header()
            if header is None:
                raise CaptureFormatError(
                    'pcapng section has no interface description block',
                    self._stream.offset, LAYER_INTERFACE)
            offset, block_type, block_total, head = header
            body = self._stream.read_body(block_total - 8,
                                          LAYER_BLOCK_BODY, offset=offset)
            if block_type == pcapng.PCAPNG_BT_IDB:
                try:
                    return (pcapng.InterfaceDescriptionBlockLE(head + body)
                            if self._little_endian
                            else pcapng.InterfaceDescriptionBlock(head + body))
                except dpkt.UnpackError as exc:
                    raise CaptureFormatError(
                        'malformed interface description block at offset %d: %s'
                        % (offset, exc), offset, LAYER_INTERFACE)
            # Other blocks may legally precede the first IDB; skip them.

    def _iter_pcapng(self):
        stream = self._stream
        endian = '<' if self._little_endian else '>'
        while True:
            header = self._read_block_header()
            if header is None:
                return  # clean end of file on a block boundary
            offset, block_type, block_total, head = header

            if block_type == pcapng.PCAPNG_BT_SHB:
                raise CaptureFormatError(
                    'multiple sections are not supported; second section header '
                    'at offset %d' % offset, offset, LAYER_SECTION)

            if block_type not in (pcapng.PCAPNG_BT_EPB, pcapng.PCAPNG_BT_PB):
                # Skip blocks that carry no packets (IDB, SPB, options, ...).
                stream.read_body(block_total - 8, LAYER_BLOCK_BODY,
                                 offset=offset)
                continue

            # The fixed EPB/PB header follows the 8-byte generic block head and
            # is 20 bytes; caplen is its last-but-one uint32 (offset 12..16).
            # Read it before the body so an oversized caplen is rejected first.
            fixed = stream.read_header(20, LAYER_BLOCK_HEADER, offset=offset)
            caplen = struct_unpack(endian + 'I', fixed[12:16])[0]
            if caplen > self.max_packet:
                raise LimitExceededError(
                    'pcapng caplen %d at offset %d exceeds packet limit %d'
                    % (caplen, offset, self.max_packet),
                    offset, LAYER_PACKET_PAYLOAD)

            remaining = block_total - 8 - 20
            rest = stream.read_body(remaining, LAYER_BLOCK_BODY,
                                    offset=offset)
            block = head + fixed + rest
            if block_type == pcapng.PCAPNG_BT_EPB:
                block_cls = (pcapng.EnhancedPacketBlockLE
                             if self._little_endian
                             else pcapng.EnhancedPacketBlock)
            else:
                block_cls = (pcapng.PacketBlockLE
                             if self._little_endian
                             else pcapng.PacketBlock)
            try:
                packet_block = block_cls(block)
            except dpkt.UnpackError as exc:
                raise CaptureFormatError(
                    'malformed packet block at offset %d: %s' % (offset, exc),
                    offset, LAYER_BLOCK_BODY)

            timestamp = self._tsoffset + (
                ((packet_block.ts_high << 32) | packet_block.ts_low)
                / self._divisor)
            yield (timestamp, packet_block.pkt_data)


################################################################################
#                                    TESTS                                     #
################################################################################

class RecordingStream(object):
    """Non-seekable stream that returns at most ``chunk`` bytes per ``read``.

    It records every requested size so tests can prove that no read ever asks
    for an unbounded amount of data, even when a length field is malicious.
    """

    def __init__(self, data, chunk=1):
        self._data = bytes(data)
        self._pos = 0
        self.chunk = chunk
        self.read_requests = []
        self.name = '<RecordingStream>'

    def read(self, size):
        self.read_requests.append(size)
        if size is None or size < 0:
            raise AssertionError('reader issued an unbounded read')
        available = min(size, self.chunk, len(self._data) - self._pos)
        out = self._data[self._pos:self._pos + available]
        self._pos += available
        return out

    def seek(self, *args):
        raise AssertionError('the bounded reader must never seek')


def _pcap_bytes(packets, nano=False, linktype=pcap.DLT_EN10MB):
    from .compat import BytesIO
    fobj = BytesIO()
    writer = pcap.Writer(fobj, linktype=linktype, nano=nano)
    writer.writepkts(packets)
    return fobj.getvalue()


def _pcapng_bytes(packets, linktype=pcap.DLT_EN10MB, tsresol=None):
    from .compat import BytesIO
    fobj = BytesIO()
    idb_opts = []
    if tsresol is not None:
        idb_opts.append(pcapng.PcapngOptionLE(
            code=pcapng.PCAPNG_OPT_IF_TSRESOL, data=bytes(bytearray([tsresol]))))
    idb_opts.append(pcapng.PcapngOptionLE())
    idb = pcapng.InterfaceDescriptionBlockLE(
        snaplen=1500, linktype=linktype, opts=idb_opts)
    shb = pcapng.SectionHeaderBlockLE(opts=[pcapng.PcapngOptionLE()])
    # Writer emits the SHB/IDB itself; reuse it so blocks are not duplicated
    writer = pcapng.Writer(fobj, shb=shb, idb=idb)
    writer.writepkts(packets)
    return fobj.getvalue()


PACKETS = [
    (1454725786.526401, b'alpha' * 20),
    (1454725787.000002, b'bravo'),
    (1454725788.25, b'charlie' * 47),
]


def pack_le_block(block_type, total_len, body):
    from struct import pack
    head = pack('<II', block_type, total_len)
    tail = pack('<I', total_len)
    return head + body + tail


def test_bounded_stream_records_and_clamps_requests():
    inner = RecordingStream(b'abcdefghij', chunk=3)
    stream = BoundedStream(inner, max_total=1024)
    assert stream.read(4) == b'abcd'
    assert stream.read(4) == b'efgh'
    assert stream.read(4) == b'ij'
    # the parser-level request (4) is forwarded, but no request ever exceeds it
    assert max(inner.read_requests) <= 4
    assert all(req > 0 for req in inner.read_requests)

    # the total budget backstop never reads past the budget
    guard_inner = RecordingStream(b'x' * 100, chunk=50)
    guard = BoundedStream(guard_inner, max_total=10)
    try:
        guard.read(50)
    except LimitExceededError as exc:
        assert exc.layer == LAYER_INPUT
        assert exc.offset == 10
    else:
        raise AssertionError('total limit was not enforced')
    # the only underlying request was clamped down to the 10-byte budget
    assert guard_inner.read_requests == [10]


def test_bounded_stream_read_exact_distinguishes_header_and_payload():
    guard = BoundedStream(RecordingStream(b'abc', chunk=1))
    try:
        guard.read_header(8, LAYER_PACKET_HEADER)
    except TruncatedHeaderError as exc:
        assert exc.offset == 0
        assert exc.layer == LAYER_PACKET_HEADER
    else:
        raise AssertionError('expected TruncatedHeaderError')

    guard = BoundedStream(RecordingStream(b'abc', chunk=1))
    try:
        guard.read_body(8, LAYER_PACKET_PAYLOAD, offset=40)
    except TruncatedPayloadError as exc:
        assert exc.offset == 40
        assert exc.layer == LAYER_PACKET_PAYLOAD
    else:
        raise AssertionError('expected TruncatedPayloadError')


def test_pcap_short_read_invariance():
    from .compat import BytesIO
    data = _pcap_bytes(PACKETS)
    reference = list(pcap.Reader(BytesIO(data)))

    sequences = {}
    for chunk in (1, 2, 3, 5, 7, 16, 64, 4096):
        reader = BoundedReader(RecordingStream(data, chunk))
        sequences[chunk] = list(reader)
        assert sequences[chunk] == reference
    # every short-read partitioning yields the identical packet sequence
    assert all(seq == sequences[1] for seq in sequences.values())


def test_pcapng_short_read_invariance():
    from .compat import BytesIO
    data = pcapng.define_testdata().valid_pcapng
    reference = list(pcapng.Reader(BytesIO(data)))

    for chunk in (1, 2, 3, 7, 11, 100, 999):
        reader = BoundedReader(RecordingStream(data, chunk))
        assert list(reader) == reference


def test_never_issues_unbounded_or_oversized_read():
    data = _pcap_bytes(PACKETS)
    raw = RecordingStream(data, chunk=1)
    reader = BoundedReader(raw, max_packet=1024)
    list(reader)
    # header sizes and the packet cap are the only legal request magnitudes
    assert all(isinstance(size, int) and 0 < size <= 1024
               for size in raw.read_requests)


def test_pcap_preserves_precision_and_linktype():
    from .compat import BytesIO
    from decimal import Decimal

    micro = _pcap_bytes([(1454725786.526401, b'foo')])
    assert list(BoundedReader(RecordingStream(micro, 3))) == \
        list(pcap.Reader(BytesIO(micro)))

    nano = _pcap_bytes([(Decimal('1454725786.010203045'), b'foo')], nano=True)
    nano_packets = list(BoundedReader(RecordingStream(nano, 3)))
    assert nano_packets == list(pcap.Reader(BytesIO(nano)))
    assert isinstance(nano_packets[0][0], Decimal)

    raw = _pcap_bytes([(1.0, b'foo')], linktype=pcap.DLT_LOOP)
    loop_reader = BoundedReader(RecordingStream(raw, 5))
    assert loop_reader.datalink() == pcap.DLT_LOOP
    assert loop_reader.dloff == pcap.dltoff[pcap.DLT_LOOP]


def test_pcapng_preserves_precision_and_linktype():
    from .compat import BytesIO

    # default microsecond resolution
    micro = _pcapng_bytes([(1454725787.5, b'foo')])
    assert list(BoundedReader(RecordingStream(micro, 4))) == \
        list(pcapng.Reader(BytesIO(micro)))

    # TSRESOL = 9 declares nanosecond ticks; the writer still emits microsecond
    # tick counts, so the reader must interpret those ticks at 1e-9 resolution.
    nano = _pcapng_bytes([(1454725787.5, b'foo')], tsresol=9)
    nano_reader = BoundedReader(RecordingStream(nano, 4))
    ts, _ = next(iter(nano_reader))
    assert ts == 1454725.7875  # 1454725787500000 ticks / 1e9

    raw = _pcapng_bytes([(1.0, b'foo')], linktype=pcapng.DLT_LINUX_SLL)
    sll_reader = BoundedReader(RecordingStream(raw, 5))
    assert sll_reader.datalink() == pcapng.DLT_LINUX_SLL
    assert sll_reader.dloff == pcapng.dltoff[pcapng.DLT_LINUX_SLL]


def test_clean_eof_is_not_an_error():
    data = _pcap_bytes(PACKETS)
    reader = BoundedReader(RecordingStream(data, 7))
    assert len(list(reader)) == len(PACKETS)

    ng = pcapng.define_testdata().valid_pcapng
    assert len(list(BoundedReader(RecordingStream(ng, 7)))) == 1


def _expect_error(label, blob, error_type, offset, layer, **kwargs):
    try:
        reader = BoundedReader(RecordingStream(blob, 1), **kwargs)
        list(reader)
    except CaptureError as exc:
        assert isinstance(exc, error_type), (label, exc)
        assert exc.offset == offset, (label, 'offset', exc.offset, offset)
        assert exc.layer == layer, (label, 'layer', exc.layer, layer)
        return exc
    raise AssertionError('%s: expected %s but parsing succeeded' % (label, error_type.__name__))


def test_pcap_truncation_reports_offset_and_layer():
    single = _pcap_bytes([(1.0, b'q' * 32)])
    payload_offset = pcap.FileHdr.__hdr_len__ + pcap.PktHdr.__hdr_len__

    _expect_error('empty', b'', TruncatedHeaderError, 0, LAYER_FILE_HEADER)
    _expect_error('half magic', single[:2], TruncatedHeaderError, 0,
                  LAYER_FILE_HEADER)
    _expect_error('half file header', single[:10], TruncatedHeaderError, 0,
                  LAYER_FILE_HEADER)
    _expect_error('half packet header', single[:27], TruncatedHeaderError, 24,
                  LAYER_PACKET_HEADER)
    _expect_error('short payload', single[:-3], TruncatedPayloadError,
                  24, LAYER_PACKET_PAYLOAD)
    _expect_error('bad magic', b'\x42' * 24, CaptureFormatError, 0,
                  LAYER_FILE_HEADER)
    assert payload_offset == 40


def test_pcapng_truncation_reports_offset_and_layer():
    shb = pcapng.SectionHeaderBlockLE(opts=[pcapng.PcapngOptionLE()])
    idb = pcapng.InterfaceDescriptionBlockLE(
        snaplen=1500, linktype=1, opts=[pcapng.PcapngOptionLE()])
    epb = pcapng.EnhancedPacketBlockLE(pkt_data=b'ng-pkt-data')
    shb_b, idb_b, epb_b = bytes(shb), bytes(idb), bytes(epb)
    epb_offset = len(shb_b) + len(idb_b)
    data = shb_b + idb_b + epb_b

    _expect_error('ng empty', b'', TruncatedHeaderError, 0, LAYER_FILE_HEADER)
    _expect_error('ng half shb', data[:4], TruncatedHeaderError, 0,
                  LAYER_SECTION)
    _expect_error('ng shb body cut', data[:20], TruncatedPayloadError, 0,
                  LAYER_BLOCK_BODY)
    _expect_error('ng no idb', shb_b, CaptureFormatError, len(shb_b),
                  LAYER_INTERFACE)
    _expect_error('ng idb cut', shb_b + idb_b[:9], TruncatedPayloadError,
                  len(shb_b), LAYER_BLOCK_BODY)
    _expect_error('ng half block header', shb_b + idb_b + b'\x06\x00\x00',
                  TruncatedHeaderError, epb_offset, LAYER_BLOCK_HEADER)
    _expect_error('ng epb body cut', data[:-3], TruncatedPayloadError,
                  epb_offset, LAYER_BLOCK_BODY)
    _expect_error('ng second section', data + shb_b, CaptureFormatError,
                  len(data), LAYER_SECTION)


def test_pcap_packet_limit_rejects_malicious_caplen():
    from struct import pack
    data = _pcap_bytes(PACKETS)
    # overwrite the little-endian caplen/len of the first packet header
    evil = data[:24 + 8] + pack('<II', 0x7fffffff, 0x7fffffff) + b'abc'
    raw = RecordingStream(evil, 1)
    try:
        list(BoundedReader(raw, max_packet=65535))
    except LimitExceededError as exc:
        assert exc.offset == 24
        assert exc.layer == LAYER_PACKET_PAYLOAD
    else:
        raise AssertionError('malicious caplen was accepted')
    # the giant caplen must never have been requested from the stream
    assert max(raw.read_requests) <= 65535


def test_pcapng_block_and_packet_limits():
    from struct import pack
    shb = pcapng.SectionHeaderBlockLE(opts=[pcapng.PcapngOptionLE()])
    idb = pcapng.InterfaceDescriptionBlockLE(
        snaplen=1500, linktype=1, opts=[pcapng.PcapngOptionLE()])
    epb = pcapng.EnhancedPacketBlockLE(pkt_data=b'ng-pkt-data')
    shb_b, idb_b, epb_b = bytes(shb), bytes(idb), bytes(epb)
    epb_offset = len(shb_b) + len(idb_b)

    # inflate the block total-length field in the EPB header
    evil_block = epb_b[:4] + pack('<I', 0x00400000) + epb_b[8:]
    _expect_error('ng evil block len', shb_b + idb_b + evil_block,
                  LimitExceededError, epb_offset, LAYER_BLOCK_HEADER,
                  max_block=1 << 20)

    # inflate the EPB caplen: fixed header starts after the 8-byte generic head
    # and its caplen uint32 sits at block offset 20..24
    evil_cap = epb_b[:20] + pack('<I', 0x100000) + epb_b[24:]
    raw_blob = shb_b + idb_b + evil_cap
    raw = RecordingStream(raw_blob, 1)
    try:
        list(BoundedReader(raw, max_packet=65535, max_total=1 << 26))
    except LimitExceededError as exc:
        assert exc.offset == epb_offset
        assert exc.layer == LAYER_PACKET_PAYLOAD
    else:
        raise AssertionError('malicious caplen was accepted')
    # the inflated caplen is never requested from the underlying stream
    assert max(raw.read_requests) <= 1 << 22


def test_total_input_limit():
    data = _pcap_bytes(PACKETS)
    # the 24-byte file header leaves 6 bytes of the 30-byte budget, so the
    # 16-byte first packet header cannot complete and the budget is rejected.
    _expect_error('pcap total limit', data, LimitExceededError, 30,
                  LAYER_PACKET_HEADER, max_total=30)


def test_skips_non_packet_pcapng_blocks():
    from .compat import BytesIO
    from struct import pack
    # a Simple Packet Block (type 3) carries no parsed packet and must be skipped
    spb_payload = b's' * 16
    spb_len = 12 + 4 + pcapng._align32b(len(spb_payload))
    spb = pack_le_block(pcapng.PCAPNG_BT_SPB, spb_len,
                        pack('<I', len(spb_payload)) +
                        spb_payload + b'\x00' * pcapng._padlen(spb_payload))
    shb = pcapng.SectionHeaderBlockLE(opts=[pcapng.PcapngOptionLE()])
    idb = pcapng.InterfaceDescriptionBlockLE(
        snaplen=1500, linktype=1, opts=[pcapng.PcapngOptionLE()])
    epb = pcapng.EnhancedPacketBlockLE(pkt_data=b'keep-me')
    blob = bytes(shb) + bytes(idb) + spb + bytes(epb)

    reader = BoundedReader(RecordingStream(blob, 3))
    packets = list(reader)
    assert [pkt for _, pkt in packets] == [b'keep-me']
    # the streaming reader agrees with the reference pcapng reader
    assert packets == list(pcapng.Reader(BytesIO(blob)))


def test_dispatch_and_loop_count_packets():
    data = _pcap_bytes(PACKETS)
    reader = BoundedReader(RecordingStream(data, 5))
    seen = []
    assert reader.dispatch(0, lambda ts, pkt: seen.append(pkt)) == len(PACKETS)
    assert len(seen) == len(PACKETS)

    reader = BoundedReader(RecordingStream(data, 5))
    assert reader.dispatch(2, lambda ts, pkt: None) == 2
    assert reader.dispatch(2, lambda ts, pkt: None) == 1

    reader = BoundedReader(RecordingStream(data, 5))
    counter = {'n': 0}
    reader.loop(lambda ts, pkt: counter.__setitem__('n', counter['n'] + 1))
    assert counter['n'] == len(PACKETS)


def test_setfilter_not_supported_and_name():
    reader = BoundedReader(RecordingStream(_pcap_bytes(PACKETS), 4))
    assert reader.name == '<RecordingStream>'
    try:
        reader.setfilter('tcp')
    except NotImplementedError:
        pass
    else:
        raise AssertionError('setfilter should be unsupported')


def _be_pcapng_bytes(packets):
    from .compat import BytesIO
    fobj = BytesIO()
    idb = pcapng.InterfaceDescriptionBlock(
        snaplen=1500, linktype=1, opts=[pcapng.PcapngOption()])
    shb = pcapng.SectionHeaderBlock(opts=[pcapng.PcapngOption()])
    writer = pcapng.Writer.__new__(pcapng.Writer)
    writer._Writer__f = fobj
    writer._kls = pcapng.EnhancedPacketBlock
    writer._precision_multiplier = 1000000
    fobj.write(bytes(shb))
    fobj.write(bytes(idb))
    for ts, pkt in packets:
        ticks = pcapng.intround(ts * 1000000)
        epb = pcapng.EnhancedPacketBlock(
            ts_high=ticks >> 32,
            ts_low=ticks & 0xffffffff,
            pkt_data=pkt)
        fobj.write(bytes(epb))
    return fobj.getvalue()


def test_big_endian_captures_match_reference():
    from .compat import BytesIO

    # big-endian classic pcap built directly from the header classes
    file_hdr = pcap.FileHdr(snaplen=1500, linktype=pcap.DLT_EN10MB,
                            magic=pcap.TCPDUMP_MAGIC)
    pkt_hdr = pcap.PktHdr()
    be_pcap = bytes(file_hdr)
    for ts, pkt in PACKETS:
        be_pcap += pkt_hdr._pack_hdr(
            int(ts), int((ts % 1) * 1000000), len(pkt), len(pkt)) + pkt
    assert list(BoundedReader(RecordingStream(be_pcap, 3))) == \
        list(pcap.Reader(BytesIO(be_pcap)))

    be_ng = _be_pcapng_bytes([(1454725787.5, b'foo'), (1454725788.25, b'bar')])
    assert list(BoundedReader(RecordingStream(be_ng, 3))) == \
        list(pcapng.Reader(BytesIO(be_ng)))


def test_modified_pcap_with_extended_header():
    from .compat import BytesIO
    # the modified pcap variant uses a 24-byte packet header (PktModHdr)
    data = pcap.TestData.modified_pcap
    bounded_packets = list(BoundedReader(RecordingStream(data, 5)))
    reference_packets = list(pcap.Reader(BytesIO(data)))
    assert bounded_packets == reference_packets


def test_stream_offset_accounting_tracks_file_length():
    pcap_data = _pcap_bytes(PACKETS)
    reader = BoundedReader(RecordingStream(pcap_data, 7))
    list(reader)
    assert reader._stream.offset == len(pcap_data)

    ng = pcapng.define_testdata().valid_pcapng
    ng_reader = BoundedReader(RecordingStream(ng, 7))
    list(ng_reader)
    assert ng_reader._stream.offset == len(ng)


def test_pcapng_trailing_length_mismatch_is_an_error():
    shb = pcapng.SectionHeaderBlockLE(opts=[pcapng.PcapngOptionLE()])
    idb = pcapng.InterfaceDescriptionBlockLE(
        snaplen=1500, linktype=1, opts=[pcapng.PcapngOptionLE()])
    epb = pcapng.EnhancedPacketBlockLE(pkt_data=b'ng-pkt-data')
    blob = bytearray(bytes(shb) + bytes(idb) + bytes(epb))
    epb_offset = len(bytes(shb)) + len(bytes(idb))
    blob[-1] ^= 0xFF  # corrupt the trailing duplicate length of the last block

    _expect_error('length mismatch', bytes(blob), CaptureFormatError,
                  epb_offset, LAYER_BLOCK_BODY)


def test_pcapng_deprecated_packet_block_parity():
    from .compat import BytesIO
    shb = pcapng.SectionHeaderBlockLE(opts=[pcapng.PcapngOptionLE()])
    idb = pcapng.InterfaceDescriptionBlockLE(
        snaplen=1500, linktype=1, opts=[pcapng.PcapngOptionLE()])
    pb = pcapng.PacketBlockLE(pkt_data=b'pb-payload')
    blob = bytes(shb) + bytes(idb) + bytes(pb)
    assert list(BoundedReader(RecordingStream(blob, 2))) == \
        list(pcapng.Reader(BytesIO(blob)))

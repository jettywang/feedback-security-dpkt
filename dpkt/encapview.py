# -*- coding: utf-8 -*-
"""Offline encapsulation (tunnel) view.

The default :class:`~dpkt.dpkt.Packet` decoders expose a packet as a nested
``data`` chain and silently leave anything they cannot dispatch as raw
``bytes``.  After several layers of tunnelling (for example
``Ethernet -> VLAN -> IP -> GRE -> IP -> TCP``) only the innermost addresses
survive, so an alert can no longer explain which outer link delivered the
frame, and there is no easy way to map a decoded field back to the exact
offset it occupied on the wire.

This module provides a *separate, read-only* view that walks the encapsulation
stack in wire order and records, for every confirmed layer, the protocol and
the original byte range it occupies.  It reuses the existing protocol classes
and their dispatch tables -- no new protocol decoders are introduced.

Design rules, important for security use:

* A layer is only added once its header has actually been confirmed against
  the bytes present.  Payload whose declared protocol is unknown or whose
  bytes are too short is *not* force-decoded; in particular a payload is never
  treated as IP just because its first byte happens to look like ``0x45``.
* On truncation, an unknown protocol or the encapsulation-depth limit every
  layer confirmed so far is kept and the view is marked :attr:`EncapView.incomplete`
  with an explanatory :attr:`EncapView.reason`.
* Ranges are always ``(start, end)`` half-open offsets into the original
  buffer, so a rule that matches a field can point at the exact wire bytes.
* Nothing here changes the normal ``Ethernet(buf)`` style decoding; the two
  can be used independently.
"""
from __future__ import absolute_import

import struct

from . import dpkt
from . import ethernet
from . import gre as gre_mod
from . import ip as ip_mod
from . import tcp as tcp_mod
from . import udp

#: Termination reason codes (also exposed as human-readable attributes below).
UNKNOWN_PROTOCOL = 'unknown_protocol'
TRUNCATED = 'truncated'
DEPTH_LIMIT = 'depth_limit'
MALFORMED = 'malformed'
FRAGMENTED = 'fragmented'

#: Maximum number of confirmed layers before the walk stops, so a packet that
#: nests tunnels forever cannot run away.  Confirmed layers are retained.
DEFAULT_MAX_DEPTH = 16

# Layer name constants, in addition to ``Packet.__class__.__name__``.
ETHERNET = 'Ethernet'
VLAN = 'VLAN'
IP = 'IP'
GRE = 'GRE'
TRANSPORTS = ('TCP', 'UDP', 'ICMP', 'SCTP')

# Dispatch tables reused from the existing decoders -- nothing is duplicated.
_ETH_TYPESW = ethernet.Ethernet._typesw
_IP_PROTOSW = ip_mod.IP._protosw

_QINQ_TYPES = ethernet._ETH_TYPES_QINQ


class Layer(object):
    """One confirmed encapsulation layer.

    Attributes:
        index: Zero-based position of the layer in wire order.
        name: Protocol name (e.g. ``'Ethernet'``, ``'VLAN'``, ``'IP'``,
            ``'GRE'``, ``'TCP'``).
        packet: The decoded :class:`~dpkt.dpkt.Packet`, or ``None`` for a VLAN
            helper layer (the individual tags are kept in :attr:`tags`).
        start: Inclusive start offset of the layer in the original buffer.
        end: Exclusive end offset of the layer's header in the original
            buffer.
        tags: Decoded :class:`~dpkt.ethernet.VLANtag8021Q` tags (VLAN only).
        next_type: The type/proto value that selected the following layer
            (EtherType for Ethernet/VLAN/GRE, IP protocol number for IP).
    """

    __slots__ = ('index', 'name', 'packet', 'start', 'end', 'tags',
                 'next_type')

    def __init__(self, index, name, start, end, packet=None, tags=None,
                 next_type=None):
        self.index = index
        self.name = name
        self.packet = packet
        self.start = start
        self.end = end
        self.tags = tags
        self.next_type = next_type

    @property
    def range(self):
        """The ``(start, end)`` half-open byte range in the original buffer."""
        return self.start, self.end

    def __repr__(self):
        return ('Layer(%d, %s, range=(%d, %d))'
                % (self.index, self.name, self.start, self.end))


class EncapView(object):
    """An ordered, byte-annotated view of a packet's encapsulation stack.

    Build it with :func:`encap_view` (or directly from a raw frame) and treat
    it as an immutable sequence of :class:`Layer` objects.  The walk stops at
    the first transport layer, or earlier when the packet is truncated, uses an
    unsupported protocol, or reaches :data:`DEFAULT_MAX_DEPTH`; in every case
    :attr:`incomplete` explains whether and why decoding ended early.
    """

    def __init__(self, buf, layers, incomplete, reason, remaining_offset,
                 remaining_bytes):
        self._buf = buf
        self._layers = list(layers)
        self.incomplete = incomplete
        self.reason = reason
        self.remaining_offset = remaining_offset
        self.remaining = remaining_bytes

    # -- sequence-ish helpers ------------------------------------------------
    def __iter__(self):
        return iter(self._layers)

    def __len__(self):
        return len(self._layers)

    def __getitem__(self, item):
        return self._layers[item]

    @property
    def layers(self):
        """The list of confirmed :class:`Layer` objects, outermost first."""
        return list(self._layers)

    def names(self):
        """Protocol names in wire order (e.g. ``['Ethernet', 'VLAN', ...]``)."""
        return [layer.name for layer in self._layers]

    def find(self, name):
        """Return the first layer called ``name`` (outermost match) or None."""
        for layer in self._layers:
            if layer.name == name:
                return layer
        return None

    def find_all(self, name):
        """Return every layer called ``name`` (outer to inner)."""
        return [layer for layer in self._layers if layer.name == name]

    @property
    def last(self):
        """The innermost confirmed layer, or ``None`` for an empty view."""
        return self._layers[-1] if self._layers else None

    def byte_range(self, layer):
        """Return the original bytes covered by a layer's confirmed header."""
        return self._buf[layer.start:layer.end]

    def __repr__(self):
        status = 'incomplete=%s reason=%s' % (self.incomplete, self.reason)
        return 'EncapView([%s], %s)' % (', '.join(self.names()), status)


def _need(buf, off, length):
    """True when ``length`` bytes are not available at ``off`` in ``buf``."""
    return off + length > len(buf)


def _fixed_header(klass, buf, off):
    """Decode only a protocol's fixed header, without touching its payload.

    The full ``klass(buf)`` constructors recursively unpack ``data`` and may
    raise :class:`~dpkt.dpkt.NeedData` purely because a following layer is
    short.  A confirmed layer must not depend on whatever comes after it, so
    the encapsulation walk decodes fixed headers in isolation and validates
    each next layer on its own bytes.
    """
    pkt = klass.__new__(klass)
    dpkt.Packet.unpack(pkt, buf[off:off + klass.__hdr_len__])
    return pkt


def _transport_class(proto):
    return _IP_PROTOSW.get(proto) if proto in (
        ip_mod.IP_PROTO_TCP, ip_mod.IP_PROTO_UDP,
        ip_mod.IP_PROTO_ICMP, ip_mod.IP_PROTO_SCTP) else None


def encap_view(buf, max_depth=DEFAULT_MAX_DEPTH):
    """Walk ``buf`` (an Ethernet frame) and return an :class:`EncapView`.

    The frame is parsed strictly and independently of the packet objects'
    own on-demand decoding.  Each confirmed layer records its original byte
    range so a match on an outer ingress or an inner target is traceable to
    the wire.

    Args:
        buf: Raw Ethernet frame as ``bytes``.
        max_depth: Cap on confirmed layers; reaching it ends the walk and
            marks the view incomplete with :data:`DEPTH_LIMIT`.

    Returns:
        EncapView
    """
    layers = []
    off = 0
    total = len(buf)

    def finish(why, remaining_off):
        remaining = buf[remaining_off:]
        return EncapView(buf, layers, why is not None, why,
                         remaining_off, remaining)

    # ---- 1. outer Ethernet -------------------------------------------------
    eth_hlen = ethernet.Ethernet.__hdr_len__
    if _need(buf, off, eth_hlen):
        return finish(TRUNCATED, off)
    eth = _fixed_header(ethernet.Ethernet, buf, off)
    eth_type = eth.type
    layers.append(Layer(len(layers), ETHERNET, off, off + eth_hlen,
                        packet=eth, next_type=eth_type))
    off += eth_hlen

    # ---- 2. 802.1Q / QinQ VLAN tags (only when the EtherType says so) ------
    if eth_type in _QINQ_TYPES:
        vlan_hlen = ethernet.VLANtag8021Q.__hdr_len__
        tag_start = off
        tags = []
        cur_type = eth_type
        # Ethernet itself decodes at most two tags; mirror that bound.
        while cur_type in _QINQ_TYPES and len(tags) < 2:
            if _need(buf, off, vlan_hlen):
                return finish(TRUNCATED, off)
            tag = _fixed_header(ethernet.VLANtag8021Q, buf, off)
            tags.append(tag)
            off += vlan_hlen
            cur_type = tag.type
        layers.append(Layer(len(layers), VLAN, tag_start, off, tags=tags,
                            next_type=cur_type))
        eth_type = cur_type

    # ---- 3. generic network/tunnel walk ------------------------------------
    # ``next_class`` is what the current layer declared should follow.
    # Nothing is inferred from raw payload resemblance.
    next_class = _ETH_TYPESW.get(eth_type)
    if next_class is None:
        return finish(UNKNOWN_PROTOCOL, off)

    while True:
        if len(layers) >= max_depth:
            return finish(DEPTH_LIMIT, off)

        klass = next_class

        # -- another Ethernet (e.g. GRE carrying Transparent Ethernet) -------
        if klass is ethernet.Ethernet:
            eth_hlen = ethernet.Ethernet.__hdr_len__
            if _need(buf, off, eth_hlen):
                return finish(TRUNCATED, off)
            inner_eth = _fixed_header(ethernet.Ethernet, buf, off)
            inner_type = inner_eth.type
            layers.append(Layer(len(layers), ETHERNET, off, off + eth_hlen,
                                packet=inner_eth, next_type=inner_type))
            off += eth_hlen
            next_class = _ETH_TYPESW.get(inner_type)
            if next_class is None:
                return finish(UNKNOWN_PROTOCOL, off)
            continue

        # -- IPv4 ------------------------------------------------------------
        if klass is ip_mod.IP:
            ip_hlen = ip_mod.IP.__hdr_len__
            if _need(buf, off, ip_hlen):
                return finish(TRUNCATED, off)
            version = buf[off] >> 4
            ihl_words = buf[off] & 0x0f
            if version != 4 or ihl_words < 5:
                return finish(MALFORMED, off)
            hdr_len = ihl_words << 2
            if _need(buf, off, hdr_len):
                return finish(TRUNCATED, off)
            ip = _fixed_header(ip_mod.IP, buf, off)
            # Recover the options bytes that live beyond the fixed header so
            # the stored object stays faithful to the wire.
            ip.opts = buf[off + ip_hlen:off + hdr_len]

            ip_start = off
            ip_end = off + hdr_len
            layers.append(Layer(len(layers), IP, ip_start, ip_end,
                                packet=ip, next_type=ip.p))
            off = ip_end

            # A fragmented datagram cannot be fully reconstructed offline: a
            # non-zero offset means the transport header sits in another
            # fragment, while MF on the first fragment means the payload is
            # incomplete.  Either way, stop after the confirmed IP header.
            if ip.offset != 0 or ip.mf:
                return finish(FRAGMENTED, off)

            # The declared total length must fit inside the captured bytes,
            # otherwise the payload (or part of it) is missing.
            if ip.len and off + (ip.len - hdr_len) > total:
                return finish(TRUNCATED, off)

            proto = ip.p
            transport = _transport_class(proto)
            if transport is not None:
                t_klass = transport
                t_len = t_klass.__hdr_len__
                # The fixed length is the minimum needed to confirm the layer.
                if _need(buf, off, t_len):
                    return finish(TRUNCATED, off)
                try:
                    t_pkt = t_klass(buf[off:])
                except dpkt.UnpackError:
                    return finish(MALFORMED, off)
                t_end = off + t_len
                if t_klass is tcp_mod.TCP:
                    # TCP's real header includes options (data offset field).
                    tcp_hlen = t_pkt.off << 2
                    if tcp_hlen < t_len or off + tcp_hlen > total:
                        return finish(TRUNCATED, off)
                    t_end = off + tcp_hlen
                layers.append(Layer(len(layers), t_klass.__name__, off,
                                    t_end, packet=t_pkt, next_type=None))
                return finish(None, t_end)

            nested = _IP_PROTOSW.get(proto)
            if nested is None:
                return finish(UNKNOWN_PROTOCOL, off)
            next_class = nested
            continue

        # -- GRE -------------------------------------------------------------
        if klass is gre_mod.GRE:
            gre_hlen = gre_mod.GRE.__hdr_len__
            if _need(buf, off, gre_hlen):
                return finish(TRUNCATED, off)
            try:
                gre = gre_mod.GRE(buf[off:])
            except dpkt.UnpackError:
                return finish(MALFORMED, off)
            # GRE's total header = fixed header + option fields + SREs.  Use
            # its public helpers rather than re-deriving the flag rules.
            _, fmts = gre.opt_fields_fmts()
            opt_fmt_len = struct.calcsize(''.join(fmts)) if fmts else 0
            gre_hdr_total = (gre_hlen + opt_fmt_len +
                             sum(map(len, gre.sre)))
            gre_end = off + gre_hdr_total
            if gre_end > total:
                return finish(TRUNCATED, off)
            # Store a header-only object so it does not reach into the payload.
            gre_hdr = _fixed_header(gre_mod.GRE, buf, off)
            for attr in ('sum', 'off', 'key', 'seq', 'ack', 'len',
                         'callid'):
                if hasattr(gre, attr):
                    setattr(gre_hdr, attr, getattr(gre, attr))
            gre_hdr.sre = gre.sre
            layers.append(Layer(len(layers), GRE, off, gre_end,
                                packet=gre_hdr, next_type=gre.p))
            off = gre_end
            payload_class = _ETH_TYPESW.get(gre.p)
            if payload_class is None:
                return finish(UNKNOWN_PROTOCOL, off)
            next_class = payload_class
            continue

        # -- any other protocol the dispatch table knows how to build --------
        # Only protocols explicitly handled above participate in tunnel
        # walking; an unrelated decoder must not be guessed at.
        return finish(UNKNOWN_PROTOCOL, off)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _vlan_ip_tcp():
    """Plain 802.1Q frame: Ethernet -> VLAN -> IP -> TCP."""
    tcp = tcp_mod.TCP(sport=1234, dport=80)
    tcp.data = b'GET / HTTP/1.0\r\n\r\n'
    ip = ip_mod.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
                   p=ip_mod.IP_PROTO_TCP, data=tcp)
    eth = ethernet.Ethernet(
        src=b'\x00\x11\x22\x33\x44\x55', dst=b'\x66\x77\x88\x99\xaa\xbb',
        vlan_tags=[ethernet.VLANtag8021Q(id=100)], data=ip)
    return bytes(eth)


def _gre_ip_udp():
    """Tunnel frame: Ethernet -> outer IP -> GRE -> inner IP -> UDP."""
    inner = ip_mod.IP(src=b'\x0a\x01\x00\x01', dst=b'\x0a\x01\x00\x02',
                      p=ip_mod.IP_PROTO_UDP,
                      data=udp.UDP(sport=5000, dport=53, data=b'\x12\x34dns'))
    gre = gre_mod.GRE(p=ethernet.ETH_TYPE_IP, data=inner)
    outer = ip_mod.IP(src=b'\xc0\xa8\x01\x01', dst=b'\xc0\xa8\x01\x02',
                      p=ip_mod.IP_PROTO_GRE, data=gre)
    eth = ethernet.Ethernet(
        src=b'\x00\x01\x02\x03\x04\x05', dst=b'\x0a\x0b\x0c\x0d\x0e\x0f',
        data=outer)
    return bytes(eth)


def _gre_truncated_inner():
    """Tunnel frame whose inner IP header is cut off (14 of 20 bytes)."""
    trunc_ip = bytes(ip_mod.IP(src=b'\x10\x00\x00\x01',
                               dst=b'\x10\x00\x00\x02',
                               p=ip_mod.IP_PROTO_TCP))[:14]
    gre = gre_mod.GRE(p=ethernet.ETH_TYPE_IP, data=trunc_ip)
    outer = ip_mod.IP(src=b'\xc0\xa8\x02\x01', dst=b'\xc0\xa8\x02\x02',
                      p=ip_mod.IP_PROTO_GRE, data=gre)
    eth = ethernet.Ethernet(
        src=b'\x11\x22\x33\x44\x55\x66', dst=b'\x77\x88\x99\xaa\xbb\xcc',
        data=outer)
    return bytes(eth)


def test_vlan_ip_tcp_path_and_ranges():
    buf = _vlan_ip_tcp()
    view = encap_view(buf)

    assert not view.incomplete
    assert view.reason is None
    assert view.names() == [ETHERNET, VLAN, IP, 'TCP']

    # every layer points at the exact bytes it occupies on the wire
    for layer in view:
        assert view.byte_range(layer) == buf[layer.start:layer.end]

    eth = view.find(ETHERNET)
    assert eth.range == (0, 14)
    assert eth.packet.dst == b'\x66\x77\x88\x99\xaa\xbb'

    vlan = view.find(VLAN)
    assert vlan.range == (14, 18)
    assert len(vlan.tags) == 1 and vlan.tags[0].id == 100
    assert vlan.next_type == ethernet.ETH_TYPE_IP

    ip = view.find(IP)
    assert ip.range == (18, 38)
    assert ip.packet.src == b'\x0a\x00\x00\x01'
    assert ip.packet.dst == b'\x0a\x00\x00\x02'

    tcp_layer = view.find('TCP')
    assert tcp_layer.start == 38
    assert tcp_layer.packet.dport == 80


def test_gre_tunnel_keeps_outer_and_inner_identity():
    buf = _gre_ip_udp()
    view = encap_view(buf)

    assert not view.incomplete
    assert view.names() == [ETHERNET, IP, GRE, IP, 'UDP']

    gre = view.find(GRE)
    assert gre.packet.p == ethernet.ETH_TYPE_IP
    assert gre.end == 38  # 14 eth + 20 outer ip + 4 gre

    outer_ip, inner_ip = view.find_all(IP)
    # the outer ingress link is still visible ...
    assert outer_ip.packet.src == b'\xc0\xa8\x01\x01'
    assert view.byte_range(outer_ip)[12:16] == b'\xc0\xa8\x01\x01'
    # ... alongside the inner target, each tied to its own wire location
    assert inner_ip.packet.dst == b'\x0a\x01\x00\x02'
    assert view.byte_range(inner_ip)[16:20] == b'\x0a\x01\x00\x02'
    assert outer_ip.start < inner_ip.start

    udp_layer = view.find('UDP')
    assert udp_layer.packet.dport == 53


def test_truncated_inner_is_incomplete_but_keeps_confirmed_path():
    buf = _gre_truncated_inner()
    view = encap_view(buf)

    assert view.incomplete
    assert view.reason == TRUNCATED
    # the confirmed outer path survives ...
    assert view.names() == [ETHERNET, IP, GRE]
    # ... and the unparseable tail is preserved, never force-decoded
    assert view.remaining == buf[view.remaining_offset:]
    assert len(view.remaining) == 14
    assert view.last.name == GRE


def test_unknown_payload_resembling_ip_is_not_decoded_as_ip():
    # GRE declares an EtherType the dispatch table cannot build, while the
    # payload's first byte happens to look like an IPv4 header (0x45).
    lookalike = b'\x45\x00\x00\x14' + b'\x00' * 16
    gre = gre_mod.GRE(p=ethernet.ETH_TYPE_LLDP, data=lookalike)
    outer = ip_mod.IP(src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08',
                      p=ip_mod.IP_PROTO_GRE, data=gre)
    buf = bytes(ethernet.Ethernet(data=outer))

    view = encap_view(buf)
    assert view.incomplete
    assert view.reason == UNKNOWN_PROTOCOL
    # only the outer IP exists; the 0x45 lookalike payload is never promoted
    # to a second (inner) IP layer
    assert view.names() == [ETHERNET, IP, GRE]
    assert len(view.find_all(IP)) == 1
    assert view.remaining == lookalike


def test_unknown_ethertype_stops_after_ethernet():
    buf = bytes(ethernet.Ethernet(type=0x9999, data=b'\x45' + b'\x00' * 20))
    view = encap_view(buf)
    assert view.reason == UNKNOWN_PROTOCOL
    assert view.names() == [ETHERNET]


def test_malformed_ip_version_is_flagged():
    bad_ip = b'\x65\x00\x00\x14' + b'\x00' * 16  # version 6 where IPv4 expected
    gre = gre_mod.GRE(p=ethernet.ETH_TYPE_IP, data=bad_ip)
    outer = ip_mod.IP(src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08',
                      p=ip_mod.IP_PROTO_GRE, data=gre)
    buf = bytes(ethernet.Ethernet(data=outer))

    view = encap_view(buf)
    assert view.reason == MALFORMED
    assert view.names() == [ETHERNET, IP, GRE]


def test_fragmented_ip_does_not_invent_transport():
    frag = ip_mod.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
                     p=ip_mod.IP_PROTO_TCP)
    frag._flags_offset = ip_mod.IP_MF
    frag.data = b'\x00' * 8
    gre = gre_mod.GRE(p=ethernet.ETH_TYPE_IP, data=frag)
    outer = ip_mod.IP(src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08',
                      p=ip_mod.IP_PROTO_GRE, data=gre)
    buf = bytes(ethernet.Ethernet(data=outer))

    view = encap_view(buf)
    assert view.reason == FRAGMENTED
    assert view.names() == [ETHERNET, IP, GRE, IP]
    assert view.find('TCP') is None


def test_depth_limit_retains_confirmed_layers():
    payload = ip_mod.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
                        p=ip_mod.IP_PROTO_TCP, data=b'\x00' * 20)
    chain = payload
    for _ in range(6):
        chain = ip_mod.IP(src=b'\x01\x01\x01\x01', dst=b'\x02\x02\x02\x02',
                          p=ip_mod.IP_PROTO_GRE,
                          data=gre_mod.GRE(p=ethernet.ETH_TYPE_IP, data=chain))
    buf = bytes(ethernet.Ethernet(data=chain))

    view = encap_view(buf, max_depth=4)
    assert view.reason == DEPTH_LIMIT
    assert len(view) == 4
    assert all(isinstance(layer, Layer) for layer in view)


def test_truncated_frames():
    # not enough bytes for even the Ethernet header
    view = encap_view(b'\x00' * 8)
    assert view.reason == TRUNCATED and view.names() == []

    # full IP header, but the TCP header it promises is cut off
    ip = ip_mod.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
                   p=ip_mod.IP_PROTO_TCP, len=40)
    buf = bytes(ethernet.Ethernet(
        src=b'\x00' * 6, dst=b'\x00' * 6, data=ip)) + b'\x00\x50\x00\x50\x00'
    view = encap_view(buf)
    assert view.reason == TRUNCATED
    assert view.names() == [ETHERNET, IP]
    assert isinstance(view.last.packet, ip_mod.IP)


def test_tcp_options_are_part_of_the_layer_range():
    tcp = tcp_mod.TCP(sport=1, dport=2)
    tcp.off = 6
    tcp.opts = b'\x01\x01\x01\x01'  # 24-byte TCP header overall
    ip = ip_mod.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
                   p=ip_mod.IP_PROTO_TCP, data=tcp)
    view = encap_view(bytes(ethernet.Ethernet(data=ip)))
    tcp_layer = view.find('TCP')
    assert tcp_layer.end - tcp_layer.start == 24
    assert not view.incomplete


def test_gre_options_header_sizing():
    gre = gre_mod.GRE(p=ethernet.ETH_TYPE_IP, flags=gre_mod.GRE_KP,
                      key=0x12345678,
                      data=ip_mod.IP(src=b'\x01\x01\x01\x01',
                                     dst=b'\x02\x02\x02\x02',
                                     p=ip_mod.IP_PROTO_UDP,
                                     data=udp.UDP(sport=1, dport=2)))
    outer = ip_mod.IP(src=b'\x03\x03\x03\x03', dst=b'\x04\x04\x04\x04',
                      p=ip_mod.IP_PROTO_GRE, data=gre)
    view = encap_view(bytes(ethernet.Ethernet(data=outer)))
    gre_layer = view.find(GRE)
    assert gre_layer.end - gre_layer.start == 8  # 4 fixed + 4 key
    assert gre_layer.packet.key == 0x12345678
    assert view.names() == [ETHERNET, IP, GRE, IP, 'UDP']


def test_ip_in_ip_nesting():
    inner = ip_mod.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
                      p=ip_mod.IP_PROTO_UDP, data=udp.UDP(sport=1, dport=2))
    outer = ip_mod.IP(src=b'\x09\x09\x09\x09', dst=b'\x08\x08\x08\x08',
                      p=ip_mod.IP_PROTO_IPIP, data=inner)
    view = encap_view(bytes(ethernet.Ethernet(data=outer)))
    assert view.names() == [ETHERNET, IP, IP, 'UDP']
    assert not view.incomplete


def test_qinq_double_tag_is_one_vlan_layer():
    inner = ip_mod.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02',
                      p=ip_mod.IP_PROTO_UDP, data=udp.UDP(sport=1, dport=2))
    eth = ethernet.Ethernet(
        src=b'\x00' * 6, dst=b'\x00' * 6,
        vlan_tags=[ethernet.VLANtag8021Q(id=30, type=ethernet.ETH_TYPE_8021Q),
                   ethernet.VLANtag8021Q(id=100, type=ethernet.ETH_TYPE_IP)],
        data=inner)
    view = encap_view(bytes(eth))
    vlan = view.find(VLAN)
    assert vlan.end - vlan.start == 8  # two 4-byte tags in one layer
    assert [tag.id for tag in vlan.tags] == [30, 100]
    assert view.names() == [ETHERNET, VLAN, IP, 'UDP']


def test_gre_v1_and_sre_header_sizing():
    import codecs

    # GRE v1 (PPTP): 4 fixed bytes + 12 option bytes, unsupported payload
    g1 = gre_mod.GRE(
        codecs.decode('3081880a0067178000068fb100083a76', 'hex') + b'A' * 103)
    outer = ip_mod.IP(src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08',
                      p=ip_mod.IP_PROTO_GRE, data=g1)
    view = encap_view(bytes(ethernet.Ethernet(data=outer)))
    gre_layer = view.find(GRE)
    assert gre_layer.end - gre_layer.start == 16
    assert view.reason == UNKNOWN_PROTOCOL

    # GRE with routing (SRE) entries: 4 fixed + 4 options + 10 bytes of SREs
    sre_buf = codecs.decode(
        '40000800' '00010002' '00030402' 'ffff' '00060000', 'hex')
    outer2 = ip_mod.IP(src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08',
                       p=ip_mod.IP_PROTO_GRE, data=gre_mod.GRE(sre_buf))
    view2 = encap_view(bytes(ethernet.Ethernet(data=outer2)))
    gre2 = view2.find(GRE)
    assert gre2.end - gre2.start == 18
    assert len(gre2.packet.sre) == 2


def test_default_decoding_is_independent():
    # the encapsulation view neither mutates the buffer nor changes the
    # behaviour of the ordinary Ethernet(buf) decoder
    buf = _vlan_ip_tcp()
    snapshot = bytes(buf)
    view = encap_view(buf)
    assert bytes(buf) == snapshot

    eth = ethernet.Ethernet(buf)
    assert isinstance(eth.data, ip_mod.IP)
    assert isinstance(eth.data.data, tcp_mod.TCP)
    assert eth.vlanid == 100
    assert view.find('TCP').packet.dport == eth.data.data.dport


def test_security_rules_match_outer_ingress_and_inner_target():
    """A rule engine can match both layers and trace each to the wire."""
    buf = _gre_ip_udp()
    view = encap_view(buf)

    def match_outer_ingress(view, buf):
        layer = view.find_all(IP)[0]
        src = view.byte_range(layer)[12:16]
        return src == b'\xc0\xa8\x01\x01', layer.range

    def match_inner_target(view, buf):
        layer = view.find_all(IP)[1]
        dst = view.byte_range(layer)[16:20]
        dport = view.find('UDP').packet.dport
        return dst == b'\x0a\x01\x00\x02' and dport == 53, layer.range

    outer_hit, outer_range = match_outer_ingress(view, buf)
    inner_hit, inner_range = match_inner_target(view, buf)

    assert outer_hit and inner_hit
    # each match is independently traceable back to its original bytes
    assert buf[outer_range[0] + 12:outer_range[0] + 16] == b'\xc0\xa8\x01\x01'
    assert buf[inner_range[0] + 16:inner_range[0] + 20] == b'\x0a\x01\x00\x02'
    assert outer_range != inner_range

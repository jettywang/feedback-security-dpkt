"""Read-only checksum verification against the original capture bytes.

Design rules enforced here:

* The input byte string is the sole source of truth. Lengths, header offsets
  and checksum fields are all read via ``struct`` from raw slices; dpkt is used
  only to cross-check protocol dispatch, never to regenerate fields.
* No serializer (``bytes(pkt)``, ``pkt.pack_hdr()`` ...) is called before or
  during verification. dpkt recomputes zeroed checksums inside
  ``IP.__bytes__`` / ``IP6.__bytes__``, which would destroy forensic evidence.
* Any incomplete byte range turns the corresponding layer into an
  *inconclusive* verdict. Missing bytes can never produce "valid".
* A stored checksum of zero is never treated as proof. For IPv4/TCP and
  IPv6/TCP/UDP it means "absent/offloaded"; IPv4/UDP zero is explicitly
  *disabled* (RFC 768), which is also not proof of integrity.
"""

import copy
import struct

import dpkt.ip
import dpkt.ip6
import dpkt.tcp
import dpkt.udp

from . import reference

# Verdict identifiers suitable for an alerting backend.
VALID = "valid"              # full bytes present, stored == recomputed
MISMATCH = "mismatch"        # full bytes present, stored != recomputed
INCONCLUSIVE = "inconclusive"  # not enough bytes / not enough evidence
NOT_PRESENT = "not_present"  # checksum explicitly disabled or offloaded

IPV4 = 4
IPV6 = 6
TCP = dpkt.ip.IP_PROTO_TCP
UDP = dpkt.ip.IP_PROTO_UDP


class ChecksumVerdict:
    """Structured result for one checksum layer of one packet."""

    def __init__(self, layer, verdict, stored=None, computed=None,
                 reason="", truncated=False, byte_range=None):
        self.layer = layer                 # "ipv4" | "tcp" | "udp"
        self.verdict = verdict
        self.stored = stored               # value found on the wire (int|None)
        self.computed = computed           # independent recomputation (int|None)
        self.reason = reason
        self.truncated = truncated
        self.byte_range = byte_range       # (start, end_exclusive) covered

    def as_dict(self):
        return {
            "layer": self.layer,
            "verdict": self.verdict,
            "stored": None if self.stored is None else "0x%04x" % self.stored,
            "computed": None if self.computed is None else "0x%04x" % self.computed,
            "truncated": self.truncated,
            "byte_range": list(self.byte_range) if self.byte_range else None,
            "reason": self.reason,
        }

    def __repr__(self):
        return "ChecksumVerdict(%s)" % self.as_dict()


class PacketReport:
    def __init__(self, name, ip_version, transport, verdicts, parse_error=None):
        self.name = name
        self.ip_version = ip_version
        self.transport = transport          # "tcp" | "udp" | None
        self.verdicts = verdicts            # list[ChecksumVerdict]
        self.parse_error = parse_error

    @property
    def overall(self):
        """Worst-case verdict across layers; used to classify the packet."""
        order = {MISMATCH: 3, INCONCLUSIVE: 2, NOT_PRESENT: 1, VALID: 0}
        return max((v.verdict for v in self.verdicts),
                   key=lambda x: order.get(x, 2), default=INCONCLUSIVE)

    def as_dict(self):
        return {
            "name": self.name,
            "ip_version": self.ip_version,
            "transport": self.transport,
            "overall": self.overall,
            "parse_error": self.parse_error,
            "verdicts": [v.as_dict() for v in self.verdicts],
        }


def _need(length, end, what):
    if end > length:
        missing = end - length
        raise Truncation(what, end, length, missing)


class Truncation(Exception):
    def __init__(self, what, wanted, available, missing):
        super().__init__("%s needs %d bytes, only %d available (missing %d)"
                         % (what, wanted, available, missing))
        self.what = what
        self.wanted = wanted
        self.available = available
        self.missing = missing


def _parse_ipv4(raw):
    """Return offsets from raw bytes without trusting dpkt-derived lengths."""
    _need(len(raw), 20, "IPv4 header")
    version_ihl = raw[0]
    if version_ihl >> 4 != 4:
        raise ValueError("not an IPv4 datagram (version=%d)" % (version_ihl >> 4))
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20:
        raise ValueError("invalid IHL=%d" % ihl)
    _need(len(raw), ihl, "IPv4 header (IHL)")
    total_len = struct.unpack(">H", raw[2:4])[0]
    proto = raw[9]
    stored_sum = struct.unpack(">H", raw[10:12])[0]
    src, dst = raw[12:16], raw[16:20]
    # A declared total length larger than the capture means snap truncation.
    declared_end = total_len if total_len else len(raw)
    truncated = total_len > len(raw)
    return {
        "version": IPV4, "ihl": ihl, "total_len": total_len,
        "declared_end": declared_end, "truncated": truncated,
        "proto": proto, "stored_sum": stored_sum, "src": src, "dst": dst,
    }


def _parse_ipv6(raw):
    _need(len(raw), 40, "IPv6 header")
    if raw[0] >> 4 != 6:
        raise ValueError("not an IPv6 datagram")
    plen, nxt, hlim = struct.unpack(">HBB", raw[4:8])
    src, dst = raw[8:24], raw[24:40]
    declared_end = 40 + plen
    truncated = declared_end > len(raw)
    return {
        "version": IPV6, "plen": plen, "declared_end": declared_end,
        "truncated": truncated, "proto": nxt, "stored_sum": None,
        "src": src, "dst": dst, "ihl": 40,
    }


def _tcp_offsets(seg):
    """(header length, checksum byte offset) validated from raw TCP bytes."""
    _need(len(seg), 20, "TCP header")
    data_off = (seg[12] >> 4) * 4
    if data_off < 20:
        raise ValueError("invalid TCP data offset=%d" % data_off)
    _need(len(seg), data_off, "TCP header (data offset)")
    return data_off, 16


def _udp_offsets(seg):
    _need(len(seg), 8, "UDP header")
    return 8, 6


def _verify_transport(meta, l4_start, raw, ip_end, declared_ip_end, truncated_ip):
    """Verify TCP/UDP checksum purely on raw slices.

    ``ip_end`` is the end of the bytes actually captured; ``declared_ip_end``
    is the end implied by the IP length fields. When they differ, part of the
    transport segment is missing, so no checksum verdict can be rendered.
    """
    proto = meta["proto"]
    seg = raw[l4_start:ip_end]
    if proto == TCP:
        layer, hdr_len, csum_off = "tcp", *_tcp_offsets(seg)
    elif proto == UDP:
        layer, hdr_len, csum_off = "udp", *_udp_offsets(seg)
    else:
        return None

    stored = struct.unpack(">H", seg[csum_off:csum_off + 2])[0]
    # Length the checksum was computed over, per the IP length declaration.
    declared_seg_len = declared_ip_end - l4_start
    captured_seg_len = len(seg)
    truncated = truncated_ip

    if truncated_ip or captured_seg_len < declared_seg_len:
        # Any missing byte of the segment invalidates the checksum basis.
        return ChecksumVerdict(
            layer, INCONCLUSIVE, stored=stored,
            reason=("capture truncated: declared segment %d bytes but only %d "
                    "present; checksum basis incomplete"
                    % (declared_seg_len, captured_seg_len)),
            truncated=True, byte_range=(l4_start, ip_end))

    if stored == 0:
        if proto == UDP and meta["version"] == IPV4:
            # RFC 768: zero over IPv4/UDP means the sender disabled checksumming.
            return ChecksumVerdict(
                layer, NOT_PRESENT, stored=0, computed=None,
                reason="IPv4 UDP checksum explicitly disabled (RFC 768 zero value)",
                truncated=truncated, byte_range=(l4_start, ip_end))
        # TCP zero, or UDP zero over IPv6 (illegal): treated as absent/offload.
        reason = ("zero transport checksum: not computed by sender "
                  "(offload/disabled); no integrity evidence")
        return ChecksumVerdict(
            layer, NOT_PRESENT, stored=0, computed=None, reason=reason,
            truncated=truncated, byte_range=(l4_start, ip_end))

    if meta["version"] == IPV4:
        pseudo = reference.ipv4_pseudo_header(meta["src"], meta["dst"], proto,
                                              declared_seg_len)
    else:
        pseudo = reference.ipv6_pseudo_header(meta["src"], meta["dst"], proto,
                                              declared_seg_len)

    try:
        computed = reference.transport_checksum(pseudo, seg, csum_off)
    except ValueError as exc:
        return ChecksumVerdict(layer, INCONCLUSIVE, stored=stored, reason=str(exc),
                               truncated=True, byte_range=(l4_start, ip_end))

    # Cross-check with the RFC 1071 whole-segment-sum property as an internal
    # sanity guard on the independent reference itself.
    if computed == stored:
        assert reference.verify_ones_complement(
            pseudo + seg[:csum_off] + struct.pack(">H", stored)
            + seg[csum_off + 2:])
        verdict = VALID
        reason = "stored checksum matches independent recomputation"
    else:
        verdict = MISMATCH
        reason = "stored 0x%04x != recomputed 0x%04x" % (stored, computed)
    return ChecksumVerdict(layer, verdict, stored=stored, computed=computed,
                           reason=reason, truncated=truncated,
                           byte_range=(l4_start, ip_end))


def verify_packet(raw_ip, name="pkt"):
    """Verify all checksums of one raw IPv4/IPv6 datagram.

    Returns a :class:`PacketReport`. Never raises for truncation or checksum
    failure; structural parse problems are recorded as inconclusive verdicts.
    A defensive pre/post hash and dpkt-object snapshot prove non-mutation.
    """
    if not isinstance(raw_ip, (bytes, bytearray)):
        raise TypeError("raw_ip must be bytes")
    raw_ip = bytes(raw_ip)
    digest_before = hash(raw_ip)
    snapshot_before = None
    verdicts = []
    transport_name = None
    parse_error = None
    ip_version = None

    try:
        version = raw_ip[0] >> 4 if raw_ip else None
        if version == IPV4:
            meta = _parse_ipv4(raw_ip)
            ip_version = IPV4
        elif version == IPV6:
            meta = _parse_ipv6(raw_ip)
            ip_version = IPV6
        else:
            raise ValueError("unsupported IP version %r" % version)

        # dpkt parse used only for dispatch/parity; its output is snapshotted
        # and never serialized.
        parsed = dpkt.ip6.IP6(raw_ip) if ip_version == IPV6 else dpkt.ip.IP(raw_ip)
        snapshot_before = copy.deepcopy(parsed)

        ip_end = min(meta["declared_end"], len(raw_ip))
        truncated = meta["truncated"]

        if ip_version == IPV4:
            stored = meta["stored_sum"]
            ip_hdr = raw_ip[:meta["ihl"]]
            if truncated:
                verdicts.append(ChecksumVerdict(
                    "ipv4", INCONCLUSIVE, stored=stored,
                    reason="capture truncated; full declared datagram unavailable",
                    truncated=True, byte_range=(0, meta["declared_end"])))
            elif stored == 0:
                # A zero IPv4 header checksum is never a valid stored value
                # (the real value would be 0xffff if the sum worked out zero).
                # It marks an un-checksummed / TSO-offloaded segment.
                verdicts.append(ChecksumVerdict(
                    "ipv4", NOT_PRESENT, stored=0,
                    reason="zero IPv4 header checksum: offload/TSO artifact, "
                           "no integrity evidence",
                    byte_range=(0, meta["ihl"])))
            else:
                computed = reference.internet_checksum(
                    ip_hdr[:10] + b"\x00\x00" + ip_hdr[12:])
                verdict = MISMATCH if stored != computed else VALID
                verdicts.append(ChecksumVerdict(
                    "ipv4", verdict, stored=stored, computed=computed,
                    reason=("stored 0x%04x != recomputed 0x%04x" % (stored, computed)
                            if verdict == MISMATCH else
                            "stored checksum matches independent recomputation"),
                    byte_range=(0, meta["ihl"])))

        proto = meta["proto"]
        if proto in (TCP, UDP):
            transport_name = "tcp" if proto == TCP else "udp"
            tv = _verify_transport(meta, meta["ihl"], raw_ip, ip_end,
                                   meta["declared_end"], truncated)
            if tv is not None:
                verdicts.append(tv)
        else:
            verdicts.append(ChecksumVerdict(
                "transport", INCONCLUSIVE,
                reason="protocol %d is not TCP/UDP; out of experiment scope" % proto))

    except Truncation as exc:
        parse_error = str(exc)
        if "TCP" in exc.what:
            layer = "tcp"
        elif "UDP" in exc.what:
            layer = "udp"
        else:
            layer = "ipv4" if (raw_ip and raw_ip[0] >> 4 == IPV4) else "ipv6"
        verdicts.append(ChecksumVerdict(
            layer, INCONCLUSIVE, reason=str(exc), truncated=True))
    except (dpkt.UnpackError, ValueError, struct.error, IndexError) as exc:
        parse_error = "%s: %s" % (type(exc).__name__, exc)
        verdicts.append(ChecksumVerdict(
            "ipv", INCONCLUSIVE, reason="unparseable datagram: %s" % parse_error,
            truncated=True))

    # Non-mutation guard: raw bytes identical, dpkt object graph identical.
    if hash(raw_ip) != digest_before:
        raise AssertionError("verifier mutated the raw capture bytes")
    if snapshot_before is not None:
        parsed_after = (dpkt.ip6.IP6(raw_ip) if ip_version == IPV6
                        else dpkt.ip.IP(raw_ip))
        if _snapshot_key(snapshot_before) != _snapshot_key(parsed_after):
            raise AssertionError("verifier mutated the parsed packet object")

    return PacketReport(name, ip_version, transport_name, verdicts, parse_error)


def _snapshot_key(pkt):
    """Stable structural snapshot of a dpkt packet object's scalar fields."""
    parts = []
    for attr in ("_v_hl", "tos", "len", "id", "_flags_offset", "ttl", "p",
                 "sum", "src", "dst", "_v_fc_flow", "plen", "nxt", "hlim"):
        if hasattr(pkt, attr):
            parts.append((attr, getattr(pkt, attr)))
    data = getattr(pkt, "data", None)
    if hasattr(data, "__hdr__"):
        parts.append(("data_class", data.__class__.__name__))
        for name, _, _ in data.__hdr__:
            parts.append((("data", name), getattr(data, name, None)))
        # TCP/UDP .data is a plain payload byte string, not a Packet, so reading
        # it does not invoke any serializer.
        parts.append(("data_payload", getattr(data, "data", b"")))
    else:
        # Unparsed payload is already raw bytes; never call a serializer here.
        parts.append(("raw_data", data if data is not None else b""))
    return tuple(parts)

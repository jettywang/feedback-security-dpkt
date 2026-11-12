#!/usr/bin/env python3
"""Demonstration / self-check for the offline ICMP quote correlator.

Everything here is constructed locally with dpkt and struct: no socket is
opened and no packet is ever sent.  The script builds a set of outbound
datagrams and later ICMP error messages that quote them, then prints the
correlator verdicts with byte-level evidence.
"""

import struct

import dpkt

from icmp_correlation import (
    AMBIGUOUS, UNCORRELATED, UNIQUE, SentRecord, correlate,
)

LOCAL = struct.pack('!4B', 10, 0, 0, 5)
SERVER = struct.pack('!4B', 198, 51, 100, 7)
ROUTER = struct.pack('!4B', 198, 51, 100, 1)
FAKE_SRC = struct.pack('!4B', 203, 0, 113, 9)


def inet_hex(raw):
    return '.'.join(str(b) for b in raw)


def ip_checksum(header):
    return dpkt.in_cksum(header)


def build_udp(sport, dport, payload, ident, opts=b'', ttl=64,
              frag_off=0, more_frags=False, src=LOCAL, dst=SERVER):
    """Build a raw IPv4 datagram carrying UDP, with optional options/frags."""
    udp_len = 8 + len(payload)
    udp = struct.pack('!HHHH', sport, dport, udp_len, 0) + payload
    total_len = 20 + len(opts) + len(udp)
    # The wire field carries the offset in 8-byte units.
    flags_frag = (frag_off // 8) | (dpkt.ip.IP_MF if more_frags else 0)
    header = struct.pack('!BBHHHBBH', 0x40 | ((20 + len(opts)) // 4), 0,
                         total_len, ident, flags_frag, ttl,
                         dpkt.ip.IP_PROTO_UDP, 0) + src + dst + opts
    header = header[:10] + struct.pack('!H', ip_checksum(header)) + header[12:]
    return header + udp


def build_tcp_syn(sport, dport, seq, ident, window=65535, src=LOCAL,
                  dst=SERVER):
    """Minimal TCP SYN, used to exercise same endpoint prefix reuse."""
    off_flags = (5 << 12) | 0x02  # data offset 5, SYN
    tcp = struct.pack('!HHIIHHHH', sport, dport, seq, 0, off_flags,
                      window, 0, 0)
    total_len = 20 + len(tcp)
    header = struct.pack('!BBHHHBBH', 0x45, 0, total_len, ident, 0, 64,
                         dpkt.ip.IP_PROTO_TCP, 0) + src + dst
    header = header[:10] + struct.pack('!H', ip_checksum(header)) + header[12:]
    return header + tcp


def build_icmp_error(quoted_ip_bytes, icmp_type=3, code=3, src=ROUTER,
                     dst=LOCAL, quote_len=None, tamper=None,
                     outer_src_override=None):
    """Wrap quoted bytes in an ICMP error inside an outer IPv4 datagram.

    tamper: optional callable(quote_bytes) -> modified quote_bytes, used to
    simulate a forged or mangled reference.
    """
    quote = quoted_ip_bytes if quote_len is None else quoted_ip_bytes[:quote_len]
    if tamper is not None:
        quote = tamper(quote)
    hdr = struct.pack('!BBH', icmp_type, code, 0) + b'\x00\x00\x00\x00'
    icmp = hdr + quote
    checksum = dpkt.in_cksum(icmp)
    icmp = icmp[:2] + struct.pack('!H', checksum) + icmp[4:]

    outer_src = outer_src_override if outer_src_override is not None else src
    total = 20 + len(icmp)
    outer = struct.pack('!BBHHHBBH', 0x45, 0, total, 0x9001, 0, 64,
                        dpkt.ip.IP_PROTO_ICMP, 0) + outer_src + dst
    outer = outer[:10] + struct.pack('!H', ip_checksum(outer)) + outer[12:]
    return outer + icmp


def tamper_inner_port(quote_bytes):
    """Flip the destination port located right after the inner IP header."""
    ihl = (quote_bytes[0] & 0x0f) * 4
    # UDP destination port is the second 16-bit field of the transport header.
    dport_off = ihl + 2
    if dport_off + 2 > len(quote_bytes):
        raise ValueError('quote too short to contain an inner destination port')
    value = struct.unpack('!H', quote_bytes[dport_off:dport_off + 2])[0]
    mangled = bytearray(quote_bytes)
    mangled[dport_off:dport_off + 2] = struct.pack('!H', (value + 1) & 0xffff)
    return bytes(mangled)


def print_result(label, result):
    ev = result.evidence
    print('--- %s' % label)
    print('    verdict            : %s' % result.verdict)
    obs = result.outer_observation
    if obs:
        print('    outer observation  : %s code=%s from %s (observation only, '
              'not evidence)' % (obs.get('icmp_type_name'), obs.get('icmp_code'),
                                 inet_hex(obs.get('outer_src', b''))))
    if ev.quote_length:
        ports = ''
        if ev.src_port is not None or ev.dst_port is not None:
            ports = ' ports=%s->%s' % (ev.src_port, ev.dst_port)
        print('    quote              : offset=%s len=%d inner_total=%s '
              'ip_opts=%sB frag_off=%s MF=%s l4_prefix=%sB%s'
              % (ev.inner_ip_offset, ev.quote_length, ev.inner_total_length,
                 ev.inner_options_length, ev.fragment_offset,
                 ev.more_fragments, ev.transport_prefix_length, ports))
        if ev.inner_checksum_ok is not None:
            print('    inner hdr checksum : %s' % ev.inner_checksum_ok)
    for candidate in result.candidates:
        rec = candidate.record
        print('    candidate          : packet #%s matched_bytes=%d '
              'dt=%.6fs transport_match=%s'
              % (rec.packet_id, candidate.matched_bytes,
                 candidate.time_delta, candidate.transport_matched))
    for reason in result.reasons:
        print('    reason             : %s' % reason)
    print()


def main():
    # -- Outbound capture history (1-based packet numbers, monotonic time). --
    sent = []

    # #1 normal UDP query with a 24-byte payload.
    pkt1 = build_udp(40001, 53, b'query-A-payload-xxxxxxxx', ident=0x1111)
    sent.append(SentRecord(1, 1000.000, pkt1))

    # #2 same five-tuple endpoints as #1, reused later (different id/payload).
    pkt2 = build_udp(40001, 53, b'query-B-payload-yyyyyyyy', ident=0x2222)
    sent.append(SentRecord(2, 1000.250, pkt2))

    # #3 a datagram with IP options (NOP + timestamp option, padded).
    opts = b'\x01\x44\x08\x05\x00\x00\x00\x00'  # NOP + 8-byte timestamp option
    pkt3 = build_udp(40002, 53, b'options-payload-zzzzzz', ident=0x3333,
                     opts=opts)
    sent.append(SentRecord(3, 1000.500, pkt3))

    # #4 large UDP datagram, first and non-first fragments.
    big_payload = bytes((i * 7) & 0xff for i in range(600))
    pkt4_full = build_udp(40003, 500, big_payload, ident=0x4444)
    frag1 = pkt4_full[:1500]
    # Second fragment: IP header with MF cleared and offset 1480.  Its total
    # length field still describes the whole original datagram.
    frag2_payload = pkt4_full[20 + 1480:]
    frag2_hdr = build_udp(40003, 500, frag2_payload, ident=0x4444,
                          frag_off=1480, more_frags=False)
    fragment_total = len(frag2_hdr)
    # The total-length field still describes the whole original datagram;
    # rewrite it, then recompute the header checksum over the final header.
    frag2 = bytearray(frag2_hdr[:20])
    frag2[2:4] = struct.pack('!H', len(pkt4_full))
    frag2[10:12] = b'\x00\x00'
    frag2[10:12] = struct.pack('!H', ip_checksum(bytes(frag2)))
    frag2 = bytes(frag2) + frag2_payload
    assert fragment_total == 20 + 8 + len(frag2_payload)
    sent.append(SentRecord(4, 1001.000, frag1))
    sent.append(SentRecord(5, 1001.001, frag2))

    # #6 TCP SYN reusing the same port pair style as another record later.
    pkt6 = build_tcp_syn(40001, 53, seq=1000, ident=0x6666, window=65535)
    sent.append(SentRecord(6, 1001.200, pkt6))
    # #7 TCP SYN whose quoted 28-byte prefix is byte-identical to #6: same
    # endpoints, same IP id, same ports/seq; only the window field at inner
    # offset 30 differs, which a short ICMP quote does not carry.
    pkt7 = build_tcp_syn(40001, 53, seq=1000, ident=0x6666, window=8192)
    sent.append(SentRecord(7, 1001.400, pkt7))

    results = []

    # Case 1: correct full quote of packet #1 -> unique.
    icmp1 = build_icmp_error(pkt1)
    results.append(('1 correct full quote (expect unique -> packet #1)',
                    correlate(icmp1, 1000.030, sent)))

    # Case 2: forged quote, only the inner destination port changed -> reject.
    icmp2 = build_icmp_error(pkt1, tamper=tamper_inner_port,
                             outer_src_override=FAKE_SRC)
    results.append(('2 forged quote, inner dst port flipped (expect '
                    'uncorrelated)', correlate(icmp2, 1000.040, sent)))

    # Case 3a: endpoint reuse, quote packet #2 but both #1 and #2 share only
    # the tuple; distinct IP id/payload means only #2 matches -> unique.
    icmp3 = build_icmp_error(pkt2)
    results.append(('3 reused endpoints, exact quote of #2 (expect unique '
                    '-> #2)', correlate(icmp3, 1000.280, sent)))

    # Case 3b: truncated quote of #2 that keeps only the common prefix shared
    # by #1 and #2 (IP header differs in id, so demonstrate ambiguity with a
    # pair built to share the prefix: TCP #6/#7).
    short_quote = pkt7[:28]  # IP(20) + TCP ports+seq first 8 bytes
    icmp4 = build_icmp_error(short_quote)
    results.append(('4 reused TCP endpoints, identical 28-byte prefix (expect '
                    'ambiguous #6/#7)', correlate(icmp4, 1001.430, sent)))

    # Case 5: quote truncated inside the inner IP header -> uncorrelated.
    icmp5 = build_icmp_error(pkt1, quote_len=12)
    results.append(('5 truncated quote inside IP header (expect '
                    'uncorrelated)', correlate(icmp5, 1000.050, sent)))

    # Case 6: datagram with IP options quoted correctly -> unique #3.
    icmp6 = build_icmp_error(pkt3)
    results.append(('6 quote carrying IP options (expect unique -> #3)',
                    correlate(icmp6, 1000.540, sent)))

    # Case 7: quote of a non-first fragment (no transport header) -> #5.
    icmp7 = build_icmp_error(frag2)
    results.append(('7 quote of non-first fragment (expect unique -> #5, '
                    'limited evidence)', correlate(icmp7, 1001.060, sent)))

    # Case 8: otherwise correct quote arriving outside the time window.
    icmp8 = build_icmp_error(pkt1)
    results.append(('8 correct quote outside time window (expect '
                    'uncorrelated)', correlate(icmp8, 1100.000, sent,
                                               max_window=30.0)))

    for label, result in results:
        print_result(label, result)

    # -- Assertions: incomplete evidence must never become a definite call. --
    expectations = {
        0: (UNIQUE, [1]),
        1: (UNCORRELATED, []),
        2: (UNIQUE, [2]),
        3: (AMBIGUOUS, [6, 7]),
        4: (UNCORRELATED, []),
        5: (UNIQUE, [3]),
        6: (UNIQUE, [5]),
        7: (UNCORRELATED, []),
    }
    for index, (verdict, ids) in expectations.items():
        result = results[index][1]
        assert result.verdict == verdict, (index, result)
        assert [c.record.packet_id for c in result.candidates] == ids
    print('all %d demonstration assertions passed' % len(expectations))


if __name__ == '__main__':
    main()

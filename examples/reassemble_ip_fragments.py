"""Reassemble IPv4 fragments before decoding UDP, refusing ambiguous data.

Fragment overlap is an evasion technique: the bytes an analyzer reconstructs
may differ from the bytes the target host reconstructs.  This script feeds
every IPv4 packet of a pcap through dpkt.ipfrag.IPFragmentReassembler and
only decodes UDP when the reassembler returns a complete, unambiguous
datagram.  Conflicting, expired or incomplete groups are reported instead of
being guessed at.

Usage:
    python examples/reassemble_ip_fragments.py capture.pcap
"""
from __future__ import print_function

import sys

import dpkt
from dpkt.ipfrag import (COMPLETE, CONFLICT, EXPIRED, LIMIT, PENDING,
                         IPFragmentReassembler)
from dpkt.utils import inet_to_str

STATUS_LABEL = {
    COMPLETE: 'complete  ',
    PENDING: 'pending   ',
    CONFLICT: 'CONFLICT  ',
    EXPIRED: 'expired   ',
    LIMIT: 'limit     ',
}


def describe(key):
    return '%s -> %s proto=%d id=0x%04x' % (
        inet_to_str(key.src), inet_to_str(key.dst), key.proto, key.id)


def analyze(reader, reassembler):
    for timestamp, buf in reader:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data

        result = reassembler.add(ip, timestamp)
        prefix = STATUS_LABEL[result.status]
        identity = '%s -> %s proto=%d id=0x%04x gen=%d' % (
            inet_to_str(result.key.src), inet_to_str(result.key.dst),
            result.key.proto, result.key.id, result.generation)

        if result.status == COMPLETE:
            if result.fragments == 1 and result.key.proto == dpkt.ip.IP_PROTO_UDP:
                # Unfragmented packet: decode its transport payload directly.
                _decode_udp(ip.data)
            elif result.key.proto == dpkt.ip.IP_PROTO_UDP:
                # Reassembled only after every overlap agreed.
                print('%s %s reassembled %d bytes from %d fragments'
                      % (prefix, identity, result.total_len,
                         result.fragments))
                _decode_udp(dpkt.udp.UDP(result.payload))
            else:
                print('%s %s reassembled %d bytes'
                      % (prefix, identity, result.total_len))
        elif result.status == CONFLICT:
            # Never feed result.payload (which is None) to a decoder.
            print('%s %s %s' % (prefix, identity, result.reason))
        elif result.status == LIMIT:
            print('%s %s %s' % (prefix, identity, result.reason))
        else:
            print('%s %s gaps=%s' % (prefix, identity, result.gaps))

        # Groups retired by cache pressure or id reuse are surfaced here.
        for event in reassembler.drain_events():
            print('%s %s %s' % (STATUS_LABEL[event.status],
                                describe(event.key), event.reason))

    # Anything still unfinished at end of capture gets an explicit verdict.
    for event in reassembler.sweep(float('inf')):
        print('%s %s %s' % (STATUS_LABEL[event.status],
                            describe(event.key), event.reason))


def _decode_udp(udp):
    print('           UDP sport=%d dport=%d payload=%d bytes'
          % (udp.sport, udp.dport, len(udp.data)))


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 1
    with open(sys.argv[1], 'rb') as fp:
        reader = dpkt.pcap.Reader(fp)
        # Caller-controlled time budget and cache limits; no wall clock used.
        reassembler = IPFragmentReassembler(
            fragment_timeout=30.0, max_groups=1024,
            max_fragments_per_group=64)
        analyze(reader, reassembler)
    return 0


if __name__ == '__main__':
    sys.exit(main())

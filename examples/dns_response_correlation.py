"""Offline DNS response correlation and contradiction detection.

Demonstrates :mod:`dpkt.dns_correlator` on a synthetic capture that contains:

* two endpoint pairs reusing the same DNS transaction ID (port reuse safe);
* one legitimate query retransmission with consistent answers;
* one query that receives two contradictory answers (possible poisoning);
* answers whose only difference is TTL (must NOT be flagged);
* a response that shows up before its query is read.

The same packet set is then fed in shuffled order to show that the final
contradiction set and the source packet numbers are identical.
"""
import io
import random

import dpkt
from dpkt import dns
from dpkt.dns_correlator import (
    MATCHED,
    CONTRADICTORY,
    INSUFFICIENT,
    OUT_OF_WINDOW,
    DnsResponseCorrelator,
    correlate,
)
from dpkt.ip import IP
from dpkt.ethernet import Ethernet
from dpkt.pcap import Writer
from dpkt.udp import UDP

CLIENT_A = (b'\x0a\x00\x00\x01', 40001)
CLIENT_B = (b'\x0a\x00\x00\x02', 40002)
RESOLVER_1 = (b'\x08\x08\x08\x08', 53)
RESOLVER_2 = (b'\x01\x01\x01\x01', 53)
SHARED_TXN_ID = 0x1234


def question(name, qtype=dns.DNS_A):
    return dns.DNS.Q(name=name, type=qtype, cls=dns.DNS_IN)


def answer(name, ip4, ttl=300):
    return dns.DNS.RR(name=name, type=dns.DNS_A, cls=dns.DNS_IN,
                      ttl=ttl, rdata=ip4)


def query(txn_id, name):
    pkt = dns.DNS(id=txn_id, op=dns.DNS_RD)
    pkt.qr = 0
    pkt.qd = [question(name)]
    pkt.an = pkt.ns = pkt.ar = []
    return pkt


def response(txn_id, name, ip4=None, ttl=300, rcode=dns.DNS_RCODE_NOERR):
    pkt = dns.DNS(id=txn_id, op=0)
    pkt.qr = 1
    pkt.rcode = rcode
    pkt.qd = [question(name)]
    pkt.an = [] if ip4 is None else [answer(name, ip4, ttl)]
    pkt.ns = pkt.ar = []
    return pkt


def frame(src, dst, payload):
    udp = UDP(sport=src[1], dport=dst[1], data=payload)
    ip_pkt = IP(src=src[0], dst=dst[0], p=17, data=udp)
    return bytes(Ethernet(data=ip_pkt))


def build_packets():
    """Return ``(packet_no, timestamp, src, dst, dns_pkt)`` tuples."""
    packets = []
    no = 0

    def add(ts, src, dst, pkt):
        nonlocal no
        no += 1
        packets.append((no, ts, src, dst, pkt))

    # Flow 1: same txn id as flow 2 but a different endpoint pair.
    add(0.00, CLIENT_A, RESOLVER_1, query(SHARED_TXN_ID, 'shared.example'))
    add(0.03, RESOLVER_1, CLIENT_A, response(SHARED_TXN_ID, 'shared.example',
                                            b'\x01\x02\x03\x04'))

    # Flow 2: legitimate retransmission, then one consistent answer.
    add(0.10, CLIENT_B, RESOLVER_2, query(0x2222, 'retrans.example'))
    add(0.60, CLIENT_B, RESOLVER_2, query(0x2222, 'retrans.example'))
    add(0.64, RESOLVER_2, CLIENT_B, response(0x2222, 'retrans.example',
                                             b'\x05\x06\x07\x08'))

    # Flow 3: contradictory answers to one query.
    add(1.00, CLIENT_A, RESOLVER_1, query(0x3333, 'victim.example'))
    add(1.04, RESOLVER_1, CLIENT_A, response(0x3333, 'victim.example',
                                             b'\x0a\x00\x00\x09'))
    add(1.07, RESOLVER_1, CLIENT_A, response(0x3333, 'victim.example',
                                             b'\xc6\x12\x00\x01'))

    # Flow 4: TTL-only differences are not a contradiction.
    add(2.00, CLIENT_B, RESOLVER_2, query(0x4444, 'ttl.example'))
    add(2.02, RESOLVER_2, CLIENT_B, response(0x4444, 'ttl.example',
                                             b'\x09\x09\x09\x09', ttl=300))
    add(2.05, RESOLVER_2, CLIENT_B, response(0x4444, 'ttl.example',
                                             b'\x09\x09\x09\x09', ttl=45))

    # Flow 5: response is read before its query.
    add(3.00, RESOLVER_1, CLIENT_A, response(0x5555, 'early.example',
                                             b'\x08\x08\x04\x04'))
    add(3.02, CLIENT_A, RESOLVER_1, query(0x5555, 'early.example'))

    return packets


def to_records(packets):
    from dpkt.dns_correlator import parse_dns_datagram
    records = []
    for packet_no, ts, src, dst, pkt in packets:
        record = parse_dns_datagram(packet_no, ts, src[0], src[1],
                                    dst[0], dst[1], bytes(pkt))
        records.append(record)
    return records


def print_results(label, results):
    print('--- %s ---' % label)
    for result in results:
        name = result.questions[0][0]
        line = '%-13s id=0x%04x %-16s queries=%s responses=%s' % (
            result.status, result.txn_id, name,
            result.query_packets, result.response_packets)
        if result.status == CONTRADICTORY:
            for fingerprint, packet_numbers in result.evidence:
                rcode, rrs = fingerprint
                line += '\n    answer from packets %s -> rcode=%d rrs=%s' % (
                    packet_numbers, rcode, rrs)
        print(line)
    print()


def test():
    packets = build_packets()
    records = to_records(packets)

    results = correlate(records, window=5.0, max_pending=1000)
    print_results('natural capture order', results)

    # Feed the same records in a different order; packet numbers are preserved.
    shuffled = list(records)
    random.Random(7).shuffle(shuffled)
    reordered = correlate(shuffled, window=5.0, max_pending=1000)
    print_results('shuffled input order', reordered)

    conflicts = [r for r in results if r.status == CONTRADICTORY]
    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert conflict.txn_id == 0x3333
    assert sorted(pkts for _, pkts in conflict.evidence) == [(7,), (8,)]

    shuffled_conflicts = [r for r in reordered if r.status == CONTRADICTORY]
    assert len(shuffled_conflicts) == 1
    assert shuffled_conflicts[0].evidence == conflict.evidence
    statuses = {r.txn_id: r.status for r in results}
    assert statuses[SHARED_TXN_ID] == MATCHED
    assert statuses[0x2222] == MATCHED
    assert statuses[0x4444] == MATCHED
    assert statuses[0x5555] == MATCHED
    print('contradiction set and source packet numbers are order-independent.')

    # Demonstrate the configurable window verdict as well.
    late = DnsResponseCorrelator(window=1.0)
    late.feed(to_records([
        (1, 0.0, CLIENT_A, RESOLVER_1, query(0x6666, 'late.example')),
    ])[0])
    closed = late.feed(to_records([
        (2, 3.0, RESOLVER_1, CLIENT_A, response(0x6666, 'late.example',
                                                b'\x01\x01\x01\x01')),
    ])[0])
    assert closed[0].status == OUT_OF_WINDOW
    print('late answer verdict: %s (window=1.0s, answer 3.0s after query)'
          % OUT_OF_WINDOW)

    # Round-trip the synthetic traffic through a real pcap file object.
    buf = io.BytesIO()
    writer = Writer(buf)
    for packet_no, ts, src, dst, pkt in packets:
        writer.writepkt(frame(src, dst, bytes(pkt)), ts)
    buf.seek(0)
    from dpkt.dns_correlator import correlate_pcap
    pcap_results = correlate_pcap(buf, window=5.0, max_pending=1000)
    assert [r.status for r in pcap_results] == [r.status for r in results]
    print('pcap round-trip produced %d correlated exchanges.' % len(pcap_results))


if __name__ == '__main__':
    test()

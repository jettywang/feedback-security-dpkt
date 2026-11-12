"""
Summarize offline TCP connection attempts from a pcap for alert triage.

Each attempt is classified as:

* success  -- a full handshake was observed (normal connection);
* rejected -- the attempt was explicitly refused, typically by a RST (a failed
  probe);
* unknown  -- the capture does not contain enough evidence, for example because
  only one direction was recorded.

Only IP/TCP header metadata is read: application payloads are never inspected
and no traffic is generated.
"""
from __future__ import print_function

import dpkt
from dpkt.tcpsummary import TCPAttemptSummary, TCP_SUCCESS, TCP_REJECTED, TCP_UNKNOWN

# Verdict -> short label used in the report.
_LABELS = {
    TCP_SUCCESS: 'SUCCESS ',
    TCP_REJECTED: 'REJECTED',
    TCP_UNKNOWN: 'UNKNOWN ',
}


def summarize_packets(reader, idle_timeout=120.0, late_tolerance=30.0):
    """Feed every frame of a pcap reader through the summarizer."""
    summarizer = TCPAttemptSummary(idle_timeout=idle_timeout,
                                   late_tolerance=late_tolerance)
    for ts, buf in reader:
        summarizer.process(buf, ts=ts)
    summarizer.flush()
    return summarizer


def print_report(summarizer):
    summary = summarizer.summary()
    print('TCP connection attempts: %d (success=%d rejected=%d unknown=%d)' % (
        summary['total_attempts'], summary['success'],
        summary['rejected'], summary['unknown']))
    for attempt in summarizer.attempts():
        print('  %s gen=%d %s -> %s  evidence=%s  reason=%s' % (
            _LABELS[attempt.verdict], attempt.generation,
            attempt.initiator, attempt.responder,
            attempt.evidence, attempt.reason))
    if summary['rejected_targets']:
        print('Rejected-connection targets:')
        for target, count in sorted(summary['rejected_targets'].items()):
            print('  %s : %d' % (target, count))


def test():
    import os
    path = os.path.join(os.path.dirname(__file__), 'data', 'http.pcap')
    with open(path, 'rb') as f:
        print_report(summarize_packets(dpkt.pcap.Reader(f)))


if __name__ == '__main__':
    test()

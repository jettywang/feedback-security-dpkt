Offline ICMP Error Quote Correlation
====================================

.. contents::

Purpose
-------

When an alarm backend receives an ICMP error message it must decide which
previously observed outbound communication the error actually refers to.  The
ICMP payload quotes a prefix of the offending datagram, but that quote can be
forged, truncated or shared by several sends (endpoint reuse, identical
prefixes).  The correlator in ``examples/icmp_correlation.py`` works only on
captured bytes -- it never opens a socket and never sends a packet -- and
returns an explicit verdict instead of guessing.

Verdicts
--------

``unique``
    Exactly one recorded send matches every byte the quote contains and lies
    inside the time window.  The result carries the original packet id, the
    number of matched bytes and the quote offset inside the outer datagram.

``ambiguous``
    More than one recorded send survives every check.  Incomplete evidence is
    never promoted to a definite attribution; all survivors are returned.

``uncorrelated``
    No record survives, or the quote is unusable (for example it ends inside
    the inner IP header).  Per-record rejection reasons identify the exact
    inner/outer byte offset of the first mismatch.

What is compared
----------------

1. The outer frame is parsed with dpkt; only ICMP error types 3, 4, 5, 11 and
   12 are accepted.  The outer source address, type/code and checksum are
   retained as **observation only** and never drive the verdict.
2. The inner IP header is parsed directly from the quoted bytes.  Its declared
   IHL and total length are bounds-checked against the bytes actually present,
   so IP options and truncated headers are handled safely.
3. A hard byte-prefix comparison covers every quoted byte: IP header, IP
   options, transport header prefix and any quoted payload.  A single
   differing byte (including a flipped port) rejects the record with the
   precise offset.
4. For first fragments the available transport prefix is checked: TCP/UDP/SCTP
   ports (2 or 4 bytes depending on quote length) or an inner ICMP echo
   id/sequence prefix.  Non-first fragments have no transport header and are
   matched on IP header evidence only, which is reflected in the result.
5. The ICMP arrival time must be after the send and within ``max_window``
   seconds (default 30).

Usage
-----

.. code-block:: python

    from examples.icmp_correlation import SentRecord, correlate

    sent = [SentRecord(1, send_ts, raw_ip_bytes)]
    result = correlate(raw_icmp_frame_or_ip, icmp_ts, sent, max_window=30.0)
    print(result.verdict)                 # unique / ambiguous / uncorrelated
    print(result.evidence.inner_ip_offset)
    print([c.record.packet_id for c in result.candidates])
    print(result.reasons)

The self-contained demonstration constructs all packets locally and prints the
evidence for a correct quote, a forged quote with one port byte flipped,
reused endpoints (unique and ambiguous), truncation, IP options, a non-first
fragment and an out-of-window arrival:

.. code-block:: console

    python3 examples/icmp_correlation_demo.py

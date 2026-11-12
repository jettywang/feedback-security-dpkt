"""Reproducible checksum experiment driver.

Pipeline (forensically safe, no serializer before verification):

    corpus.build_corpus -> pcap file -> dpkt.pcap.Reader -> raw frame bytes
    -> Ethernet type/length parse with struct only -> raw IP datagram slice
    -> verifier.verify_packet (independent reference checksums)
    -> expected-verdict assertions -> JSON + console report
"""

import json
import os
import struct

import dpkt.pcap

from . import corpus
from .verifier import verify_packet

ETH_HDR_LEN = 14
ETH_TYPE_V4 = 0x0800
ETH_TYPE_V6 = 0x86DD


def _raw_ip_from_frame(frame):
    """Strip Ethernet with struct only; reject 802.3/ VLAN for this lab."""
    if len(frame) < ETH_HDR_LEN:
        raise ValueError("frame shorter than Ethernet header")
    ethertype = struct.unpack(">H", frame[12:14])[0]
    if ethertype == ETH_TYPE_V4:
        return frame[ETH_HDR_LEN:], 4
    if ethertype == ETH_TYPE_V6:
        return frame[ETH_HDR_LEN:], 6
    raise ValueError("unsupported EtherType 0x%04x" % ethertype)


def run(pcap_path, json_path=None):
    entries = corpus.build_corpus()
    corpus.write_pcap(pcap_path, entries)
    expected = {e["name"]: e for e in entries}

    results = []
    failures = []

    with open(pcap_path, "rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        for _, frame in reader:
            # frame is the exact captured byte string from the pcap record.
            frame_before = bytes(frame)
            raw_ip, _ = _raw_ip_from_frame(frame)
            name_hint = None
            report = verify_packet(raw_ip)
            if hash(frame_before) != hash(frame):
                failures.append("frame bytes mutated during verification")

            # Exact match first; truncated frames match the longest stored
            # prefix so they can never be confused with the full valid sample.
            matched = next((c["name"] for c in entries if c["raw_ip"] == raw_ip),
                           None)
            if matched is None:
                prefixes = ((c["name"], c["raw_ip"]) for c in entries
                            if raw_ip and c["raw_ip"][:len(raw_ip)] == raw_ip
                            and len(c["raw_ip"]) > len(raw_ip))
                best = max(prefixes, key=lambda item: len(item[1]), default=None)
                matched = best[0] if best else None
            report.name = matched or report.name
            entry = expected.get(report.name)

            record = report.as_dict()
            record["frame_len"] = len(frame_before)
            record["raw_ip_len"] = len(raw_ip)
            record["bytes_unchanged"] = hash(frame_before) == hash(frame)

            if entry is not None:
                record["expected_overall"] = entry["expect"]
                record["kind"] = entry["kind"]
                record["description"] = entry["description"]
                layer_got = {v.layer: v.verdict for v in report.verdicts}
                record["expected_layers"] = entry["expect_layers"]
                overall_ok = report.overall == entry["expect"]
                layers_ok = all(layer_got.get(layer) == verdict
                                for layer, verdict in entry["expect_layers"].items())
                record["expectation_met"] = overall_ok and layers_ok
                if not record["expectation_met"]:
                    failures.append(
                        "%s: expected overall=%s layers=%s got overall=%s layers=%s"
                        % (report.name, entry["expect"], entry["expect_layers"],
                           report.overall, layer_got))
            else:
                record["expectation_met"] = False
                failures.append("unmatched pcap frame")

            results.append(record)

    summary = {
        "total": len(results),
        "by_verdict": {},
        "by_kind": {},
        "all_bytes_unchanged": all(r["bytes_unchanged"] for r in results),
        "all_expectations_met": all(r["expectation_met"] for r in results),
        "failures": failures,
    }
    for r in results:
        summary["by_verdict"][r["overall"]] = \
            summary["by_verdict"].get(r["overall"], 0) + 1
        kind = r.get("kind", "unknown")
        summary["by_kind"][kind] = summary["by_kind"].get(kind, 0) + 1

    payload = {"pcap": os.path.abspath(pcap_path), "summary": summary,
               "results": results}
    if json_path:
        with open(json_path, "w") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
    return payload


def print_report(payload):
    print("pcap: %s" % payload["pcap"])
    print("%-38s %-23s %-13s %-8s %s" %
          ("sample", "kind", "overall", "bytes", "layer verdicts"))
    print("-" * 110)
    for r in payload["results"]:
        layers = ",".join("%s=%s" % (v["layer"], v["verdict"])
                          for v in r["verdicts"])
        print("%-38s %-23s %-13s %-8s %s" % (
            r["name"], r.get("kind", "?"), r["overall"],
            "ok" if r["bytes_unchanged"] else "MUTATED", layers))
    print("-" * 110)
    s = payload["summary"]
    print("summary: %s" % json.dumps(s["by_verdict"]))
    print("kinds  : %s" % json.dumps(s["by_kind"]))
    print("bytes unchanged in every case : %s" % s["all_bytes_unchanged"])
    print("all expectations met          : %s" % s["all_expectations_met"])
    if s["failures"]:
        print("FAILURES:")
        for f in s["failures"]:
            print("  - %s" % f)
        return 1
    return 0


def main():
    import sys
    here = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(here, "output")
    os.makedirs(out_dir, exist_ok=True)
    pcap_path = os.path.join(out_dir, "checksum_corpus.pcap")
    json_path = os.path.join(out_dir, "checksum_report.json")
    payload = run(pcap_path, json_path)
    rc = print_report(payload)
    print("\nJSON report: %s" % json_path)
    sys.exit(rc)


if __name__ == "__main__":
    main()

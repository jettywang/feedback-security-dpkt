"""Alert-backend classification policy for passive checksum verdicts.

The hard rule required by the experiment: a layer may be reported *valid* only
when every byte the checksum covers is present and the recomputed value equals
the stored one. Anything else maps to a non-passing severity so that
uncomputed, zero, or unverifiable checksums can never silently count as "ok".
"""

from .verifier import INCONCLUSIVE, MISMATCH, NOT_PRESENT, VALID

# Backend-facing severities / dispositions.
SEVERITY = {
    MISMATCH: ("high", "alert"),
    # Truncated evidence is a capture-quality problem, not proof of tampering.
    INCONCLUSIVE: ("info", "quarantine_evidence"),
    # Offload / disabled checksums carry no integrity claim at all.
    NOT_PRESENT: ("info", "no_integrity_claim"),
    VALID: ("none", "pass"),
}

# Whether a verdict is admissible as positive integrity evidence.
POSITIVE_EVIDENCE = frozenset([VALID])
# Verdicts that must never be aggregated into a "checksum OK" metric.
NON_PASSING = frozenset([MISMATCH, INCONCLUSIVE, NOT_PRESENT])


def classify_layer(verdict):
    """Return (severity, disposition, is_positive_evidence) for one layer."""
    if verdict not in SEVERITY:
        raise ValueError("unknown verdict %r" % verdict)
    severity, disposition = SEVERITY[verdict]
    return severity, disposition, verdict in POSITIVE_EVIDENCE


def classify_packet(report):
    """Aggregate a :class:`PacketReport` into one backend decision.

    Returns a dict with a single ``decision``. ``pass`` is emitted only when
    every verifiable layer is VALID and no layer is missing evidence. A packet
    that has no checksum evidence at all becomes ``no_evidence``, distinct from
    both a pass and an alert.
    """
    layers = [v.verdict for v in report.verdicts]
    if MISMATCH in layers:
        decision, reason = "alert", "at least one checksum mismatch on full bytes"
    elif INCONCLUSIVE in layers:
        decision, reason = "no_evidence", "truncated/partial capture; evidence insufficient"
    elif all(v == NOT_PRESENT for v in layers):
        decision, reason = "no_evidence", "no layer carried a usable checksum"
    elif NOT_PRESENT in layers:
        # Some layers validated, others had no checksum claim: pass only the
        # validated layers, never claim end-to-end integrity.
        decision, reason = "partial_pass", "validated layers pass; others have no claim"
    elif all(v == VALID for v in layers):
        decision, reason = "pass", "all present checksums verified on complete bytes"
    else:
        decision, reason = "no_evidence", "unclassified verdict combination"

    return {
        "name": report.name,
        "decision": decision,
        "reason": reason,
        "layers": [
            {
                "layer": v.layer,
                "verdict": v.verdict,
                "severity": classify_layer(v.verdict)[0],
                "disposition": classify_layer(v.verdict)[1],
                "positive_evidence": classify_layer(v.verdict)[2],
                "truncated": v.truncated,
            }
            for v in report.verdicts
        ],
    }

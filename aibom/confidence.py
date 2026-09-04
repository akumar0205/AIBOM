from __future__ import annotations


def score_confidence(signals: set[str] | None = None) -> str:
    """Score detector confidence from corroborating static-analysis signals."""
    observed = signals or set()
    score = 0
    if "import" in observed:
        score += 1
    if "constructor" in observed:
        score += 1
    if "config_key" in observed:
        score += 1

    if score >= 2:
        return "high"
    if score == 1:
        return "medium"
    return "low"


def score_confidence_with_evidence(
    signals: set[str] | None = None, evidence_class: str = "observed_call"
) -> str:
    """Score confidence from signals, calibrated by evidence class.

    ``observed_call`` keeps the signal-based score; ``inferred_dependency``
    is capped at ``medium`` unless three corroborating signals exist; and
    ``suspected_usage`` is always ``low`` since no direct call was observed.
    """
    base = score_confidence(signals)
    if evidence_class == "suspected_usage":
        return "low"
    if evidence_class == "inferred_dependency":
        observed = signals or set()
        if len(observed & {"import", "constructor", "config_key"}) >= 3:
            return "high"
        return "medium" if base in {"high", "medium"} else "low"
    return base

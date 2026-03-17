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

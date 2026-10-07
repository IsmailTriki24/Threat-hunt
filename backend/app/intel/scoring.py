# ruff: noqa: E501
"""Explainable threat-intelligence scoring.

Each provider contributes at most one signal: (verdict, confidence 0-100) weighted by how much we trust that source.

  strength_i      = weight_i * confidence_i / 100
  malicious       -> p_i = strength_i              suspicious -> p_i = 0.5 * strength_i
  score           = 100 * (1 - prod(1 - p_i))      (independent corroboration raises the score; one weak source cannot reach 100)
  benign dampener = score * (1 - 0.6 * max(benign strengths)); a watch-list "benign" with confidence >= 80 caps the score at 10
  verdict         = malicious if score >= 70, suspicious if score >= 35,
                    benign if a benign signal of strength >= 0.5 exists, otherwise unknown

"unknown" is deliberate: the absence of reports is not evidence of safety. The breakdown lists every signal so an analyst
can see exactly why a score is what it is, plus coverage (how many providers answered or failed) so a low score from
one source is not mistaken for a clean bill of health.
"""

from dataclasses import asdict, dataclass
from typing import Any

WEIGHTS: dict[str, float] = {
    "watchlist": 1.0,
    "misp": 0.9,
    "virustotal": 0.9,
    "threatfox": 0.85,
    "urlhaus": 0.85,
    "otx": 0.6,
    "heuristics": 0.4,
}
MALICIOUS_AT, SUSPICIOUS_AT = 70, 35


@dataclass(frozen=True)
class Signal:
    provider: str
    verdict: str  # malicious | suspicious | benign | unknown
    confidence: int
    summary: str = ""


def score(signals: list[Signal]) -> tuple[int, str, list[dict[str, Any]]]:
    breakdown: list[dict[str, Any]] = []
    survive = 1.0
    max_benign = 0.0
    watch_benign_hard = False
    for s in signals:
        w = WEIGHTS.get(s.provider, 0.5)
        strength = w * max(0, min(100, s.confidence)) / 100
        p = strength if s.verdict == "malicious" else 0.5 * strength if s.verdict == "suspicious" else 0.0
        if s.verdict == "benign":
            max_benign = max(max_benign, strength)
            watch_benign_hard |= s.provider == "watchlist" and s.confidence >= 80
        survive *= 1 - p
        breakdown.append(
            {
                "provider": s.provider,
                "verdict": s.verdict,
                "confidence": s.confidence,
                "weight": w,
                "contribution": round(100 * p, 1),
                "summary": s.summary,
            }
        )
    raw = 100 * (1 - survive)
    adjusted = raw * (1 - 0.6 * max_benign)
    if watch_benign_hard:
        adjusted = min(adjusted, 10)
    final = int(round(max(0, min(100, adjusted))))
    if final >= MALICIOUS_AT:
        verdict = "malicious"
    elif final >= SUSPICIOUS_AT:
        verdict = "suspicious"
    elif max_benign >= 0.5:
        verdict = "benign"
    else:
        verdict = "unknown"
    return final, verdict, breakdown


__all__ = ["Signal", "asdict", "score"]

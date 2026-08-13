from app.risk_scoring.risk_assessment import ScoringBreakdownEntry
from app.risk_scoring.scoring_policy import ScoringPolicy


def calculate_confidence(breakdown: list[ScoringBreakdownEntry], policy: ScoringPolicy) -> float:
    """Independent of risk_score by construction: this never looks at the
    final risk_score or severity weights, only at how strong and how
    independently-corroborated the COUNTED evidence is.

    confidence = w1 * avg(evidence_confidence of counted items)
               + w2 * min(distinct_correlation_groups / N, 1.0)

    Uses correlation-group count (not detector count) as the independence
    proxy, so this stays decoupled from DetectionEngine's composition.
    """

    counted = [entry for entry in breakdown if entry.counted]
    if not counted:
        return 0.0

    avg_confidence = sum(entry.evidence_confidence for entry in counted) / len(counted)

    distinct_groups = {entry.correlation_group for entry in counted}
    weights = policy.confidence_weights
    diversity_ratio = min(len(distinct_groups) / weights.signals_for_full_diversity, 1.0)

    confidence = (
        weights.evidence_confidence_weight * avg_confidence
        + weights.diversity_weight * diversity_ratio
    )
    return round(min(1.0, max(0.0, confidence)), 4)

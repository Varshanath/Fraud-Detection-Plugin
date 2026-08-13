import math

from app.detection.evidence import DetectionEvidence
from app.risk_scoring.risk_assessment import ScoringBreakdownEntry
from app.risk_scoring.scoring_policy import ScoringPolicy


def calculate_risk(
    evidence: list[DetectionEvidence], policy: ScoringPolicy
) -> tuple[int, float, list[ScoringBreakdownEntry]]:
    """Deterministic, additive-with-cap scoring:

    1. Each evidence item's raw contribution = severity_weight * confidence.
    2. Evidence sharing a correlation group (e.g. LOOKALIKE_DOMAIN and
       LOOKALIKE_URL_DOMAIN -- the same underlying fact observed twice) is
       deduplicated: only the highest-contribution item in the group counts.
    3. Counted contributions are summed (raw_score_before_cap), then clamped
       to [0, 100] and floored to an int.

    Returns (risk_score, raw_score_before_cap, scoring_breakdown). The
    breakdown lists every evidence item, counted or not, for full
    traceability: `raw_score_before_cap == sum(e.contribution for e in
    breakdown if e.counted)` always holds.
    """

    groups: dict[str, list[tuple[DetectionEvidence, float]]] = {}
    for item in evidence:
        weight = policy.severity_weights.weight_for(item.severity)
        contribution = round(weight * item.confidence, 2)
        group = policy.correlation_group_for(item.rule_id)
        groups.setdefault(group, []).append((item, contribution))

    breakdown: list[ScoringBreakdownEntry] = []
    raw_score_before_cap = 0.0

    for group, members in groups.items():
        winner_item, winner_contribution = max(members, key=lambda pair: pair[1])
        for item, contribution in members:
            counted = item is winner_item
            suppressed_reason = None
            if not counted:
                suppressed_reason = (
                    f"superseded by {winner_item.rule_id} in correlation group "
                    f"'{group}' (higher contribution: {winner_contribution} > {contribution})"
                )
            breakdown.append(
                ScoringBreakdownEntry(
                    rule_id=item.rule_id,
                    category=item.category,
                    severity=item.severity,
                    evidence_confidence=item.confidence,
                    severity_weight=policy.severity_weights.weight_for(item.severity),
                    contribution=contribution if counted else 0.0,
                    correlation_group=group,
                    counted=counted,
                    suppressed_reason=suppressed_reason,
                )
            )
        raw_score_before_cap += winner_contribution

    risk_score = math.floor(min(100.0, max(0.0, raw_score_before_cap)))
    return risk_score, raw_score_before_cap, breakdown

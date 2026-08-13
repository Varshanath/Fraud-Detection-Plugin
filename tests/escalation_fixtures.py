from app.detection.coverage import DetectorOutcome, DetectorStatus
from app.escalation.detection_coverage import DetectionCoverage
from app.risk_scoring.enums import RecommendedAction, RiskClassification
from app.risk_scoring.risk_assessment import RiskAssessment

_ACTION_FOR_CLASSIFICATION = {
    RiskClassification.SAFE: RecommendedAction.ALLOW,
    RiskClassification.LOW_RISK: RecommendedAction.MONITOR,
    RiskClassification.SUSPICIOUS: RecommendedAction.WARN,
    RiskClassification.HIGH_RISK: RecommendedAction.QUARANTINE,
    RiskClassification.CRITICAL: RecommendedAction.BLOCK,
}


def _classification_for(risk_score: int) -> RiskClassification:
    if risk_score <= 19:
        return RiskClassification.SAFE
    if risk_score <= 39:
        return RiskClassification.LOW_RISK
    if risk_score <= 69:
        return RiskClassification.SUSPICIOUS
    if risk_score <= 89:
        return RiskClassification.HIGH_RISK
    return RiskClassification.CRITICAL


def make_risk_assessment(risk_score: int, confidence: float, **overrides) -> RiskAssessment:
    classification = overrides.pop("classification", None) or _classification_for(risk_score)
    defaults = dict(
        risk_score=risk_score,
        confidence=confidence,
        classification=classification,
        recommended_action=_ACTION_FOR_CLASSIFICATION[classification],
        scoring_breakdown=[],
        raw_score_before_cap=float(risk_score),
    )
    defaults.update(overrides)
    return RiskAssessment(**defaults)


def complete_coverage(*names: str) -> DetectionCoverage:
    detector_names = names or ("RuleEngine", "SenderAnalyzer", "URLAnalyzer")
    return DetectionCoverage(
        detector_statuses=[
            DetectorStatus(detector_name=n, outcome=DetectorOutcome.SUCCEEDED)
            for n in detector_names
        ]
    )


def coverage_with_failures(
    failed_names: list[str], succeeded_names: list[str] | None = None
) -> DetectionCoverage:
    succeeded_names = succeeded_names or []
    statuses = [
        DetectorStatus(detector_name=n, outcome=DetectorOutcome.SUCCEEDED) for n in succeeded_names
    ]
    statuses += [
        DetectorStatus(detector_name=n, outcome=DetectorOutcome.FAILED) for n in failed_names
    ]
    return DetectionCoverage(detector_statuses=statuses)

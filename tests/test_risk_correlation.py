from app.detection.enums import EvidenceCategory, Severity
from app.risk_scoring.risk_calculator import calculate_risk
from app.risk_scoring.scoring_policy import default_scoring_policy
from tests.risk_fixtures import make_evidence

policy = default_scoring_policy()


def test_independent_evidence_both_fully_counted():
    evidence = [
        make_evidence(rule_id="A", severity=Severity.HIGH, confidence=0.8),
        make_evidence(rule_id="B", severity=Severity.HIGH, confidence=0.8),
    ]
    score, raw, breakdown = calculate_risk(evidence, policy)
    assert all(entry.counted for entry in breakdown)
    assert raw == breakdown[0].contribution + breakdown[1].contribution


def test_correlated_lookalike_evidence_only_max_counted():
    evidence = [
        make_evidence(
            rule_id="LOOKALIKE_DOMAIN",
            category=EvidenceCategory.SENDER_SPOOFING,
            severity=Severity.HIGH,
            confidence=0.9,
        ),
        make_evidence(
            rule_id="LOOKALIKE_URL_DOMAIN",
            category=EvidenceCategory.SUSPICIOUS_URL,
            severity=Severity.HIGH,
            confidence=0.95,
        ),
    ]
    score, raw, breakdown = calculate_risk(evidence, policy)

    counted = [e for e in breakdown if e.counted]
    suppressed = [e for e in breakdown if not e.counted]
    assert len(counted) == 1
    assert len(suppressed) == 1
    assert counted[0].rule_id == "LOOKALIKE_URL_DOMAIN"  # higher confidence -> higher contribution
    assert suppressed[0].rule_id == "LOOKALIKE_DOMAIN"
    assert suppressed[0].suppressed_reason is not None
    assert suppressed[0].contribution == 0.0
    # Score reflects only the winning item's contribution, not both summed.
    assert raw == counted[0].contribution


def test_correlated_evidence_does_not_double_count_vs_single_item():
    single = calculate_risk(
        [
            make_evidence(
                rule_id="LOOKALIKE_URL_DOMAIN",
                category=EvidenceCategory.SUSPICIOUS_URL,
                severity=Severity.HIGH,
                confidence=0.95,
            )
        ],
        policy,
    )[0]
    correlated_pair = calculate_risk(
        [
            make_evidence(
                rule_id="LOOKALIKE_DOMAIN",
                category=EvidenceCategory.SENDER_SPOOFING,
                severity=Severity.HIGH,
                confidence=0.9,
            ),
            make_evidence(
                rule_id="LOOKALIKE_URL_DOMAIN",
                category=EvidenceCategory.SUSPICIOUS_URL,
                severity=Severity.HIGH,
                confidence=0.95,
            ),
        ],
        policy,
    )[0]
    assert correlated_pair == single


def test_duplicate_same_rule_id_evidence_only_counts_once():
    evidence = [
        make_evidence(rule_id="URGENCY_PRESSURE", severity=Severity.HIGH, confidence=0.5),
        make_evidence(rule_id="URGENCY_PRESSURE", severity=Severity.HIGH, confidence=0.9),
    ]
    score, raw, breakdown = calculate_risk(evidence, policy)
    counted = [e for e in breakdown if e.counted]
    assert len(counted) == 1
    assert counted[0].evidence_confidence == 0.9


def test_multiple_signals_same_category_different_rule_ids_stay_additive():
    # Six distinct SUSPICIOUS_URL rule_ids -- genuinely different facts about
    # one URL, not the same fact twice -- must NOT be collapsed into one.
    rule_ids = [
        "IP_ADDRESS_URL",
        "INSECURE_HTTP_URL",
        "EXCESSIVE_URL_LENGTH",
        "EXCESSIVE_SUBDOMAINS",
        "OBFUSCATED_URL",
        "SUSPICIOUS_QUERY_PARAMETER",
    ]
    evidence = [
        make_evidence(
            rule_id=rule_id,
            category=EvidenceCategory.SUSPICIOUS_URL,
            severity=Severity.MEDIUM,
            confidence=0.7,
        )
        for rule_id in rule_ids
    ]
    score, raw, breakdown = calculate_risk(evidence, policy)
    assert all(entry.counted for entry in breakdown)
    # Still bounded even though additive and same category.
    assert 0 <= score <= 100


def test_uncontrolled_inflation_is_prevented_by_global_clamp():
    evidence = [
        make_evidence(rule_id=f"RULE_{i}", severity=Severity.CRITICAL, confidence=1.0)
        for i in range(15)
    ]
    score, raw, breakdown = calculate_risk(evidence, policy)
    assert score == 100
    assert raw > 100

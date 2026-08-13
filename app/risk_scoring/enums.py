from enum import Enum


class RiskClassification(str, Enum):
    SAFE = "SAFE"
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"


class RecommendedAction(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    WARN = "WARN"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"

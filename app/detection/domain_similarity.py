from collections.abc import Iterable
from dataclasses import dataclass

_MAX_DOMAIN_LENGTH = 253  # DNS's own maximum domain length -- bounds the DP table below
_DEFAULT_THRESHOLD = 0.85

# Common leetspeak / homoglyph-style character substitutions used to make a
# lookalike domain read as the original word to a human eye.
_SUBSTITUTIONS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"}


@dataclass(frozen=True)
class DomainSimilarityResult:
    observed_domain: str
    reference_domain: str
    similarity: float
    reason: str


def _delete_common_substitutions(value: str) -> str:
    return "".join(_SUBSTITUTIONS.get(ch, ch) for ch in value)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i] + [0] * len(b)
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            current_row[j] = min(
                previous_row[j] + 1,  # deletion
                current_row[j - 1] + 1,  # insertion
                previous_row[j - 1] + cost,  # substitution
            )
        previous_row = current_row
    return previous_row[-1]


def _similarity_ratio(a: str, b: str) -> float:
    longer = max(len(a), len(b))
    if longer == 0:
        return 1.0
    return 1.0 - (_levenshtein(a, b) / longer)


class DomainSimilarityAnalyzer:
    """Reusable, deterministic domain lookalike detector.

    Bounded: inputs longer than `_MAX_DOMAIN_LENGTH` (DNS's own max) are
    skipped rather than compared, so an attacker-supplied huge string cannot
    force excessive computation. Uses a hand-rolled Levenshtein distance
    (pure stdlib) rather than an external library -- domain strings are
    short and the reference set is small, so a library isn't genuinely
    necessary here.
    """

    def __init__(self, threshold: float = _DEFAULT_THRESHOLD) -> None:
        self.threshold = threshold

    def normalize(self, domain: str) -> str:
        value = (domain or "").strip().lower().rstrip(".")
        if value.startswith("www."):
            value = value[4:]
        labels = value.split(".")
        if len(labels) > 2:
            # Practical registrable-domain approximation, not a full public
            # suffix list -- documented limitation (mishandles multi-part
            # TLDs like .co.uk), acceptable for this phase's small, curated
            # comparison set.
            value = ".".join(labels[-2:])
        return value

    def compare(self, observed: str, reference: str) -> DomainSimilarityResult:
        observed_norm = self.normalize(observed)
        reference_norm = self.normalize(reference)

        if len(observed_norm) > _MAX_DOMAIN_LENGTH or len(reference_norm) > _MAX_DOMAIN_LENGTH:
            return DomainSimilarityResult(observed_norm, reference_norm, 0.0, "too_long_to_compare")

        if observed_norm == reference_norm:
            return DomainSimilarityResult(observed_norm, reference_norm, 1.0, "exact_match")

        raw_similarity = _similarity_ratio(observed_norm, reference_norm)
        desubstituted_similarity = _similarity_ratio(
            _delete_common_substitutions(observed_norm), reference_norm
        )

        if desubstituted_similarity > raw_similarity:
            return DomainSimilarityResult(
                observed_norm, reference_norm, desubstituted_similarity, "character_substitution"
            )
        return DomainSimilarityResult(observed_norm, reference_norm, raw_similarity, "edit_distance")

    def find_best_match(
        self, observed: str, candidate_domains: Iterable[str], threshold: float | None = None
    ) -> DomainSimilarityResult | None:
        effective_threshold = self.threshold if threshold is None else threshold
        best: DomainSimilarityResult | None = None

        for candidate in candidate_domains:
            result = self.compare(observed, candidate)
            if result.reason == "exact_match":
                continue  # legitimate, not a lookalike
            if result.similarity < effective_threshold:
                continue
            if best is None or result.similarity > best.similarity:
                best = result

        return best

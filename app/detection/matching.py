import re
from collections.abc import Sequence

_TOKEN_RE = re.compile(r"[a-zA-Z0-9']+(?:-[a-zA-Z0-9']+)*")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def compile_phrase_pattern(phrase: str) -> re.Pattern[str]:
    tokens = phrase.split()
    escaped = r"\s+".join(re.escape(token) for token in tokens)
    return re.compile(rf"\b{escaped}\b", re.IGNORECASE)


def find_matches(text: str | None, phrases: Sequence[str]) -> list[str]:
    """Return the distinct phrases (from `phrases`, order preserved) present in `text`."""
    if not text:
        return []
    matches = []
    for phrase in phrases:
        if compile_phrase_pattern(phrase).search(text):
            matches.append(phrase)
    return matches


def split_sentences(text: str | None) -> list[str]:
    if not text:
        return []
    return [s for s in _SENTENCE_SPLIT_RE.split(text.strip()) if s]


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text)]


def _find_phrase_positions(tokens: list[str], phrase: str) -> list[tuple[int, int]]:
    phrase_tokens = _tokenize(phrase)
    n = len(phrase_tokens)
    if n == 0:
        return []
    positions = []
    for i in range(len(tokens) - n + 1):
        if tokens[i : i + n] == phrase_tokens:
            positions.append((i, i + n - 1))
    return positions


def verb_noun_cooccurs(
    sentence: str, verbs: Sequence[str], nouns: Sequence[str], max_gap_words: int = 4
) -> list[str]:
    """Return distinct nouns that co-occur with a verb (either order) within
    `max_gap_words` words of each other in `sentence`.
    """
    tokens = _tokenize(sentence)
    verb_spans = [span for verb in verbs for span in _find_phrase_positions(tokens, verb)]
    if not verb_spans:
        return []

    matched: list[str] = []
    for noun in nouns:
        for n_start, n_end in _find_phrase_positions(tokens, noun):
            for v_start, v_end in verb_spans:
                if v_end < n_start:
                    distance = n_start - v_end - 1
                elif n_end < v_start:
                    distance = v_start - n_end - 1
                else:
                    distance = 0
                if distance <= max_gap_words:
                    matched.append(noun)
                    break
            else:
                continue
            break
    return matched


def find_requested_terms(
    text: str | None, verbs: Sequence[str], nouns: Sequence[str], max_gap_words: int = 4
) -> list[str]:
    """Sentence-scoped version of `verb_noun_cooccurs`, aggregated over the whole text."""
    if not text:
        return []
    matched: list[str] = []
    for sentence in split_sentences(text):
        for noun in verb_noun_cooccurs(sentence, verbs, nouns, max_gap_words):
            if noun not in matched:
                matched.append(noun)
    return matched


def scored_confidence(
    match_count: int, base: float, increment: float = 0.15, cap: float = 0.95
) -> float:
    if match_count <= 0:
        return 0.0
    return min(base + increment * max(match_count - 1, 0), cap)

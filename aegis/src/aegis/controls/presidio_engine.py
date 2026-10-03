"""Microsoft Presidio as the single detection engine for data controls.

PII, secrets and DLP all run through one shared Presidio ``AnalyzerEngine``
(spaCy ``en_core_web_sm`` for NER + Presidio's validated pattern recognizers)
and are masked with Presidio's ``AnonymizerEngine``. Presidio has no built-in
recognizers for Polish identifiers or API credentials, so this module registers
custom ones: PESEL and NRB with checksum validation, plus credential formats.

Policy files keep using short category names (``email``, ``iban``, ``pesel``,
``aws_access_key`` …); ``CATEGORIES`` maps each to a Presidio entity type and a
mask token.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from aegis.policy.models import Strictness

DEFAULT_SPACY_MODEL = "en_core_web_sm"


@dataclass(frozen=True)
class Category:
    entity: str
    mask: str


CATEGORIES: dict[str, Category] = {
    # --- PII (Presidio built-ins, NER-backed where applicable) ---
    "email": Category("EMAIL_ADDRESS", "[REDACTED_EMAIL]"),
    "phone": Category("PHONE_NUMBER", "[REDACTED_PHONE]"),
    "ssn": Category("US_SSN", "[REDACTED_SSN]"),
    "credit_card": Category("CREDIT_CARD", "[REDACTED_CARD]"),
    "iban": Category("IBAN_CODE", "[REDACTED_IBAN]"),
    "ip_address": Category("IP_ADDRESS", "[REDACTED_IP]"),
    "person": Category("PERSON", "[REDACTED_PERSON]"),
    "location": Category("LOCATION", "[REDACTED_LOCATION]"),
    # --- Polish identifiers (custom, checksum-validated) ---
    "pesel": Category("PL_PESEL", "[REDACTED_PESEL]"),
    "account": Category("PL_NRB", "[REDACTED_ACCOUNT]"),
    # --- Secrets (custom recognizers) ---
    "aws_access_key": Category("AWS_ACCESS_KEY", "[REDACTED_AWS_KEY]"),
    "openai_key": Category("OPENAI_API_KEY", "[REDACTED_OPENAI_KEY]"),
    "github_token": Category("GITHUB_TOKEN", "[REDACTED_GITHUB_TOKEN]"),
    "generic_api_key": Category("GENERIC_API_KEY", "[REDACTED_API_KEY]"),
    "private_key": Category("PRIVATE_KEY", "[REDACTED_PRIVATE_KEY]"),
    "bearer_token": Category("BEARER_TOKEN", "[REDACTED_BEARER]"),
}

_CATEGORY_BY_ENTITY = {c.entity: name for name, c in CATEGORIES.items()}

# Minimum Presidio score per strictness (phone numbers score ~0.4 without context).
SCORE_THRESHOLD = {Strictness.HIGH: 0.3, Strictness.MEDIUM: 0.35, Strictness.LOW: 0.5}


class PeselRecognizer(PatternRecognizer):
    """Polish national ID: 11 digits with a weighted checksum."""

    _WEIGHTS = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)

    def __init__(self) -> None:
        super().__init__(
            supported_entity="PL_PESEL",
            patterns=[Pattern("pesel", r"\b\d{11}\b", 0.5)],
            context=["pesel"],
        )

    def validate_result(self, pattern_text: str) -> bool:
        digits = [int(c) for c in pattern_text]
        check = (10 - sum(w * d for w, d in zip(self._WEIGHTS, digits, strict=False)) % 10) % 10
        return check == digits[10]


class NrbRecognizer(PatternRecognizer):
    """Polish bank account (NRB): 26 digits, validated as the IBAN 'PL' + NRB (mod 97)."""

    def __init__(self) -> None:
        super().__init__(
            supported_entity="PL_NRB",
            patterns=[Pattern("nrb", r"\b\d{2}(?:[ ]?\d{4}){6}\b", 0.6)],
            context=["konto", "account", "rachunek", "nrb"],
        )

    def validate_result(self, pattern_text: str) -> bool:
        digits = pattern_text.replace(" ", "")
        if len(digits) != 26:
            return False
        rearranged = digits[2:] + "2521" + digits[:2]  # P=25, L=21
        return int(rearranged) % 97 == 1


def _secret(entity: str, name: str, regex: str, score: float = 0.95) -> PatternRecognizer:
    return PatternRecognizer(supported_entity=entity, patterns=[Pattern(name, regex, score)])


# Structural context, always analyzed but never reported: a hit strictly inside one
# of these spans (e.g. a Luhn-valid 16-digit run inside a 26-digit account number)
# is a fragment, not an entity of its own. DIGIT_RUN is a 26-digit, NRB-shaped run
# (any checksum, space or dash separated): a wider run would let a card hide by
# appending digits.
DIGIT_RUN = "DIGIT_RUN"
_CONTEXT_ENTITIES = [DIGIT_RUN, "PL_NRB", "IBAN_CODE"]


def _custom_recognizers() -> list[PatternRecognizer]:
    return [
        _secret(DIGIT_RUN, "digit_run", r"\b\d{2}(?:[ -]?\d{4}){6}\b", 0.6),
        PeselRecognizer(),
        NrbRecognizer(),
        _secret("AWS_ACCESS_KEY", "aws", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        _secret("OPENAI_API_KEY", "openai", r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        _secret(
            "GITHUB_TOKEN",
            "github",
            r"\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b",
        ),
        _secret(
            "GENERIC_API_KEY",
            "generic",
            # Quoted keys (JSON/YAML) too; the value runs to the next quote, space or delimiter
            # so base64 tails (``/+=``) are masked with it.
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)['\"]?"
            r"\s*[:=]\s*['\"]?[^\s'\",;]{16,}",
            0.85,
        ),
        # The whole block, body included; an unterminated block is masked to the end.
        _secret(
            "PRIVATE_KEY",
            "pem",
            r"-----BEGIN [A-Z ]{0,20}PRIVATE KEY(?: BLOCK)?-----[\s\S]*?"
            r"(?:-----END [A-Z ]{0,20}PRIVATE KEY(?: BLOCK)?-----|\Z)",
        ),
        # The auth scheme is case-insensitive (RFC 9110); the length rules out prose.
        _secret("BEARER_TOKEN", "bearer", r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*"),
    ]


# spaCy labels with no Presidio meaning; ignoring them keeps logs quiet and NER fast.
_IGNORED_NER_LABELS = [
    "CARDINAL", "ORDINAL", "QUANTITY", "MONEY", "PERCENT", "WORK_OF_ART",
    "LANGUAGE", "LAW", "EVENT", "PRODUCT", "FAC",
]


class _Presidio:
    """Lazily built, process-wide analyzer + anonymizer (spaCy load is ~0.5 s)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._analyzer: AnalyzerEngine | None = None
        self._anonymizer = AnonymizerEngine()

    @property
    def analyzer(self) -> AnalyzerEngine:
        if self._analyzer is None:
            with self._lock:
                if self._analyzer is None:
                    model = os.environ.get("AEGIS_SPACY_MODEL", DEFAULT_SPACY_MODEL)
                    nlp = NlpEngineProvider(
                        nlp_configuration={
                            "nlp_engine_name": "spacy",
                            "models": [{"lang_code": "en", "model_name": model}],
                            "ner_model_configuration": {"labels_to_ignore": _IGNORED_NER_LABELS},
                        }
                    ).create_engine()
                    analyzer = AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])
                    for recognizer in _custom_recognizers():
                        analyzer.registry.add_recognizer(recognizer)
                    self._analyzer = analyzer
        return self._analyzer

    def anonymize(self, text: str, results: list[RecognizerResult]) -> str:
        operators = {
            r.entity_type: OperatorConfig("replace", {"new_value": CATEGORIES[_CATEGORY_BY_ENTITY[r.entity_type]].mask})
            for r in results
        }
        return self._anonymizer.anonymize(text=text, analyzer_results=results, operators=operators).text


PRESIDIO = _Presidio()


def _drop_contained(results: list[RecognizerResult]) -> list[RecognizerResult]:
    """Drop a hit lying strictly inside a longer hit that is stronger or a raw digit run."""
    kept: list[RecognizerResult] = []
    for r in results:
        shadowed = any(
            o is not r
            and o.start <= r.start
            and r.end <= o.end
            and (o.end - o.start) > (r.end - r.start)
            and (o.score >= r.score or o.entity_type == DIGIT_RUN)
            for o in results
        )
        if not shadowed:
            kept.append(r)
    return kept


@dataclass(frozen=True)
class Detection:
    category: str
    score: float
    start: int
    end: int


def detect(
    text: str,
    categories: list[str],
    strictness: Strictness,
    *,
    min_score: float | None = None,
) -> tuple[list[Detection], list[RecognizerResult]]:
    """``min_score`` (a control's ``adherence``) overrides the strictness default."""
    entities = [CATEGORIES[c].entity for c in categories if c in CATEGORIES]
    if not text or not entities:
        return [], []
    raw = PRESIDIO.analyzer.analyze(
        text=text,
        language="en",
        entities=sorted(set(entities) | set(_CONTEXT_ENTITIES)),
        score_threshold=SCORE_THRESHOLD[strictness] if min_score is None else min_score,
    )
    wanted = set(entities)
    results = [r for r in _drop_contained(raw) if r.entity_type in wanted]
    detections = [
        Detection(_CATEGORY_BY_ENTITY[r.entity_type], round(r.score, 3), r.start, r.end)
        for r in sorted(results, key=lambda r: r.start)
    ]
    return detections, results


def detect_and_mask(
    text: str,
    categories: list[str],
    strictness: Strictness,
    *,
    mask: bool,
    min_score: float | None = None,
) -> tuple[list[Detection], str]:
    detections, results = detect(text, categories, strictness, min_score=min_score)
    if not mask or not results:
        return detections, text
    return detections, PRESIDIO.anonymize(text, results)


def warm_up() -> None:
    """Load the spaCy model ahead of the first request."""
    PRESIDIO.analyzer.analyze(text="warm up", language="en", entities=["EMAIL_ADDRESS"])

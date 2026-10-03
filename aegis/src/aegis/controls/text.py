"""Text views shared by the signature-based controls."""

from __future__ import annotations

import unicodedata


def normalize_for_matching(text: str) -> str:
    """NFKC-fold and drop invisible format characters so they cannot split a signature."""
    folded = unicodedata.normalize("NFKC", text)
    return "".join(c for c in folded if unicodedata.category(c) != "Cf")

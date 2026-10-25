"""Discovery — unified intermediate format bridging analytics engines to the
Librarian (scribe) for automatic spectral engraving.

All analytics engines (Apriori, FCA, Invariant, NCD, Category, Causality)
produce Discovery objects. The Scribe Pipeline consumes them to generate,
update, or flag gaps in capabilities/ spectral entries.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class Discovery:
    """A knowledge discovery from an analytics engine.

    Designed as the universal output format for Phase 1 (管道化) of the
    Librarian-Analytics integration architecture.
    """

    source: str
    intent: str
    domain: str
    abstraction: float
    content: str
    evidence: List[str] = field(default_factory=list)
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ── intent constants ──
    INTENT_NEW_SPECTRUM = "new_spectrum"
    INTENT_UPDATE_SPECTRUM = "update_spectrum"
    INTENT_GAP = "gap"
    INTENT_SYNONYM = "synonym"
    INTENT_ISOMORPHISM = "isomorphism"

    # ── source constants ──
    SOURCE_APRIORI = "apriori"
    SOURCE_FCA = "fca"
    SOURCE_INVARIANT = "invariant"
    SOURCE_NCD = "ncd"
    SOURCE_CATEGORY = "category"
    SOURCE_CAUSALITY = "causality"
    SOURCE_ANOMALY = "anomaly"
    SOURCE_META_CORRELATION = "meta_correlation"
    SOURCE_HOMOLOGY = "homology"
    SOURCE_CUP = "cup"

    # ── abstraction bands (from spectrum.py) ──
    BAND_TOOL = (0.00, 0.15)
    BAND_TECHNIQUE_LOW = (0.15, 0.35)
    BAND_TECHNIQUE_HIGH = (0.35, 0.55)
    BAND_PATTERN_LOW = (0.55, 0.75)
    BAND_PATTERN_HIGH = (0.75, 0.90)
    BAND_PRINCIPLE = (0.90, 1.00)

    def __post_init__(self):
        if self.abstraction < 0.0 or self.abstraction > 1.0:
            raise ValueError(
                f"abstraction must be in [0.0, 1.0], got {self.abstraction}"
            )

    @property
    def band(self) -> str:
        a = self.abstraction
        if a < 0.15:
            return "tool_command"
        elif a < 0.55:
            return "technique"
        elif a < 0.90:
            return "pattern"
        else:
            return "principle"

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "intent": self.intent,
            "domain": self.domain,
            "abstraction": self.abstraction,
            "band": self.band,
            "content": self.content,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        return (
            f"Discovery({self.source}/{self.intent} → {self.domain} "
            f"@{self.abstraction:.2f} [{self.band}] conf={self.confidence:.2f})"
        )

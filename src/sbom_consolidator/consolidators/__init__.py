"""
SBOM consolidation components for merging and deduplicating multiple SBOMs.
"""

from .sbom_consolidator import SBOMConsolidator
from .deduplicator import Deduplicator
from .merger import Merger

__all__ = [
    "SBOMConsolidator",
    "Deduplicator",
    "Merger"
]
"""
Rule validator package (Phase 2).

Exports the file-level validator and the decision-matrix verdict model.
"""

from .pipeline import ValidationVerdict, decide, validate_file

__all__ = ["ValidationVerdict", "decide", "validate_file"]

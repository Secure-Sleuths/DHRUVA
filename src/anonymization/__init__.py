"""
Alert anonymization layer — strips client-sensitive identifiers from
prompts sent to external LLMs while preserving triage-relevant context.
"""

from src.anonymization.anonymizer import AlertAnonymizer

__all__ = ["AlertAnonymizer"]

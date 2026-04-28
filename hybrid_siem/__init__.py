"""Hybrid SIEM Phase 1 package."""

from .dataset import generate_feature_dataset
from .normalization import build_canonical_attempts
from .synthetic import build_synthetic_training_corpus

__all__ = ["build_canonical_attempts", "build_synthetic_training_corpus", "generate_feature_dataset"]

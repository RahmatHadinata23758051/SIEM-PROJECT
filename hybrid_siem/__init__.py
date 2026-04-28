"""Hybrid SIEM package."""

from .anomaly import fit_isolation_forest, load_isolation_forest
from .dataset import generate_feature_dataset
from .normalization import build_canonical_attempts
from .pipeline import PipelineDecision, process_feature_records
from .risk import RiskScoreResult, RiskWeights, compute_risk_score
from .synthetic import build_synthetic_training_corpus
from .temporal import TemporalFeatureComputer, TemporalFeatures
from .watchlist import WatchlistEntry, WatchlistManager

__all__ = [
    "build_canonical_attempts",
    "build_synthetic_training_corpus",
    "compute_risk_score",
    "fit_isolation_forest",
    "generate_feature_dataset",
    "load_isolation_forest",
    "PipelineDecision",
    "process_feature_records",
    "RiskScoreResult",
    "RiskWeights",
    "TemporalFeatureComputer",
    "TemporalFeatures",
    "WatchlistEntry",
    "WatchlistManager",
]

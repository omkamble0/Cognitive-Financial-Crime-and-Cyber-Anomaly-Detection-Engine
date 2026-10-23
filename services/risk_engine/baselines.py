"""
FinCipher AI — Entity Behavioral Baseline & Profiling Engine
Author: Om Kamble
"""

import time
import math
from typing import Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field


class BaselineEvaluation(BaseModel):
    entity_id: str
    metric_name: str
    actual_value: float
    expected_mean: float
    expected_std: float
    z_score: float
    is_anomalous: bool
    deviation_ratio: float
    confidence: float


class EntityBaselineProfile:
    """Maintains statistical baseline profiles using Welford's running variance algorithm."""

    def __init__(self, alpha: float = 0.05):
        # Smoothing factor for Exponential Moving Statistics
        self.alpha = alpha
        self.count: int = 0
        self.mean: float = 0.0
        self.var: float = 0.0
        self.last_updated: float = time.time()

    def update(self, value: float) -> Tuple[float, float, float]:
        """Updates mean and variance and returns (mean, std, z_score)."""
        self.count += 1
        if self.count == 1:
            self.mean = value
            self.var = 1.0  # Initial nominal variance
            return self.mean, math.sqrt(self.var), 0.0

        # Welford / EMA update
        diff = value - self.mean
        self.mean += self.alpha * diff
        self.var = (1.0 - self.alpha) * self.var + self.alpha * (diff ** 2)
        std = max(0.1, math.sqrt(self.var))
        z_score = abs(value - self.mean) / std
        self.last_updated = time.time()
        return self.mean, std, z_score


class EntityBehaviorBaselineEngine:
    """
    Manages multi-metric behavioral baselines for all entities across domains.
    Profiles spend ticket sizes, request cadence, and access hour distributions.
    """

    def __init__(self, z_score_threshold: float = 3.0):
        self.z_score_threshold = z_score_threshold
        # Key: (entity_id, metric_name) -> EntityBaselineProfile
        self._profiles: Dict[Tuple[str, str], EntityBaselineProfile] = {}

    def evaluate_metric(
        self,
        entity_id: str,
        metric_name: str,
        value: float,
        update_baseline: bool = True
    ) -> BaselineEvaluation:
        """
        Evaluates an observed metric against the entity's historical baseline.
        Returns a BaselineEvaluation with anomaly flagging.
        """
        key = (entity_id, metric_name)
        profile = self._profiles.get(key)

        if not profile:
            profile = EntityBaselineProfile()
            self._profiles[key] = profile

        curr_mean = profile.mean if profile.count > 0 else value
        curr_std = math.sqrt(profile.var) if profile.count > 1 else max(1.0, value * 0.2)

        if update_baseline:
            mean, std, z_score = profile.update(value)
        else:
            mean = curr_mean
            std = curr_std
            z_score = abs(value - mean) / std

        is_anomalous = (profile.count >= 3) and (z_score >= self.z_score_threshold)
        deviation_ratio = (value / max(1.0, mean)) if mean > 0 else 1.0
        confidence = min(0.99, profile.count / 10.0)

        return BaselineEvaluation(
            entity_id=entity_id,
            metric_name=metric_name,
            actual_value=value,
            expected_mean=round(mean, 2),
            expected_std=round(std, 2),
            z_score=round(z_score, 2),
            is_anomalous=is_anomalous,
            deviation_ratio=round(deviation_ratio, 2),
            confidence=round(confidence, 2)
        )

    def get_profile_summary(self, entity_id: str) -> Dict[str, Any]:
        """Summarizes all behavioral profiles tracked for an entity."""
        summary = {}
        for (eid, metric), prof in self._profiles.items():
            if eid == entity_id:
                summary[metric] = {
                    "observations": prof.count,
                    "mean": round(prof.mean, 2),
                    "std": round(math.sqrt(prof.var), 2)
                }
        return summary


# Singleton baseline engine
behavior_baseline_engine = EntityBehaviorBaselineEngine()

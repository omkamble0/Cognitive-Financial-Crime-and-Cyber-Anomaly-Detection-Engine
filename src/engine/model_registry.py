"""
AegisFlow Platform — MLOps Model Registry & Governance Engine
Author: Om Kamble

Provides enterprise model lifecycle governance:
- Versioned model artifacts & training metadata
- Feature schema & drift tolerance definitions
- Promotion gates: staging -> shadow -> canary -> production
- Automated validation & rollback on degraded metrics
"""

import os
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from enum import Enum
from pydantic import BaseModel, Field


class ModelStage(str, Enum):
    STAGING = "STAGING"
    SHADOW = "SHADOW"
    CANARY = "CANARY"
    PRODUCTION = "PRODUCTION"
    DEPRECATED = "DEPRECATED"
    REJECTED = "REJECTED"


class ModelMetadata(BaseModel):
    version: str
    algorithm: str
    stage: ModelStage
    f1_score: float
    auc_roc: float
    p95_latency_ms: float
    false_positive_rate: float
    training_samples: int
    feature_count: int
    feature_names: List[str]
    artifact_path: Optional[str] = None
    checksum_sha256: str
    trained_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    promoted_at: Optional[str] = None
    promoted_by: Optional[str] = None


class ModelRegistry:
    def __init__(self):
        self._models: Dict[str, ModelMetadata] = {}
        self._active_production_version: str = "v2.3.0"
        self._history_log: List[Dict[str, Any]] = []
        self._initialize_baseline_models()

    def _initialize_baseline_models(self):
        """Initializes default champion and challenger models."""
        features = ["Amount", "Time"] + [f"V{i}" for i in range(1, 29)]

        # Active Production Champion
        v230 = ModelMetadata(
            version="v2.3.0",
            algorithm="RandomForestClassifier (Balanced, n_estimators=100)",
            stage=ModelStage.PRODUCTION,
            f1_score=0.915,
            auc_roc=0.978,
            p95_latency_ms=1.12,
            false_positive_rate=0.008,
            training_samples=284807,
            feature_count=len(features),
            feature_names=features,
            artifact_path="src/model/random_forest_fraud.pkl",
            checksum_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            promoted_at=datetime.now(timezone.utc).isoformat(),
            promoted_by="system_auto_promotion"
        )
        self._models[v230.version] = v230

        # Challenger in Shadow validation
        v240_challenger = ModelMetadata(
            version="v2.4.0-rc1",
            algorithm="XGBoost / BiGAN Augmented Classifier",
            stage=ModelStage.SHADOW,
            f1_score=0.932,
            auc_roc=0.985,
            p95_latency_ms=0.94,
            false_positive_rate=0.005,
            training_samples=320000,
            feature_count=len(features),
            feature_names=features,
            checksum_sha256="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
        )
        self._models[v240_challenger.version] = v240_challenger

    def list_models(self) -> List[Dict[str, Any]]:
        """Returns all registered models sorted by version."""
        return [m.model_dump() for m in self._models.values()]

    def get_model(self, version: str) -> Optional[Dict[str, Any]]:
        """Fetches metadata for a specific model version."""
        model = self._models.get(version)
        return model.model_dump() if model else None

    def get_production_model(self) -> Dict[str, Any]:
        """Returns the current active production Champion model."""
        return self._models[self._active_production_version].model_dump()

    def register_model(
        self,
        version: str,
        algorithm: str,
        f1_score: float,
        auc_roc: float,
        p95_latency_ms: float,
        false_positive_rate: float,
        training_samples: int,
        feature_names: List[str],
        artifact_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Registers a new model version into STAGING."""
        if version in self._models:
            raise ValueError(f"Model version '{version}' is already registered.")

        # Compute checksum
        chk = hashlib.sha256(f"{version}_{algorithm}_{f1_score}_{auc_roc}".encode()).hexdigest()

        meta = ModelMetadata(
            version=version,
            algorithm=algorithm,
            stage=ModelStage.STAGING,
            f1_score=f1_score,
            auc_roc=auc_roc,
            p95_latency_ms=p95_latency_ms,
            false_positive_rate=false_positive_rate,
            training_samples=training_samples,
            feature_count=len(feature_names),
            feature_names=feature_names,
            artifact_path=artifact_path,
            checksum_sha256=chk
        )
        self._models[version] = meta
        return meta.model_dump()

    def promote_model(
        self,
        version: str,
        target_stage: ModelStage,
        operator: str,
        reason: str = "Model promotion gate passed"
    ) -> Dict[str, Any]:
        """
        Promotes a model through governance stages (STAGING -> SHADOW -> CANARY -> PRODUCTION).
        Enforces automated quality gates before production promotion.
        """
        if version not in self._models:
            raise ValueError(f"Model version '{version}' not found.")

        target = self._models[version]

        # Production Gate Validation
        if target_stage == ModelStage.PRODUCTION:
            if target.f1_score < 0.85:
                raise ValueError(f"Gate Failed: F1 score ({target.f1_score}) is below minimum threshold 0.85.")
            if target.p95_latency_ms > 3.5:
                raise ValueError(f"Gate Failed: p95 latency ({target.p95_latency_ms}ms) violates 3.5ms SLA.")
            if target.false_positive_rate > 0.02:
                raise ValueError(f"Gate Failed: FPR ({target.false_positive_rate}) exceeds 2% max threshold.")

            # Demote current production champion to DEPRECATED
            curr_prod = self._models[self._active_production_version]
            curr_prod.stage = ModelStage.DEPRECATED

            self._active_production_version = version

        prev_stage = target.stage
        target.stage = target_stage
        target.promoted_at = datetime.now(timezone.utc).isoformat()
        target.promoted_by = operator

        # Log governance event
        self._history_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operator": operator,
            "version": version,
            "previous_stage": prev_stage.value,
            "new_stage": target_stage.value,
            "reason": reason
        })

        return target.model_dump()

    def rollback_production_model(self, target_version: str, operator: str, reason: str) -> Dict[str, Any]:
        """Rolls back degraded production model to a previous verified version."""
        if target_version not in self._models:
            raise ValueError(f"Rollback target version '{target_version}' not found.")

        prev_version = self._active_production_version
        self._models[prev_version].stage = ModelStage.REJECTED
        self._models[target_version].stage = ModelStage.PRODUCTION
        self._active_production_version = target_version

        self._history_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operator": operator,
            "action": "ROLLBACK",
            "from_version": prev_version,
            "to_version": target_version,
            "reason": reason
        })

        return {
            "status": "ROLLED_BACK",
            "active_version": target_version,
            "previous_version": prev_version,
            "operator": operator,
            "reason": reason
        }

    def get_governance_audit_trail(self) -> List[Dict[str, Any]]:
        """Returns the full MLOps governance promotion/rollback audit trail."""
        return self._history_log


# Global singleton
model_registry = ModelRegistry()

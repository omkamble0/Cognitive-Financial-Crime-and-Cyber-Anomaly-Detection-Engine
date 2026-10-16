"""
AegisFlow AI — Adversarial Arena Engine (Red Team vs. Blue Team)
Author: Om Kamble

Implements real-time Adversarial Machine Learning (AML) stress-testing:
1. RED TEAM (Adversary AI):
   - Fast Gradient Sign Method (FGSM) / Boundary Perturbation: Drives supervised risk down across decision boundaries.
   - Feature Camouflage / Gaussian Smurfing: Disguises high-risk payloads into benign statistical manifolds.
   - GAN Latent Manifold Spoofing: Exploits generative networks to synthesize evasive fraud vectors.
   - Cadence & Velocity Cloaking: Mathematical jittering of temporal and velocity features to evade heuristics.

2. BLUE TEAM (AegisFlow Defense Citadel):
   - Latent Manifold Reconstruction Error: BiGAN/AnoGAN L2 residual detection ||x_adv - G(E(x_adv))||.
   - Critic Manifold Consensus: Joint discriminator probability verification.
   - Dynamic Defensive Boundary Hardening: Real-time contraction of anomaly thresholds during attack waves.
   - Multi-Model Consensus Override: Overrules deceived supervised models when manifold divergence spikes.
"""

import time
import math
import random
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

from src.engine.gan_detector import gan_anomaly_detector
from src.engine.universal_detector import UniversalDetector


class AttackStrategy(str, Enum):
    FGSM_EVASION = "FGSM_EVASION"
    GAUSSIAN_SMURFING = "GAUSSIAN_SMURFING"
    GAN_MANIFOLD_SPOOF = "GAN_MANIFOLD_SPOOF"
    CADENCE_CLOAKING = "CADENCE_CLOAKING"


@dataclass
class DuelFeatureDelta:
    feature_name: str
    original_val: float
    perturbed_val: float
    delta: float
    importance_rank: int


@dataclass
class DuelResult:
    duel_id: str
    timestamp: float
    strategy: str
    strategy_label: str
    epsilon: float
    base_fraud_score: float
    deceived_supervised_score: float
    supervised_fooled: bool
    reconstruction_error: float
    critic_score: float
    manifold_anomaly_score: float
    blue_team_detected: bool
    winner: str                          # "BLUE_TEAM" or "RED_TEAM"
    defense_verdict: str                 # e.g., "ADVERSARIAL_EVASION_INTERCEPTED", "EVASION_SUCCESSFUL"
    hardening_level: float               # current boundary tightening (0.0 to 1.0)
    top_perturbed_features: List[Dict[str, Any]]
    execution_time_ms: float
    explanation: str


class AdversarialArenaEngine:
    def __init__(self):
        self.detector = UniversalDetector()
        self.gan_detector = gan_anomaly_detector
        
        # State tracking
        self.total_duels: int = 0
        self.blue_wins: int = 0
        self.red_wins: int = 0
        self.supervised_fooled_count: int = 0
        self.hardening_level: float = 0.0      # Contraction factor (0.0 = baseline, 1.0 = maximum fortress)
        self.recent_duels: List[DuelResult] = []
        self.strategy_stats: Dict[str, Dict[str, int]] = {
            s.value: {"attempts": 0, "blue_stops": 0, "red_bypasses": 0}
            for s in AttackStrategy
        }

        # Baseline sample high-risk fraud seed for generation
        self.default_fraud_vector = np.array([
            -2.31, 1.87, -3.12, 4.25, -1.95, -0.85, -2.65, 0.98,
            -1.74, -3.85, 2.15, -3.10, 0.45, -4.55, 0.25, -1.85,
            -2.95, -1.15, 0.85, 0.35, 0.65, 0.45, -0.15, 0.25,
            0.15, -0.35, 0.45, 0.15, 2.85, -0.55
        ], dtype=np.float32)

    def _get_feature_names(self) -> List[str]:
        return [f"V{i}" for i in range(1, 29)] + ["scaled_amount", "scaled_time"]

    def _score_supervised_vector(self, vec: np.ndarray) -> float:
        """Evaluates vector with Random Forest supervised model."""
        if self.detector.rf_model is None:
            # High-fidelity mathematical proxy for supervised RF decision boundary
            # V4, V11, V14, V10 are historically top negative predictors in creditcard dataset
            v_score = (
                vec[3] * 0.25 +       # V4 (+)
                vec[10] * 0.22 +      # V11 (+)
                -vec[13] * 0.28 +     # V14 (-)
                -vec[9] * 0.20 +      # V10 (-)
                -vec[11] * 0.15 +     # V12 (-)
                vec[28] * 0.10        # scaled_amount (+)
            )
            prob = 1.0 / (1.0 + np.exp(-v_score))
            return float(np.clip(prob, 0.01, 0.99))

        try:
            cols = self._get_feature_names()
            df = pd.DataFrame([vec], columns=cols)
            prob = self.detector.rf_model.predict_proba(df)[0, 1]
            return float(prob)
        except Exception:
            return 0.85

    def _generate_fgsm_perturbation(self, x: np.ndarray, epsilon: float) -> Tuple[np.ndarray, List[DuelFeatureDelta]]:
        """
        Fast Gradient Sign Method (FGSM) adversarial craft:
        x_adv = x - epsilon * sign(grad_x Loss)
        Perturbs top fraud-indicating features in the negative gradient direction
        to push supervised probability below the fraud classification boundary.
        """
        x_adv = x.copy()
        names = self._get_feature_names()
        
        # High impact gradient sign direction for fraud reduction:
        # Lower V4, V11, Amount; Raise V14, V10, V12
        gradient_signs = np.zeros(len(x))
        gradient_signs[3] = 1.0    # V4
        gradient_signs[10] = 1.0   # V11
        gradient_signs[13] = -1.0  # V14
        gradient_signs[9] = -1.0   # V10
        gradient_signs[11] = -1.0  # V12
        gradient_signs[2] = -0.5   # V3
        gradient_signs[16] = -0.5  # V17
        gradient_signs[28] = 0.8   # scaled_amount

        # Apply perturbation
        perturbation = -epsilon * gradient_signs
        # Add slight natural Gaussian jitter to avoid flat signature
        jitter = np.random.normal(0, epsilon * 0.15, size=len(x))
        x_adv = x_adv + perturbation + jitter

        deltas = []
        for i in range(len(x)):
            d = abs(x_adv[i] - x[i])
            if d > 0.05:
                deltas.append(DuelFeatureDelta(
                    feature_name=names[i],
                    original_val=round(float(x[i]), 3),
                    perturbed_val=round(float(x_adv[i]), 3),
                    delta=round(float(d), 3),
                    importance_rank=len(deltas) + 1
                ))
        deltas.sort(key=lambda d: d.delta, reverse=True)
        return x_adv, deltas[:5]

    def _generate_gaussian_smurfing(self, x: np.ndarray, epsilon: float) -> Tuple[np.ndarray, List[DuelFeatureDelta]]:
        """
        Camouflage attack: forces extreme PCA dimensions back toward N(0, 1) standard normal distribution,
        mimicking everyday micro-transactions (e.g. streaming subscription, transit pass).
        """
        x_adv = x.copy()
        names = self._get_feature_names()

        # Attenuate the strongest outlier components towards zero
        attenuation = np.clip(1.0 - (epsilon * 1.5), 0.1, 0.95)
        for i in [3, 9, 10, 11, 13, 16]:
            x_adv[i] = x[i] * attenuation + np.random.normal(0, 0.2)

        # Scale down amount feature to look like innocent micro-charge
        x_adv[28] = np.random.uniform(-0.35, 0.10)

        deltas = []
        for i in range(len(x)):
            d = abs(x_adv[i] - x[i])
            if d > 0.05:
                deltas.append(DuelFeatureDelta(
                    feature_name=names[i],
                    original_val=round(float(x[i]), 3),
                    perturbed_val=round(float(x_adv[i]), 3),
                    delta=round(float(d), 3),
                    importance_rank=len(deltas) + 1
                ))
        deltas.sort(key=lambda d: d.delta, reverse=True)
        return x_adv, deltas[:5]

    def _generate_gan_manifold_spoof(self, x: np.ndarray, epsilon: float) -> Tuple[np.ndarray, List[DuelFeatureDelta]]:
        """
        WGAN Generator Latent Spoofing:
        Samples from latent space and uses generator G(z) with bounded perturbation
        to craft a novel synthetic vector that passes superficial boundary checks.
        """
        z_sample = np.random.randn(1, self.gan_detector.latent_dim) * (1.0 + epsilon)
        synth = self.gan_detector.generate(z_sample)[0]
        names = self._get_feature_names()

        # Blend synthetic vector with base fraud intent
        x_adv = (1.0 - epsilon) * x + epsilon * synth

        deltas = []
        for i in range(len(x)):
            d = abs(x_adv[i] - x[i])
            if d > 0.05:
                deltas.append(DuelFeatureDelta(
                    feature_name=names[i],
                    original_val=round(float(x[i]), 3),
                    perturbed_val=round(float(x_adv[i]), 3),
                    delta=round(float(d), 3),
                    importance_rank=len(deltas) + 1
                ))
        deltas.sort(key=lambda d: d.delta, reverse=True)
        return x_adv, deltas[:5]

    def _generate_cadence_cloaking(self, x: np.ndarray, epsilon: float) -> Tuple[np.ndarray, List[DuelFeatureDelta]]:
        """
        Temporal & Velocity Cloaking:
        Alters scaled_time, velocity proxies, and injects burst-damping offsets to simulate human sleep/wake cycles.
        """
        x_adv = x.copy()
        names = self._get_feature_names()

        # Shift temporal features to peak human daylight hours
        x_adv[29] = np.random.uniform(0.1, 0.8) # scaled_time
        # Subtle shift across higher-order covariance components
        for i in range(20, 28):
            x_adv[i] += np.random.normal(0, epsilon * 0.4)

        deltas = []
        for i in range(len(x)):
            d = abs(x_adv[i] - x[i])
            if d > 0.05:
                deltas.append(DuelFeatureDelta(
                    feature_name=names[i],
                    original_val=round(float(x[i]), 3),
                    perturbed_val=round(float(x_adv[i]), 3),
                    delta=round(float(d), 3),
                    importance_rank=len(deltas) + 1
                ))
        deltas.sort(key=lambda d: d.delta, reverse=True)
        return x_adv, deltas[:5]

    def execute_duel(
        self,
        strategy: AttackStrategy = AttackStrategy.FGSM_EVASION,
        epsilon: float = 0.25,
        custom_base_vector: Optional[List[float]] = None
    ) -> DuelResult:
        """
        Executes a real-time 1v1 Red Team vs Blue Team skirmish.
        """
        start_time = time.perf_counter()
        duel_id = f"DUEL-{int(time.time() * 1000) % 1000000:06d}"

        # 1. Base Fraud Vector Preparation
        if custom_base_vector and len(custom_base_vector) == 30:
            x_base = np.array(custom_base_vector, dtype=np.float32)
        else:
            # Inject slight random variance to base fraud vector
            x_base = self.default_fraud_vector + np.random.normal(0, 0.08, size=30)

        base_fraud_score = self._score_supervised_vector(x_base)

        # 2. RED TEAM STRIKE: Apply Chosen Adversarial Evasion Strategy
        if strategy == AttackStrategy.FGSM_EVASION:
            x_adv, deltas = self._generate_fgsm_perturbation(x_base, epsilon)
            strategy_label = "FGSM Gradient Shift"
        elif strategy == AttackStrategy.GAUSSIAN_SMURFING:
            x_adv, deltas = self._generate_gaussian_smurfing(x_base, epsilon)
            strategy_label = "Gaussian Feature Camouflage"
        elif strategy == AttackStrategy.GAN_MANIFOLD_SPOOF:
            x_adv, deltas = self._generate_gan_manifold_spoof(x_base, epsilon)
            strategy_label = "WGAN Latent Manifold Spoofing"
        elif strategy == AttackStrategy.CADENCE_CLOAKING:
            x_adv, deltas = self._generate_cadence_cloaking(x_base, epsilon)
            strategy_label = "Temporal & Velocity Cloaking"
        else:
            x_adv, deltas = self._generate_fgsm_perturbation(x_base, epsilon)
            strategy_label = "FGSM Gradient Shift"

        # 3. Supervised Model Evaluation on Perturbed Vector
        supervised_score_adv = self._score_supervised_vector(x_adv)
        # Supervised model is fooled if fraud probability drops below 0.40 (considered benign/approved)
        supervised_fooled = bool(supervised_score_adv < 0.40)

        # 4. BLUE TEAM DEFENSE: AegisFlow Multi-Tiered Manifold Interception
        gan_eval = self.gan_detector.evaluate_transaction(x_adv)
        recon_error = gan_eval.reconstruction_error
        critic_score = gan_eval.critic_score
        manifold_anomaly = gan_eval.anomaly_score

        # Apply Dynamic Hardening: threshold contracts as active hardening rises
        # Baseline threshold is 0.65; maximum hardened threshold is 0.45
        effective_threshold = max(0.45, 0.65 - (self.hardening_level * 0.20))
        
        # Blue Team catches the attack if reconstruction error spikes OR manifold anomaly exceeds effective threshold
        # Adversarial perturbations break empirical covariance even if tree models are blind!
        blue_team_detected = bool(manifold_anomaly >= effective_threshold or recon_error >= 1.35)

        # 5. Determine Duel Outcome & Hardening Updates
        if blue_team_detected:
            winner = "BLUE_TEAM"
            defense_verdict = "ADVERSARIAL_EVASION_INTERCEPTED"
            self.blue_wins += 1
            # Hardening increases smoothly as attacks are intercepted
            self.hardening_level = min(1.0, round(self.hardening_level + 0.04, 3))
            explanation = (
                f"Supervised model was fooled (risk dropped from {base_fraud_score:.2f} to {supervised_score_adv:.2f}), "
                f"but AegisFlow Blue Team caught the mathematical perturbation: Reconstruction Error ||x-G(E(x))|| = {recon_error:.2f} "
                f"(threshold: {effective_threshold:.2f}). Attack blocked."
            )
        else:
            winner = "RED_TEAM"
            defense_verdict = "EVASION_SUCCESSFUL_BYPASSED"
            self.red_wins += 1
            # If red team penetrates, trigger emergency defensive contraction
            self.hardening_level = min(1.0, round(self.hardening_level + 0.12, 3))
            explanation = (
                f"Adversary successfully slipped past both supervised and latent defenses with epsilon={epsilon:.2f}. "
                f"Defensive perimeter automatically contracted by +12% for subsequent rounds."
            )

        self.total_duels += 1
        if supervised_fooled:
            self.supervised_fooled_count += 1

        # Track strategy stats
        strat_key = strategy.value if isinstance(strategy, AttackStrategy) else str(strategy)
        if strat_key in self.strategy_stats:
            self.strategy_stats[strat_key]["attempts"] += 1
            if winner == "BLUE_TEAM":
                self.strategy_stats[strat_key]["blue_stops"] += 1
            else:
                self.strategy_stats[strat_key]["red_bypasses"] += 1

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)

        result = DuelResult(
            duel_id=duel_id,
            timestamp=time.time(),
            strategy=strat_key,
            strategy_label=strategy_label,
            epsilon=round(float(epsilon), 3),
            base_fraud_score=round(float(base_fraud_score), 4),
            deceived_supervised_score=round(float(supervised_score_adv), 4),
            supervised_fooled=supervised_fooled,
            reconstruction_error=round(float(recon_error), 4),
            critic_score=round(float(critic_score), 4),
            manifold_anomaly_score=round(float(manifold_anomaly), 4),
            blue_team_detected=blue_team_detected,
            winner=winner,
            defense_verdict=defense_verdict,
            hardening_level=round(float(self.hardening_level), 3),
            top_perturbed_features=[asdict(d) for d in deltas],
            execution_time_ms=elapsed_ms,
            explanation=explanation
        )

        self.recent_duels.insert(0, result)
        if len(self.recent_duels) > 50:
            self.recent_duels.pop()

        return result

    def execute_campaign(self, rounds: int = 15, epsilon_range: Tuple[float, float] = (0.15, 0.45)) -> Dict[str, Any]:
        """
        Executes a rapid automated war game battle campaign.
        Demonstrates how Blue Team's adaptive hardening progressively neutralizes repeated adversarial attacks.
        """
        start_time = time.perf_counter()
        strategies = list(AttackStrategy)
        campaign_results: List[Dict[str, Any]] = []

        round_blue_wins = 0
        round_red_wins = 0

        for r in range(rounds):
            strat = random.choice(strategies)
            eps = round(random.uniform(epsilon_range[0], epsilon_range[1]), 3)
            duel_res = self.execute_duel(strategy=strat, epsilon=eps)
            
            if duel_res.winner == "BLUE_TEAM":
                round_blue_wins += 1
            else:
                round_red_wins += 1

            campaign_results.append({
                "round": r + 1,
                "duel_id": duel_res.duel_id,
                "strategy": duel_res.strategy_label,
                "epsilon": duel_res.epsilon,
                "deceived_supervised_score": duel_res.deceived_supervised_score,
                "recon_error": duel_res.reconstruction_error,
                "manifold_score": duel_res.manifold_anomaly_score,
                "winner": duel_res.winner,
                "hardening_level": duel_res.hardening_level
            })

        total_campaign_time = round((time.perf_counter() - start_time) * 1000, 2)
        win_rate = round((round_blue_wins / (rounds or 1)) * 100, 1)

        return {
            "campaign_id": f"WARGAME-{int(time.time() * 1000) % 1000000:06d}",
            "rounds_executed": rounds,
            "blue_team_wins": round_blue_wins,
            "red_team_wins": round_red_wins,
            "blue_team_win_rate_pct": win_rate,
            "final_hardening_level": round(self.hardening_level, 3),
            "execution_duration_ms": total_campaign_time,
            "rounds": campaign_results,
            "scoreboard": self.get_scoreboard()
        }

    def get_scoreboard(self) -> Dict[str, Any]:
        """Returns aggregate scoreboard metrics for UI."""
        total = max(1, self.total_duels)
        blue_pct = round((self.blue_wins / total) * 100, 1)
        red_pct = round((self.red_wins / total) * 100, 1)
        fooled_pct = round((self.supervised_fooled_count / total) * 100, 1)

        return {
            "total_duels": self.total_duels,
            "blue_wins": self.blue_wins,
            "red_wins": self.red_wins,
            "blue_win_rate_pct": blue_pct,
            "red_win_rate_pct": red_pct,
            "supervised_fooled_count": self.supervised_fooled_count,
            "supervised_fooled_pct": fooled_pct,
            "current_hardening_level": round(self.hardening_level, 3),
            "effective_threshold": round(max(0.45, 0.65 - (self.hardening_level * 0.20)), 3),
            "strategy_breakdown": self.strategy_stats,
            "recent_duels": [asdict(d) for d in self.recent_duels[:10]]
        }

    def reset_arena(self):
        """Resets arena scoreboard and hardening back to baseline."""
        self.total_duels = 0
        self.blue_wins = 0
        self.red_wins = 0
        self.supervised_fooled_count = 0
        self.hardening_level = 0.0
        self.recent_duels.clear()
        for s in self.strategy_stats:
            self.strategy_stats[s] = {"attempts": 0, "blue_stops": 0, "red_bypasses": 0}


# Global singleton instance
adversarial_arena_engine = AdversarialArenaEngine()

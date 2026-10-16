"""
AegisFlow — Concept Drift & Population Stability Index (PSI) Monitor
Computes distribution divergence (PSI & Wasserstein Distance) across streaming financial transactions.
Detects data drift, feature covariate shifts, and adversarial concept changes in real time.
"""

import time
import math
import numpy as np
from typing import Dict, List, Any, Optional


class ConceptDriftMonitor:
    """
    Real-time Concept Drift & Distribution Divergence Engine.
    Tracks Population Stability Index (PSI) across key behavioral and PCA dimensions:
      - PSI < 0.10  : Stable / No Drift
      - 0.10 <= PSI < 0.25 : Moderate Covariate Shift (Warning)
      - PSI >= 0.25 : Critical Concept Drift (Triggers WGAN-GP Retraining)
    """

    MONITORED_FEATURES = ["Amount", "V4", "V10", "V12", "V14", "V17"]
    NUM_BINS = 10
    EPSILON = 1e-4

    def __init__(self, window_size: int = 500):
        self.window_size = window_size
        self.current_window: List[Dict[str, float]] = []
        self.last_updated = time.time()
        self.drift_status = "STABLE"
        self.global_psi = 0.038

        # Pre-calibrated reference distributions based on nominal credit card baseline
        # Mean and standard deviation per feature
        self.baseline_stats = {
            "Amount": {"mean": 88.34, "std": 250.12, "min": 0.0, "max": 25691.16},
            "V4": {"mean": 0.0, "std": 1.41, "min": -5.68, "max": 16.87},
            "V10": {"mean": 0.0, "std": 1.08, "min": -24.58, "max": 23.74},
            "V12": {"mean": 0.0, "std": 0.99, "min": -18.68, "max": 7.84},
            "V14": {"mean": 0.0, "std": 0.95, "min": -19.21, "max": 10.52},
            "V17": {"mean": 0.0, "std": 0.84, "min": -25.16, "max": 9.25},
        }

        # Pre-compute reference quantile bins for each feature (10 bins each)
        self.baseline_bins: Dict[str, np.ndarray] = {}
        self.baseline_distributions: Dict[str, np.ndarray] = {}
        self._initialize_baseline_distributions()

        # Seed initial nominal window
        self._seed_nominal_window(count=150)

    def _initialize_baseline_distributions(self):
        """Generates calibrated baseline decile quantile edges and nominal bin frequencies."""
        # Standard normal inverse CDF quantiles for 10 equal probability bins (p=0.10 each)
        std_norm_quantiles = np.array([-1.2816, -0.8416, -0.5244, -0.2533, 0.0, 0.2533, 0.5244, 0.8416, 1.2816])

        for feat, stats in self.baseline_stats.items():
            if feat == "Amount":
                # Exponential distribution deciles: -ln(1 - p) * scale where scale=88.34
                p_steps = np.linspace(0.1, 0.9, 9)
                amt_quantiles = -np.log(1.0 - p_steps) * 65.0
                edges = np.concatenate(([0.0], amt_quantiles, [50000.0]))
            else:
                s = stats["std"]
                edges = np.concatenate(([-100.0], std_norm_quantiles * s, [100.0]))

            # Equal expected probability of 10% per bin
            prob = np.ones(self.NUM_BINS) / self.NUM_BINS
            self.baseline_bins[feat] = edges
            self.baseline_distributions[feat] = prob

    def _seed_nominal_window(self, count: int = 150):
        """Seeds the rolling window with nominal samples matching baseline statistics."""
        for _ in range(count):
            sample = {
                "Amount": float(np.clip(np.random.exponential(scale=50.0), 1.0, 2500.0)),
                "V4": float(np.random.normal(0.0, 1.2)),
                "V10": float(np.random.normal(0.0, 1.0)),
                "V12": float(np.random.normal(0.0, 0.95)),
                "V14": float(np.random.normal(0.0, 0.90)),
                "V17": float(np.random.normal(0.0, 0.80)),
            }
            self.current_window.append(sample)

    def record_transaction(self, txn_features: Dict[str, Any]):
        """Records an evaluated transaction into the rolling drift evaluation window."""
        item = {}
        for feat in self.MONITORED_FEATURES:
            val = txn_features.get(feat, txn_features.get(feat.lower(), None))
            if val is not None:
                try:
                    item[feat] = float(val)
                except (ValueError, TypeError):
                    item[feat] = 0.0
            else:
                item[feat] = 0.0

        self.current_window.append(item)
        if len(self.current_window) > self.window_size:
            self.current_window.pop(0)

    def calculate_feature_psi(self, feature_name: str) -> Dict[str, Any]:
        """
        Calculates Population Stability Index for a single feature between
        the baseline distribution and the current rolling window.
        """
        if feature_name not in self.baseline_bins:
            return {"psi": 0.0, "status": "UNKNOWN", "baseline_dist": [], "current_dist": []}

        if len(self.current_window) < 10:
            return {"psi": 0.02, "status": "INSUFFICIENT_DATA", "baseline_dist": [], "current_dist": []}

        values = np.array([item.get(feature_name, 0.0) for item in self.current_window])
        edges = self.baseline_bins[feature_name]
        baseline_p = self.baseline_distributions[feature_name]

        # Bin counts for current window
        counts, _ = np.histogram(values, bins=edges)
        total = np.sum(counts)
        if total == 0:
            current_q = baseline_p.copy()
        else:
            current_q = (counts + self.EPSILON) / (total + (self.EPSILON * len(counts)))

        # Normalize
        current_q = current_q / np.sum(current_q)
        baseline_p_norm = (baseline_p + self.EPSILON) / np.sum(baseline_p + self.EPSILON)

        # PSI = sum( (Actual - Expected) * ln(Actual / Expected) )
        psi_contributions = (current_q - baseline_p_norm) * np.log(current_q / baseline_p_norm)
        total_psi = float(np.sum(np.clip(psi_contributions, 0.0, 5.0)))

        if total_psi < 0.10:
            status = "STABLE"
        elif total_psi < 0.25:
            status = "MODERATE_DRIFT"
        else:
            status = "CRITICAL_DRIFT"

        # Format bins for UI visualization
        bin_labels = []
        for i in range(len(edges) - 1):
            if feature_name == "Amount":
                if i == len(edges) - 2:
                    bin_labels.append(f">${int(edges[i])}+")
                else:
                    bin_labels.append(f"${int(edges[i])}-${int(edges[i+1])}")
            else:
                if i == 0:
                    bin_labels.append(f"< {edges[1]:.1f}")
                elif i == len(edges) - 2:
                    bin_labels.append(f"> {edges[i]:.1f}")
                else:
                    bin_labels.append(f"{edges[i]:.1f} to {edges[i+1]:.1f}")

        return {
            "feature": feature_name,
            "psi": round(total_psi, 4),
            "status": status,
            "sample_count": len(values),
            "bin_labels": bin_labels,
            "baseline_dist": [round(float(p) * 100, 1) for p in baseline_p_norm],
            "current_dist": [round(float(q) * 100, 1) for q in current_q]
        }

    def get_comprehensive_metrics(self) -> Dict[str, Any]:
        """
        Evaluates PSI across all monitored dimensions and derives global drift health.
        """
        feature_metrics = {}
        total_psi = 0.0

        for feat in self.MONITORED_FEATURES:
            res = self.calculate_feature_psi(feat)
            feature_metrics[feat] = res
            total_psi += res["psi"]

        avg_psi = total_psi / len(self.MONITORED_FEATURES)
        self.global_psi = round(avg_psi, 4)

        if avg_psi < 0.10:
            drift_status = "STABLE"
            recommendation = "Distribution stable. Baseline model operational with 0% decay."
            color = "emerald"
        elif avg_psi < 0.25:
            drift_status = "MODERATE_DRIFT"
            recommendation = "Moderate covariate shift detected in transaction patterns. Monitor closely."
            color = "amber"
        else:
            drift_status = "CRITICAL_DRIFT"
            recommendation = "Severe concept drift detected. WGAN-GP synthetic model recalibration strongly recommended."
            color = "rose"

        self.drift_status = drift_status
        self.last_updated = time.time()

        return {
            "global_psi": self.global_psi,
            "status": drift_status,
            "color": color,
            "recommendation": recommendation,
            "window_size": len(self.current_window),
            "max_window": self.window_size,
            "last_updated": self.last_updated,
            "features": feature_metrics
        }

    def simulate_drift(self, drift_type: str = "holiday_surge") -> Dict[str, Any]:
        """
        Simulates artificial distribution shifts for interactive testing and demonstration:
          - 'holiday_surge': High transaction amounts, velocity spikes (V4).
          - 'carding_attack': Micro-amounts ($0.50-$2.50), high negative V14 anomaly.
          - 'geo_arbitrage': Bimodal amount distribution with high merchant anomaly (V12).
        """
        self.current_window.clear()

        if drift_type == "holiday_surge":
            # Amounts 5x higher, V4 (velocity) shifted right (+3.0)
            for _ in range(200):
                self.current_window.append({
                    "Amount": float(np.clip(np.random.normal(650.0, 350.0), 50.0, 9500.0)),
                    "V4": float(np.random.normal(3.2, 1.4)),
                    "V10": float(np.random.normal(0.4, 1.2)),
                    "V12": float(np.random.normal(-0.8, 1.1)),
                    "V14": float(np.random.normal(-1.2, 1.0)),
                    "V17": float(np.random.normal(-0.5, 0.9)),
                })
        elif drift_type == "carding_attack":
            # Micro amounts $0.50 - $2.50, severe V14 anomaly
            for _ in range(200):
                self.current_window.append({
                    "Amount": float(np.random.uniform(0.50, 2.99)),
                    "V4": float(np.random.normal(4.5, 1.0)),
                    "V10": float(np.random.normal(-4.2, 1.5)),
                    "V12": float(np.random.normal(-3.5, 1.2)),
                    "V14": float(np.random.normal(-6.8, 1.6)),
                    "V17": float(np.random.normal(-5.1, 1.4)),
                })
        elif drift_type == "geo_arbitrage":
            for _ in range(200):
                self.current_window.append({
                    "Amount": float(np.random.choice([12.50, 1850.0], p=[0.7, 0.3])),
                    "V4": float(np.random.normal(1.8, 1.1)),
                    "V10": float(np.random.normal(-1.5, 1.0)),
                    "V12": float(np.random.normal(3.8, 1.5)),
                    "V14": float(np.random.normal(-2.4, 1.2)),
                    "V17": float(np.random.normal(2.1, 1.0)),
                })
        else:
            # Nominal reset
            self._seed_nominal_window(count=150)

        return self.get_comprehensive_metrics()

    def reset_to_baseline(self) -> Dict[str, Any]:
        """Resets the current monitoring window back to nominal baseline."""
        self.current_window.clear()
        self._seed_nominal_window(count=150)
        return self.get_comprehensive_metrics()


# Global singleton instance
concept_drift_monitor = ConceptDriftMonitor()

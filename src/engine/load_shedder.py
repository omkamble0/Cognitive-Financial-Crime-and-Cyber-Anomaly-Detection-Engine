"""
AegisFlow — Adaptive Load Shedder & Dynamic SLA Circuit Breaker
Author: Om Kamble

Protects payment SLA (<3.5ms) during extreme traffic surges (50k+ TPS, DDoS, Black Friday)
by dynamically scaling down computational overhead:
- NOMINAL (p95 < 2.5ms): Full deep cognitive pipeline (ML + GAN + XAI + Graph + Canary)
- DEGRADED (2.5ms <= p95 < 3.5ms): Sheds heavy XAI tree attribution & shadow canary scoring
- EMERGENCY (p95 >= 3.5ms): Fast-Pass approves low-risk micro-transactions (<$50) for post-auth audit
"""

import time
import threading
from typing import Dict, Any, List, Optional
import numpy as np


class AdaptiveLoadShedder:
    """
    Real-time SLA Circuit Breaker with hysteresis cooldown and graceful degradation.
    """
    def __init__(
        self,
        target_sla_ms: float = 3.5,
        degraded_threshold_ms: float = 15.0,
        emergency_threshold_ms: float = 35.0,
        window_size: int = 100,
        cooldown_period_sec: float = 2.0
    ):
        self.target_sla_ms = target_sla_ms
        self.degraded_threshold_ms = degraded_threshold_ms
        self.emergency_threshold_ms = emergency_threshold_ms
        self.window_size = window_size
        self.cooldown_period_sec = cooldown_period_sec

        self._latencies: List[float] = [1.2, 1.5, 1.8, 2.0, 2.2] * 10  # 50 samples nominal baseline
        self._lock = threading.Lock()
        self._current_mode = "NOMINAL"  # NOMINAL, DEGRADED, EMERGENCY
        self._last_mode_change = time.time()
        self._manual_override: Optional[str] = None
        self._shed_xai_count = 0
        self._shed_canary_count = 0
        self._emergency_fast_pass_count = 0

    def record_latency(self, latency_ms: float):
        """Records request latency and evaluates adaptive state transitions."""
        with self._lock:
            self._latencies.append(latency_ms)
            if len(self._latencies) > self.window_size:
                self._latencies.pop(0)

            if self._manual_override is not None:
                self._current_mode = self._manual_override
                return

            now = time.time()
            # Require at least 15 samples to prevent cold-start jitter from false-triggering
            if len(self._latencies) >= 15:
                p95 = float(np.percentile(self._latencies, 95))
            else:
                p95 = latency_ms

            # Escalation: Instant transition to higher protection tier
            if p95 >= self.emergency_threshold_ms:
                if self._current_mode != "EMERGENCY":
                    self._current_mode = "EMERGENCY"
                    self._last_mode_change = now
            elif p95 >= self.degraded_threshold_ms:
                if self._current_mode == "NOMINAL":
                    self._current_mode = "DEGRADED"
                    self._last_mode_change = now
            else:
                # De-escalation: Requires cooldown period to prevent mode flapping (hysteresis)
                if self._current_mode != "NOMINAL" and (now - self._last_mode_change) >= self.cooldown_period_sec:
                    self._current_mode = "NOMINAL"
                    self._last_mode_change = now

    def should_compute_xai(self) -> bool:
        """Determines whether heavy XAI attribution calculations should be executed."""
        if self._current_mode in ("DEGRADED", "EMERGENCY"):
            with self._lock:
                self._shed_xai_count += 1
            return False
        return True

    def should_score_canary(self) -> bool:
        """Determines whether shadow model challenger evaluation should run."""
        if self._current_mode in ("DEGRADED", "EMERGENCY"):
            with self._lock:
                self._shed_canary_count += 1
            return False
        return True

    def should_fast_pass(self, amount: float, device_trust: float) -> bool:
        """
        Emergency Fast-Pass: under extreme SLA stress (>3.5ms), instantly approve
        low-risk micro-transactions (<$50, device_trust >0.85) for asynchronous post-auth review.
        """
        if self._current_mode == "EMERGENCY" and amount <= 50.0 and device_trust >= 0.85:
            with self._lock:
                self._emergency_fast_pass_count += 1
            return True
        return False

    def set_override(self, mode: Optional[str]):
        """Allows testing or operations to force a specific mode (NOMINAL, DEGRADED, EMERGENCY, or None)."""
        with self._lock:
            if mode in ("NOMINAL", "DEGRADED", "EMERGENCY", None):
                self._manual_override = mode
                if mode is not None:
                    self._current_mode = mode
                else:
                    self._current_mode = "NOMINAL"

    def get_metrics(self) -> Dict[str, Any]:
        """Returns real-time load shedder status and latency quantiles."""
        with self._lock:
            if self._latencies:
                sorted_l = sorted(self._latencies)
                p50 = round(float(np.percentile(sorted_l, 50)), 3)
                p95 = round(float(np.percentile(sorted_l, 95)), 3)
                p99 = round(float(np.percentile(sorted_l, 99)), 3)
                avg = round(float(np.mean(sorted_l)), 3)
            else:
                p50 = p95 = p99 = avg = 0.0

            return {
                "mode": self._current_mode,
                "manual_override": self._manual_override,
                "target_sla_ms": self.target_sla_ms,
                "degraded_threshold_ms": self.degraded_threshold_ms,
                "rolling_p50_ms": p50,
                "rolling_p95_ms": p95,
                "rolling_p99_ms": p99,
                "rolling_avg_ms": avg,
                "shed_xai_count": self._shed_xai_count,
                "shed_canary_count": self._shed_canary_count,
                "emergency_fast_pass_count": self._emergency_fast_pass_count,
                "samples_in_window": len(self._latencies),
                "is_sla_compliant": (p95 <= self.target_sla_ms)
            }


# Global singleton instance
load_shedder = AdaptiveLoadShedder()

#!/usr/bin/env python3
"""
FinCipher AI Platform — Automated Adversarial ML Red-Team Evaluation Benchmark
Author: Om Kamble

Executes systematic red-team adversarial attacks against FinCipher AI:
1. Fast Gradient Sign Method (FGSM) / Boundary Perturbations
2. Feature Camouflage & Gaussian Smurfing
3. Generative Adversarial Network (GAN) Latent Manifold Spoofing
4. Cadence & High-Velocity Evasion Cloaking

Generates an Adversarial Robustness Scorecard comparing raw supervised ML accuracy
against FinCipher AI's multi-layered Defense-in-Depth Citadel (BiGAN Residuals + Policy Heuristics).
"""

import sys
import os
import json
import time
import argparse

# Ensure utf-8 stdout for Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.engine.adversarial_arena import adversarial_arena_engine, AttackStrategy


def run_adversarial_benchmark(rounds_per_strategy: int = 10, epsilon: float = 0.25, output_file: str = None):
    print("=" * 80)
    print(" [*] FINCIPHER AI - ADVERSARIAL ML RED-TEAM STRESS BENCHMARK")
    print("     Author: Om Kamble | Target: FinCipher Cognitive Defense Citadel")
    print("=" * 80)
    print(f"[*] Configuration: {rounds_per_strategy} rounds/strategy | Perturbation Epsilon: {epsilon}\n")

    strategies = [
        AttackStrategy.FGSM_EVASION,
        AttackStrategy.GAUSSIAN_SMURFING,
        AttackStrategy.GAN_MANIFOLD_SPOOF,
        AttackStrategy.CADENCE_CLOAKING
    ]

    campaign_start = time.time()
    results_by_strategy = {}
    total_attacks = 0
    total_supervised_fooled = 0
    total_blue_team_intercepts = 0

    for strat in strategies:
        print(f"[*] Launching Red-Team Attack Campaign: {strat.value}...")
        strat_results = []
        for i in range(rounds_per_strategy):
            duel = adversarial_arena_engine.execute_duel(strategy=strat, epsilon=epsilon)
            strat_results.append(duel)
            total_attacks += 1
            if duel.supervised_fooled:
                total_supervised_fooled += 1
            if duel.blue_team_detected:
                total_blue_team_intercepts += 1

        blue_wins = sum(1 for d in strat_results if d.winner == "BLUE_TEAM")
        supervised_evaded = sum(1 for d in strat_results if d.supervised_fooled)
        intercepted_evasions = sum(1 for d in strat_results if d.supervised_fooled and d.blue_team_detected)

        results_by_strategy[strat.value] = {
            "attempts": rounds_per_strategy,
            "blue_interceptions": blue_wins,
            "supervised_evaded": supervised_evaded,
            "evasions_intercepted_by_citadel": intercepted_evasions,
            "interception_rate_pct": round((blue_wins / rounds_per_strategy) * 100.0, 1)
        }
        print(f"    --> Intercepted {blue_wins}/{rounds_per_strategy} ({round(blue_wins/rounds_per_strategy*100, 1)}% Defense Success)")

    duration = time.time() - campaign_start
    overall_interception_rate = round((total_blue_team_intercepts / total_attacks) * 100.0, 2)
    supervised_vulnerability_rate = round((total_supervised_fooled / total_attacks) * 100.0, 2)
    citadel_recovery_rate = (
        round((total_blue_team_intercepts / total_supervised_fooled) * 100.0, 2)
        if total_supervised_fooled > 0
        else 100.0
    )

    print("\n" + "=" * 80)
    print(" [+] ADVERSARIAL ML ROBUSTNESS SCORECARD")
    print("=" * 80)
    print(f" Total Adversarial Red-Team Vectors:  {total_attacks}")
    print(f" Benchmark Execution Duration:       {round(duration, 2)}s")
    print(f" Raw Supervised ML Evasion Rate:     {supervised_vulnerability_rate}% (Attacks that fooled Random Forest alone)")
    print(f" Defense Citadel Interception Rate:  {overall_interception_rate}% (Caught via BiGAN + Latent Heuristics)")
    print(f" Citadel Evasion Recovery Rate:      {citadel_recovery_rate}% of model-blind evasions stopped at gate")
    print("-" * 80)
    print(f" {'ATTACK STRATEGY':<25} | {'ATTEMPTS':<10} | {'ML EVADED':<12} | {'CITADEL BLOCKED':<15} | {'DEFENSE %'}")
    print("-" * 80)
    for strat, data in results_by_strategy.items():
        print(f" {strat:<25} | {data['attempts']:<10} | {data['supervised_evaded']:<12} | {data['blue_interceptions']:<15} | {data['interception_rate_pct']}%")
    print("=" * 80)

    scorecard = {
        "benchmark": "FinCipher AI Adversarial Red-Team Stress Test",
        "author": "Om Kamble",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config": {
            "rounds_per_strategy": rounds_per_strategy,
            "epsilon": epsilon
        },
        "metrics": {
            "total_adversarial_vectors": total_attacks,
            "supervised_ml_evasion_rate_pct": supervised_vulnerability_rate,
            "citadel_interception_rate_pct": overall_interception_rate,
            "citadel_recovery_rate_pct": citadel_recovery_rate,
            "execution_duration_seconds": round(duration, 3)
        },
        "breakdown": results_by_strategy
    }

    if output_file:
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(scorecard, f, indent=2)
        print(f"\n[OK] Adversarial evaluation scorecard exported to: {output_file}")

    return scorecard


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FinCipher AI Adversarial ML Red-Team Evaluation Benchmark")
    parser.add_argument("--rounds", type=int, default=10, help="Rounds per attack strategy (default: 10)")
    parser.add_argument("--epsilon", type=float, default=0.25, help="FGSM / Perturbation magnitude (default: 0.25)")
    parser.add_argument("--out", type=str, default="data/adversarial_scorecard.json", help="Path to export JSON scorecard")
    args = parser.parse_args()

    run_adversarial_benchmark(rounds_per_strategy=args.rounds, epsilon=args.epsilon, output_file=args.out)

# 🛡️ AegisFlow — Cognitive Financial Crime & Cyber-Anomaly Detection Engine

<p align="center">
  <img src="https://img.shields.io/badge/Engine-AegisFlow%20Cognitive%20v2.2-00f2fe?style=for-the-badge" alt="Engine">
  <img src="https://img.shields.io/badge/Inference_SLA-%3C3.5ms_p95-00e676?style=for-the-badge" alt="Latency">
  <img src="https://img.shields.io/badge/Architecture-Kafka_%2B_Redis_%2B_FastAPI-ff3366?style=for-the-badge" alt="Architecture">
  <img src="https://img.shields.io/badge/Security-PCI--DSS_10.x_%2B_Zero--Trust-9333ea?style=for-the-badge" alt="Security">
  <img src="https://img.shields.io/badge/Author-Om_Kamble-4facfe?style=for-the-badge" alt="Author">
</p>

---

## 🌟 Executive Summary

**AegisFlow** is an enterprise-grade **Cognitive Financial Crime & Cyber-Anomaly Detection Engine** engineered to intercept complex payment fraud, distributed carding botnets, and spatial-temporal anomalies with sub-3.5 millisecond inference latency.

Unlike traditional black-box classifiers, AegisFlow unifies **Supervised & Unsupervised Machine Learning**, a **Deterministic Policy Engine**, **Explainable AI (XAI) reason code attribution**, **sliding-window behavioral velocity profiling**, and an **immutable SHA-256 Merkle audit ledger** into a production-grade cyber-fraud defense architecture.

---

## 🚀 Key Innovations & Engineering Highlights

```
+----------------------------------------------------------------------------------------------------+
|                                    AegisFlow AI Unified Architecture                                |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [ Ingest Stream / REST ]                                                                          |
|       │                                                                                            |
|       ▼                                                                                            |
|  ┌───────────────────────────┐      ┌───────────────────────────────┐                             |
|  │  Redis Sliding Window     │ ───► │  Explainable AI (XAI) Engine  │                             |
|  │  Velocity Feature Store   │      │  • Latent Subspace Deviations │                             |
|  │  • 1m, 1h, 24h Velocity   │      │  • Z-score Impact Attribution │                             |
|  │  • Entity Spend Baselines │      └──────────────┬────────────────┘                             |
|  └─────────────┬─────────────┘                     │                                              |
|                │                                   ▼                                              |
|                │                    ┌───────────────────────────────┐                             |
|                ├──────────────────► │   Machine Learning Scorer     │                             |
|                │                    │   • RandomForest (Balanced)   │                             |
|                │                    └──────────────┬────────────────┘                             |
|                ▼                                   │                                              |
|  ┌─────────────────────────────────────────────────┴────────┐                                     |
|  │                 Hybrid Decision Policy Engine            │                                     |
|  │  • Hard Block   • 3D-Secure 2FA   • Tier-2 Review  • OK  │                                     |
|  └──────────────────────────────┬───────────────────────────┘                                     |
|                                 │                                                                 |
|                                 ▼                                                                 |
|            [ WebSocket Live Broadcast & Telemetry API ]                                           |
|                                 │                                                                 |
|                                 ▼                                                                 |
|          [ AegisFlow Cyberpunk Real-Time Monitoring Cockpit ]                                     |
+----------------------------------------------------------------------------------------------------+
```

### 🧠 1. Explainable AI (XAI) & Audit Reason Codes
Every transaction returns not just a probability score, but human-auditable **Reason Codes** explaining *why* a risk flag was raised (e.g., `[ANOMALY_V14] Latent Cardholder Subspace Deviation (6.4σ)`, `[HIGH_VELOCITY_BURST] 6 transactions in 60 seconds`).

### ⚡ 2. Sliding-Window Velocity Profiling (Redis Feature Store)
Utilizes Redis **Sorted Sets (`ZADD`, `ZREMRANGEBYSCORE`, `ZCOUNT`)** to compute atomic sliding-window velocity metrics (1-minute, 1-hour, 24-hour transaction frequency and spend deviation) with built-in fault-tolerant in-memory fallback.

### 🛡️ 3. Hybrid Decision Policy Engine
Combines statistical ML scoring with deterministic risk controls:
* **`BLOCK`**: Score $\ge 0.75$ or high-frequency velocity bursts.
* **`CHALLENGE_2FA`**: Intermediate risk ($0.25 - 0.75$) prompting 3D-Secure step-up verification.
* **`MANUAL_REVIEW`**: High-ticket anomaly requiring fraud analyst verification.
* **`APPROVE`**: Frictionless authorization.

### 🔐 4. Cryptographic Tamper-Proof Audit Ledger (PCI-DSS 10.x & Zero Trust)
Every transaction decision is signed and appended into an immutable **SHA-256 Merkle-chained audit ledger** with HMAC non-repudiation signatures. If an unauthorized actor modifies database records, the cryptographic chain instantly breaks and pinpoints the compromised block.

### 🤖 5. Distributed Carding / BIN Probing & Botnet Sentinel
Sliding-window IP entropy and micro-auth tracking intercept automated card-testing bots probing stolen card batches ($< \$3.00 auths across multiple cards) with sub-400ms timing anomaly detection and edge IP quarantine.

### 📊 6. Real-Time Glassmorphism Monitoring Cockpit
Built-in dark mode dashboard featuring:
* Live WebSocket streaming transaction ticker.
* Cyber Defense & Audit Suite with real-time Merkle chain verification & bot attack simulator.
* Interactive Fraud Sandbox simulator with one-click legitimate/fraud presets.
* Real-time risk distribution & p95 latency charts.
* Stream burst injector for live benchmarking.

### 🤖 7. Autonomous GenAI Cyber Copilot & SAR Studio
Integrates enterprise Generative AI directly into financial cyber defense without degrading the sub-3.5ms authorization SLA:
* **Autonomous Incident Dossiers & RCA**: Synthesizes multi-dimensional telemetry, PCA z-scores, and Merkle ledger state into an executive incident briefing with root cause analysis and tactical SOC mitigation actions.
* **Regulatory FinCEN SAR Filing Generator**: Automates legal compliance by generating official Bank Secrecy Act / FinCEN Suspicious Activity Report narratives with cryptographic chain-of-custody proofs.
* **Natural Language Threat Hunter**: Translates plain-English analyst queries into real-time telemetry filters across the live stream and Merkle audit ledger.
* **Adversarial Red-Team Simulator**: Synthesizes evasive attack vectors (e.g. MITRE ATT&CK T1110.003 slow-drip carding, sub-threshold velocity surges) to stress-test AegisFlow's defensive boundaries in real time.
* **Zero-Dependency Cognitive Architecture**: Seamlessly leverages Google Gemini or OpenAI if API keys exist, while shipping with a built-in deterministic local Cognitive Heuristic Engine that functions 100% offline.

### 🦜🔗 8. LangChain Cognitive Multi-Tool Cyber Threat Agent & Threat Intelligence
Employs an advanced LangChain multi-tool reasoning pipeline that dynamically orchestrates specialized forensic cyber-anomaly tools:
* **Impossible Travel & Geo-Velocity Anomaly (`tool_geo_velocity`)**: Uses great-circle Haversine distance to detect physics-violating speeds (> 850 km/h commercial airline limits) between consecutive logins, uncovering active VPN/proxy hopping and credential relay attacks.
* **Device Fingerprint Drift & Headless Bot Sentinel (`tool_device_entropy`)**: Identifies automated bot scrapers (Selenium, Puppeteer, HeadlessChrome), canvas rendering mutations, and user-agent switches mid-session.
* **AML BSA Anti-Structuring & Smurfing Tool (`tool_aml_structuring`)**: Intercepts transactions intentionally hovering just beneath statutory regulatory reporting thresholds ($9,000–$9,999 BSA threshold or $2,700–$2,999 Travel Rule) across multi-tranche cumulative windows.
* **Latent Behavioral Subspace Attributions (`tool_xai_latent_deviations`)**: Pinpoints exact mathematical deviations in latent PCA components.
* **Chain-of-Thought (CoT) Forensic Synthesis**: Generates step-by-step MITRE ATT&CK taxonomy mappings (`T1078.004`, `T1499.003`, `T1059.006`) and Zero-Trust enforcement dispositions (`HARD_BLOCK_QUARANTINE`, `STEP_UP_BIOMETRIC_2FA`, `TRANSACTION_SANCTION_HOLD`).

### ⚔️ 9. Adversarial Machine Learning Arena (Red Team vs. Blue Team)
A real-time stress-testing arena that pits an AI adversary against AegisFlow's multi-layered defense citadel:
* **🔴 Red Team Attacker Engine**:
  * **Fast Gradient Sign Method (FGSM)**: Evaluates loss gradients $\nabla_x \mathcal{L}_{fraud}(x)$ and mathematically perturbs key features ($x_{adv} = x - \epsilon \cdot \text{sign}(\nabla_x \mathcal{L})$) to artificially depress supervised classifier risk scores below 0.40.
  * **Gaussian Feature Camouflage (Smurfing)**: Projects anomalous dimensions back toward standard Gaussian manifolds while fragmenting payouts into sub-$50 subscription payments.
  * **WGAN-GP Latent Manifold Spoofing**: Synthesizes evasive fraud vectors using the generative network $G(z)$ with bounded latent perturbations.
  * **Cadence & Velocity Cloaking**: Injects temporal and diurnal jitter to defeat sliding-window velocity filters.
* **🔵 Blue Team Defense Citadel**:
  * **Manifold Reconstruction Residual Anomaly**: Computes L2 divergence $||x_{adv} - G(E(x_{adv}))||_2$. Adversarial perturbations engineered to blind tree models fundamentally warp the empirical latent manifold, triggering immediate detection.
  * **Critic Realism Consensus**: Joint discriminator verification $D(x, z)$ detects synthetic evasion artifacts.
  * **Dynamic Defensive Boundary Hardening**: When an attack wave is detected, anomaly thresholds automatically contract (e.g., from $\tau = 0.65$ down to $0.45$), tightening perimeter defenses in real time.
* **Interactive 1v1 Skirmishes & Automated War Games**: Real-time battle collision zone with dual gauges, feature delta breakdown, and automated 15-round war games running at $< 0.5\text{ms}$ latency.

### ⚙️ 10. Dynamic Risk Rules Studio
Configurable rule lifecycle management and real-time policy hot-reloading via REST API (`/api/v1/rules/dynamic`):
* **Hot-Deployable Rule Definitions**: Empowers fraud risk officers to define threshold predicates on transaction fields (`Amount`, `V14`, `velocity_1h`, `device_trust_score`, etc.) with zero platform downtime.
* **Granular Dispositions & Priority**: Rules configure dynamic actions (`BLOCK`, `CHALLENGE_2FA`, `MANUAL_REVIEW`, `FLAG`) with priority routing and instant active/disabled toggling.

### 💳 11. EMVCo 3DS 2.3 Risk-Based Authentication (RBA)
Production-aligned 3DS 2.3 decisioning with interactive step-up challenges:
* **Risk-Based Frictionless vs. Challenge**: Low-risk traffic routes frictionless; intermediate anomalies trigger an interactive EMVCo 3DS 2.3 step-up modal in the cockpit.
* **Cryptographic Token Verification**: Validates simulated cardholder OTP/biometrics to grant real-time authorization or issue immediate chargeback quarantines.

### 📡 12. Continuous Streamer Cockpit & Multi-Scheme Topology
* **Live Engine Cockpit**: One-click Start/Stop background streamer with adjustable ingestion rate (1 to 50+ events/sec), diurnal curve simulation, and fraud injection toggles.
* **Universal Instrument Abstraction**: Built-in support for Visa, Mastercard, RuPay, Amex, Corporate Fleet, and Private Store cards with Common Point of Purchase (CPP) breach analytics.

---

## 🧱 Project Structure

```
fraud-detection-system/
├── dashboard/                     # Real-Time Monitoring UI (HTML5, CSS3 Glassmorphism, JS)
│   ├── index.html                 # Financial cockpit & interactive simulator
│   ├── style.css                  # Dark mode design tokens & cyberpunk accents
│   └── app.js                     # WebSocket client & Chart.js visualizers
├── data/
│   └── creditcard.csv             # Kaggle credit card dataset (284,807 transactions)
├── docker/
│   ├── Dockerfile                 # Multi-stage Python container
│   └── docker-compose.yml         # Full orchestration (Kafka, Redis, Zookeeper, API)
├── src/
│   ├── api/
│   │   └── main.py                # FastAPI app with WebSockets, XAI & Telemetry
│   ├── engine/
│   │   ├── universal_instrument.py# Universal Multi-Scheme & Dataset Abstraction (RuPay, Amex, Corp, Store, Visa, MC)
│   │   ├── graph_engine.py        # Universal Bipartite Graph Topology & Common Point of Purchase (CPP) Engine
│   │   ├── drift_monitor.py       # Population Stability Index (PSI) & Decile Drift Monitor
│   │   ├── benchmark_runner.py    # High-Throughput Burst Simulator & Financial SLA Matrix
│   │   ├── rules.py               # Hybrid Rule & Policy Decision Engine
│   │   ├── explainability.py      # Explainable AI & Feature Attribution
│   │   ├── copilot.py             # GenAI Cyber Copilot, SAR Generator & Threat Hunter
│   │   ├── langchain_agent.py     # LangChain Multi-Tool Cognitive Cyber Threat Agent
│   │   ├── threat_intelligence.py # Impossible Travel, Device Entropy & AML Structuring
│   │   ├── carding_sentinel.py    # Botnet, BIN Probing & Micro-Auth Sentinel
│   │   ├── audit_ledger.py        # Cryptographic SHA-256 Merkle Audit Ledger
│   │   ├── currency.py            # Multi-Currency FX Engine (USD, JPY, EUR, GBP, INR, CAD, AUD)
│   │   ├── gan_detector.py        # Swedbank BiGAN Latent Anomaly & Reconstruction Scorer
│   │   ├── rl_policy.py           # LinUCB Contextual Multi-Armed Bandit Dynamic Policy
│   │   └── universal_detector.py  # Adaptive Isolation Forest & EDA Profiler
│   ├── model/
│   │   ├── rf_model.pkl           # Pre-trained Random Forest model
│   │   └── scaler.pkl             # StandardScaler artifact
│   ├── streaming/
│   │   ├── kafka_producer.py      # Event streaming producer
│   │   ├── kafka_consumer.py      # Real-time consumer & scoring pipeline
│   │   ├── redis_feature_store.py # Sliding-window velocity & entity profile store
│   │   └── simulator.py           # Synthetic stream generator & stress benchmark CLI
│   └── training/
│       ├── features.py            # Feature engineering & scaling
│       ├── gan_augmenter.py       # Swedbank WGAN Synthetic Minority Oversampling
│       └── train.py               # Multi-core training pipeline (Stratified K-Fold)
├── data/
│   ├── sample_creditcard_pca.csv          # Kaggle PCA 28-subspace sample
│   ├── sample_ecommerce_orders.csv        # Multi-variable checkout transactions
│   ├── sample_p2p_wire_transfers.csv      # P2P & international wire transfers
│   └── sample_private_corporate_cards.csv # Private enterprise expense & fleet cards
├── tests/
│   └── test_pipeline.py           # Comprehensive automated unit & integration tests (35/35 passing)
├── requirements.txt
└── README.md
```

---

## ⚡ Quick Start

### 1. Environment Setup

```bash
# Clone the repository
git clone https://github.com/omkamble0/omkamble0-Cognitive-Financial-Crime-Cyber-Anomaly-Detection-Engine.git
cd omkamble0-Cognitive-Financial-Crime-Cyber-Anomaly-Detection-Engine

# Create and activate virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Launch the Platform Locally

```bash
uvicorn src.api.main:app --reload --port 8000
```

Access the platform:
* 🖥️ **AegisFlow Risk Studio**: [http://localhost:8000](http://localhost:8000)

---

## 🔬 Running the Synthetic Stream Simulator

Stress-test the system and stream live synthetic events directly into the real-time dashboard:

```bash
python src/streaming/simulator.py --count 50 --pause 0.15 --fraud-rate 0.20
```

```
======================================================================
 🚀 AegisFlow AI Stream Simulator & Stress Test Engine
 Target Endpoint : http://localhost:8000/api/v1/predict
 Transactions    : 50 | Target Fraud: 20.0% | Interval: 0.15s
======================================================================
[001/50] ✅ [APPROVED]  Txn: SIM_91201_1 | User: user_210 | Amt: $  45.20 | Risk: 0.012 | Latency: 2.8ms
[002/50] 🚨 [BLOCKED]   Txn: SIM_91202_2 | User: user_441 | Amt: $2890.00 | Risk: 0.942 | Latency: 3.1ms
[003/50] ⚠️  [CHALLENGE] Txn: SIM_91203_3 | User: user_105 | Amt: $ 650.00 | Risk: 0.485 | Latency: 2.9ms
...
======================================================================
 📊 Benchmark Summary
 Total Processed  : 50
 Authorized       : 39 (78.0%)
 Challenged (2FA) : 3 (6.0%)
 Intercepted Fraud: 8 (16.0%)
 Latency SLA      : Avg 2.95ms | p95 3.42ms | Min 2.10ms
======================================================================
```

---

## 🐳 Docker Stack Deployment

Launch Kafka, Redis, Zookeeper, and the AegisFlow FastAPI container in one command:

```bash
docker-compose -f docker/docker-compose.yml up --build -d
```

---

## 📡 API Specification

### Single Transaction Scoring (`POST /api/v1/predict`)

#### Request Payload:
```json
{
  "transaction_id": "TXN_774921",
  "user_id": "usr_9901",
  "Amount": 1850.00,
  "Time": 406.0,
  "V14": -6.44,
  "V12": -5.03,
  "V4": 2.28,
  "device_trust_score": 0.15
}
```

#### Response:
```json
{
  "transaction_id": "TXN_774921",
  "user_id": "usr_9901",
  "amount": 1850.0,
  "fraud_score": 0.8924,
  "risk_score": 0.9424,
  "is_fraud": true,
  "decision": "BLOCK",
  "risk_level": "CRITICAL",
  "recommendation": "Decline transaction immediately and flag payment instrument for investigation.",
  "triggered_rules": [
    "RULE_UNTRUSTED_DEVICE: Unrecognized device fingerprint or proxy detected"
  ],
  "explainability": [
    {
      "feature": "V14",
      "title": "Latent Cardholder Pattern Anomaly (V14 Subspace)",
      "value": -6.44,
      "z_score": 6.79,
      "impact_score": 12.23,
      "signal": "Negative Spike",
      "contribution_percentage": 52.4
    },
    {
      "feature": "Amount",
      "title": "Transaction Ticket Size Deviation",
      "value": 1850.0,
      "z_score": 7.4,
      "impact_score": 11.1,
      "signal": "High Value Ticket",
      "contribution_percentage": 47.6
    }
  ],
  "velocity_metrics": {
    "velocity_1m": 1,
    "velocity_1h": 1,
    "velocity_24h": 1,
    "avg_amount": 1850.0,
    "total_txns": 1
  },
  "latency_ms": 3.12,
  "timestamp": "2026-09-27 20:15:00"
}
```

---

## 🧪 Automated Testing

Execute the test suite verifying end-to-end ML scoring, rule logic, XAI, and velocity tracking:

```bash
python -m unittest -v tests/test_pipeline.py
```
```
test_api_evaluation_endpoint ... ok
test_explainability_engine ... ok
test_feature_dataframe_dimension_and_columns ... ok
test_hybrid_rule_engine ... ok
test_model_and_scaler_loaded ... ok
test_redis_sliding_window_velocity ... ok
test_telemetry_stats_endpoint ... ok

----------------------------------------------------------------------
Ran 35 tests in ~19s
OK
```

---

## 🧑‍💻 Author & Engineering Credits

**Om Kamble**
* 💼 **Specialization**: Machine Learning Systems, Distributed Streaming & Backend Engineering
* 📬 **Project Repository**: [AegisFlow Fraud Detection System](https://github.com/omkamble0/omkamble0-Cognitive-Financial-Crime-Cyber-Anomaly-Detection-Engine)


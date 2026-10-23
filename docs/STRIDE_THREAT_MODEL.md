# 🛡️ FinCipher AI — Enterprise STRIDE Threat Model & AI Security Whitepaper
**Author:** Om Kamble  
**Version:** v2.4-enterprise  
**Standards:** Microsoft STRIDE Threat Modeling | OWASP Top 10 API Security | OWASP Machine Learning Top 10 | PCI-DSS 4.0 | FinCEN BSA  

---

## 1. Executive Summary

FinCipher AI is engineered under a **Zero-Trust, Defense-in-Depth Security Model**. Unlike classical software where vulnerabilities are confined to application and network layers, AI-driven payment fraud systems face a dual threat surface:
1. **Conventional Web & API Attack Vectors:** SQL injection, broken object-level authorization (BOLA), brute force, credential stuffing, CORS misconfigurations, and privilege escalation.
2. **Artificial Intelligence & Machine Learning Vulnerabilities:** Adversarial model evasion (FGSM, gradient masking), latent manifold spoofing, feature smurfing, data poisoning, model extraction/inversion, and LLM agent tool abuse.

This document formalizes the **STRIDE Threat Model** applied across FinCipher AI’s architecture and enumerates the defensive mitigations enforced in code.

---

## 2. FinCipher AI System Architecture & Trust Boundaries

```
      TRUST BOUNDARY 0: UNTRUSTED EXTERNAL WORLD
      [ Adversary / Carding Botnet / Legitimate Cardholder / Merchant Gateway ]
                         │
                         ▼ (HTTPS / TLS 1.3 / OWASP Ingress Filter)
      ═══════════════════╪══════════════════════════════════════════════════════
      TRUST BOUNDARY 1: PERIMETER & IDENTITY GATEWAY
      [ Rate Limiter (CWE-307) | JWT Authenticator (CWE-285) | CORS Filter (CWE-942) ]
                         │
                         ▼ (Sub-3.5ms Payment Pipeline)
      ═══════════════════╪══════════════════════════════════════════════════════
      TRUST BOUNDARY 2: COGNITIVE DEFENSE CITADEL
      ┌────────────────────────────────────────────────────────────────────────┐
      │  [ Universal Feature Extractor & PII Sanitizer (Zero-Trust Tokenizer) ] │
      │                                │                                       │
      │       ┌────────────────────────┴────────────────────────┐              │
      │       ▼                                                 ▼              │
      │  [ Supervised Random Forest ]            [ BiGAN / AnoGAN Critic ]     │
      │  (Supervised Classifier)                 (Manifold L2 Residual Guard)  │
      │       │                                                 │              │
      │       └────────────────────────┬────────────────────────┘              │
      │                                ▼                                       │
      │            [ Hybrid Deterministic Decision Engine ]                    │
      │            (Velocity Heuristics + Multi-Model Consensus Override)      │
      └────────────────────────────────┬───────────────────────────────────────┘
                         │
                         ▼ (Cryptographic Non-Repudiation)
      ═══════════════════╪══════════════════════════════════════════════════════
      TRUST BOUNDARY 3: IMMUTABLE AUDIT LEDGER & PERSISTENCE
      [ SHA-256 Merkle Ledger (CWE-312) | SQL Parameterized Store (CWE-89) | MLflow Registry ]
```

---

## 3. Comprehensive STRIDE Threat Matrix

The STRIDE methodology decomposes potential threats across six fundamental vectors:

### 3.1. S — Spoofing (Identity & Entity Deception)
| Threat ID | Threat Description | Attack Surface | FinCipher AI Defensive Mitigation | Code Implementation |
|---|---|---|---|---|
| **STR-S1** | Operator Identity Spoofing in Audit Trail | REST API (`/cases/{id}/notes`, `/actions`) | Analyst operator identity is cryptographically bound to authenticated JWT claims (`current_user["username"]`). Operator payload fields cannot be overridden. | [`src/api/main.py:1082`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/api/main.py) |
| **STR-S2** | Cardholder Synthetic Identity / Sybil Attack | Ingestion Pipeline | Device fingerprint entropy evaluation, canvas mutation detection, and impossible geo-velocity travel checks (Haversine thresholding). | [`src/engine/threat_intelligence.py`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/engine/threat_intelligence.py) |
| **STR-S3** | Webhook / Tenant Spoofing | Multi-Tenant Ingress | Per-tenant API token authentication and tenant-scoped SQL queries (`WHERE tenant_id = ?`). Cross-tenant data leakage strictly prevented. | [`src/db/database.py:342`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/db/database.py) |

### 3.2. T — Tampering (Data Modification & Evasion)
| Threat ID | Threat Description | Attack Surface | FinCipher AI Defensive Mitigation | Code Implementation |
|---|---|---|---|---|
| **STR-T1** | Adversarial ML Feature Evasion (FGSM / Epsilon Noise) | Model Pipeline | Multi-Model Defense Citadel: BiGAN manifold reconstruction error $|x_{adv} - G(E(x_{adv}))|_2$ flags high-dimensional outliers even when tree models are fooled. | [`src/engine/adversarial_arena.py`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/engine/adversarial_arena.py) |
| **STR-T2** | SQL Injection (CWE-89) | Database Queries | 100% Parameterized queries across SQLite and PostgreSQL layers. String interpolation completely banned. Strict bounds checking on `limit` and `offset`. | [`src/db/database.py:339`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/db/database.py) |
| **STR-T3** | Audit Log Manipulation / Cover-Up | Forensic DB | Cryptographic SHA-256 Merkle-tree blockchain ledger. Any retrofitted tampering invalidates the cryptographic parent hash and signature chain. | [`src/engine/audit_ledger.py`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/engine/audit_ledger.py) |
| **STR-T4** | Model Weights File Tampering | Filesystem (`src/model/`) | SHA-256 integrity hash verification of `.pkl` weights before deserialization; read-only container filesystem (`readOnlyRootFilesystem: true`). | [`docker/Dockerfile`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/docker/Dockerfile) |

### 3.3. R — Repudiation (Disavowal of Actions)
| Threat ID | Threat Description | Attack Surface | FinCipher AI Defensive Mitigation | Code Implementation |
|---|---|---|---|---|
| **STR-R1** | Analyst Denies Action or Note Authoring | Case Management | Cryptographically chained audit ledger records operator username, timestamp, previous state, new state, and reason in tamper-proof hash chains. | [`src/engine/audit_ledger.py`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/engine/audit_ledger.py) |
| **STR-R2** | Disputed Payment Decision (Customer / Merchant) | Authorization Gate | Full decision provenance logged with Explainable AI (XAI) reason codes, feature Z-scores, and rule triggers for FinCEN 31 CFR § 1020.320 compliance. | [`src/engine/explainability.py`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/engine/explainability.py) |

### 3.4. I — Information Disclosure (Data Leakage & Model Inversion)
| Threat ID | Threat Description | Attack Surface | FinCipher AI Defensive Mitigation | Code Implementation |
|---|---|---|---|---|
| **STR-I1** | Plaintext PII / Credit Card Leakage | Logs & Dashboard | Automated PII masking/tokenization replaces PANs with masked hashes (`************1234`) and hashes email/phone before persistence or broadcast. | [`src/engine/data_contract.py`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/engine/data_contract.py) |
| **STR-I2** | Insecure CORS Wildcard Exploit (CWE-942) | REST API | Enforced explicit `allow_origins` whitelist with `allow_credentials=False` when wildcard origins are detected. Browser CSRF credential theft blocked. | [`src/api/main.py:126`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/api/main.py) |
| **STR-I3** | Model Extraction & Gradient Inversion | Scoring API | The API does not expose raw neural gradients; outputs are quantized confidence bands with decision recommendations rather than raw continuous outputs. | [`src/api/main.py:810`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/api/main.py) |

### 3.5. D — Denial of Service (Exhaustion & Latency Spikes)
| Threat ID | Threat Description | Attack Surface | FinCipher AI Defensive Mitigation | Code Implementation |
|---|---|---|---|---|
| **STR-D1** | Brute-Force Password / Auth Flooding (CWE-307) | Auth Endpoint | In-memory sliding-window rate limiter: 5 consecutive failed logins triggers an automatic 5-minute IP/user lockout returning HTTP 429. | [`src/api/main.py:1010`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/api/main.py) |
| **STR-D2** | High-Traffic Surge Breaching Sub-3.5ms SLA | Core Pipeline | Adaptive Load Shedder: gracefully sheds secondary XAI subspace calculations when latency spikes, guaranteeing critical authorization under 3.5ms. | [`src/engine/load_shedder.py`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/engine/load_shedder.py) |
| **STR-D3** | Distributed Carding Micro-Transaction Storm | Payment Gate | Carding Sentinel and Redis Sliding-Window Velocity Store intercept rapid low-dollar carding bursts before reaching downstream merchant processors. | [`src/engine/carding_sentinel.py`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/engine/carding_sentinel.py) |

### 3.6. E — Elevation of Privilege (Unauthorized Access)
| Threat ID | Threat Description | Attack Surface | FinCipher AI Defensive Mitigation | Code Implementation |
|---|---|---|---|---|
| **STR-E1** | Unauthorized Access to User Registry (CWE-200/284) | User Mgmt API | `GET /api/v1/auth/users` strictly protected with `require_roles("admin", "fraud_manager")`. Operators cannot view system credentials or roles. | [`src/api/main.py:1042`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/api/main.py) |
| **STR-E2** | Path Traversal / Arbitrary File Overwrite (CWE-22/434) | Upload Endpoint | Dataset uploads sanitized via `os.path.basename` and restricted to whitelisted `.csv` extensions within isolated `/data` directories. | [`src/api/main.py:1738`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/api/main.py) |
| **STR-E3** | Container Breakout & Linux Privilege Escalation | Runtime Pod | Docker container hardened per CIS Benchmark: runs as non-root user `aegisuser` (UID: 10001), drops all Linux capabilities (`drop: ["ALL"]`), read-only rootfs. | [`docker/Dockerfile`](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/docker/Dockerfile) |

---

## 4. Adversarial Machine Learning Threat Analysis

FinCipher AI includes defensive primitives against the **OWASP Machine Learning Top 10**:

1. **ML01: Input Manipulation (Evasion Attacks):**  
   Adversaries apply Fast Gradient Sign Method (FGSM) or feature smurfing (altering `V14`, `V12`, `V4`) to shift malicious transactions across decision boundaries.  
   *Mitigation:* FinCipher AI evaluates transactions through a **BiGAN Manifold Residual Critic**. When supervised confidence drops but manifold reconstruction error $|x - G(E(x))|_2$ spikes, the system triggers a **Multi-Model Consensus Override**, forcing a 2FA challenge or block.

2. **ML02: Data Poisoning & Concept Drift:**  
   Adversaries gradually introduce subtle label-skewed transactions to distort the online training distribution.  
   *Mitigation:* Population Stability Index (PSI) drift monitoring continuously tracks 6 key latent features (`V4`, `V10`, `V12`, `V14`, `V17`, `Amount`). If PSI breaches `0.25`, the system alerts operators and executes an **Automated Model Rollback** to the verified Champion baseline.

3. **ML06: AI Agent Tool Abuse / Prompt Injection:**  
   Adversaries craft transaction metadata notes attempting to trick forensic LLM copilot agents into clearing fraudulent alerts.  
   *Mitigation:* LangChain agent tools enforce strict JSON schemas and validate inputs via deterministic Python routines rather than unconstrained LLM shell execution.

---

## 5. Summary Compliance Verification

- **PCI-DSS 4.0:** Section 3.4 (PAN Masking), Section 6.4 (Public-facing Web Application Protection), Section 10.2 (Automated Audit Trails).
- **FinCEN 31 CFR § 1020.320:** 5-year immutable data retention policy with Merkle-chain proof export for Suspicious Activity Reports (SAR).
- **CIS Benchmark:** Zero root execution, non-root UID 10001, immutable read-only rootfs, zero-dependency Python health checks.

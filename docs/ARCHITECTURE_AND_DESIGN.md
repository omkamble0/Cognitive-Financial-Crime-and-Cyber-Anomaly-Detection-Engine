# 🌐 AegisNexus: Generic Modular Risk, Anomaly & Cyber-Investigation Platform
## Enterprise Architecture Specification & Multi-Domain System Design
**Author:** Om Kamble | **Role:** Lead Architect & Principal Systems Engineer  
**Status:** Architecture Blueprint & Phase 1 Execution Plan  

---

## 1. Executive Vision & Core Philosophy

The goal is to evolve the platform into **AegisNexus** — a **domain-agnostic, event-driven cognitive risk and investigation platform**. 

Rather than building isolated point solutions for banking fraud, IT security, or e-commerce abuse, AegisNexus decouples **Event Ingestion, Entity Graph Linkage, Baseline Modeling, and Case Orchestration** into a generic, high-throughput core, while domain-specific heuristics, features, and compliance rules live in **pluggable domain modules**.

```
+----------------------------------------------------------------------------------------------------+
|                                    AegisNexus Core Architecture                                    |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [ Multi-Source Ingestion: REST / Webhooks / Syslog / Kafka Streams / CloudTrail / EventBridge ]     |
|       │                                                                                            |
|       ▼                                                                                            |
|  ┌──────────────────────────────────────────────────────────────────────────────────────────────┐  |
|  │                       Generic Ingestion, Normalization & Validation Layer                    │  |
|  │  • Strict Pydantic Schema Validation   • Schema Normalizer   • Distributed Trace ID Injector │  |
|  └──────────────────────────────────────────────┬───────────────────────────────────────────────┘  |
|                                                 │                                                  |
|                                                 ▼                                                  |
|  ┌──────────────────────────────────────────────────────────────────────────────────────────────┐  |
|  │                                Entity Linkage & Graph Store Engine                           │  |
|  │  • Entity Resolution (User, Device, IP, Account, Asset, Merchant, Session, File)             │  |
|  │  • Bi-directional Relationship Edges (same_device, same_ip, same_beneficiary, shared_session)│  |
|  └──────────────────────────────────────────────┬───────────────────────────────────────────────┘  |
|                                                 │                                                  |
|         ┌───────────────────────────────────────┴───────────────────────────────────────┐          |
|         ▼                                       ▼                                       ▼          |
|  ┌─────────────────────────────┐ ┌─────────────────────────────┐ ┌─────────────────────────────┐   |
|  │    🏦 Banking & AML Module  │ │  🛡️ Cybersecurity / SOC Mod │ │   🛒 E-Commerce & Retail    │   |
|  │ • Payment Anomaly & Velocity│ │ • Impossible Travel & ATO   │ │ • Promo & Voucher Abuse     │   |
|  │ • Structuring & Mule Rings  │ │ • Privileged Access Abuse   │ │ • Refund Fraud & Chargebacks│   |
|  │ • Sanctions / PEP Screening │ │ • Lateral Movement & Exfil  │ │ • Bot Traffic & Fake Orders │   |
|  └──────────────┬──────────────┘ └──────────────┬──────────────┘ └──────────────┬──────────────┘   |
|                 │                               │                               │                  |
|                 └───────────────────────┬───────┴───────────────────────────────┘                  |
|                                         ▼                                                          |
|  ┌──────────────────────────────────────────────────────────────────────────────────────────────┐  |
|  │                        Core Composite Risk & Anomaly Scoring Engine                          │  |
|  │  • Unsupervised BiGAN / Isolation Forest   • Pluggable Rule Engine   • Entity Baseline Drift │  |
|  └──────────────────────────────────────────────┬───────────────────────────────────────────────┘  |
|                                                 │                                                  |
|                                                 ▼                                                  |
|  ┌──────────────────────────────────────────────────────────────────────────────────────────────┐  |
|  │                     Alert Deduplication, Suppression & Triage Engine                         │  |
|  │  • Sliding Window Fingerprint Suppressor   • Priority Tiering   • Automated Triage Evaluator │  |
|  └──────────────────────────────────────────────┬───────────────────────────────────────────────┘  |
|                                                 │                                                  |
|                                                 ▼                                                  |
|  ┌──────────────────────────────────────────────────────────────────────────────────────────────┐  |
|  │                    Case Management, Policy Orchestration & Workflow Engine                   │  |
|  │  • Automated Case Escalation   • Forensic Timeline   • Analyst Notes & Status Lifecycle      │  |
|  │  • SHA-256 Merkle Audit Ledger • FinCEN SAR / SOC Incident Report Evidence Export Package    │  |
|  └──────────────────────────────────────────────────────────────────────────────────────────────┘  |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Generic Domain-Agnostic Data Model

### 2.1 Generic Entity Types
Entities represent identifiable nodes across any risk domain:

| Entity Type | Description | Common Attributes |
|---|---|---|
| `USER` | Human actor or customer | `user_id`, `email`, `risk_tier`, `created_at` |
| `ACCOUNT` | Bank account, customer wallet, or system login ID | `account_number`, `type`, `balance`, `currency` |
| `DEVICE` | Hardware, mobile, or workstation terminal | `fingerprint`, `os`, `browser`, `is_emulator` |
| `IP_ADDRESS` | Network origin | `ip_str`, `country`, `asn`, `is_vpn`, `is_tor` |
| `MERCHANT` | E-commerce seller, store, or vendor | `merchant_id`, `category`, `mcc`, `chargeback_rate` |
| `ASSET` | IT server, database, AWS S3 bucket, or workstation | `hostname`, `criticality`, `vpc_id`, `os` |
| `FILE` | Data file, executable, or database record | `file_hash_sha256`, `path`, `classification` |
| `SESSION` | Interactive token, cookie, or API session | `session_token`, `expires_at`, `mfa_verified` |
| `THREAT_INDICATOR` | Known malicious IoC (IP, hash, domain) | `ioc_type`, `confidence`, `threat_group` |

### 2.2 Generic Event Schema
All inbound data normalizes into a standard event contract:

```json
{
  "event_id": "EVT-2026-948194",
  "domain": "BANKING | CYBERSECURITY | ECOMMERCE",
  "event_type": "PAYMENT | LOGIN | ACCESS_REQUEST | ORDER | REFUND | FILE_ACCESS | SYSTEM_LOG",
  "timestamp": 1729681200.0,
  "source": "api_gateway | cloudtrail | pos_terminal | auth_service",
  "primary_entity_id": "usr_99182",
  "entities": [
    {"type": "USER", "id": "usr_99182", "role": "ACTOR"},
    {"type": "DEVICE", "id": "dev_mac_8f910a", "role": "ORIGIN"},
    {"type": "IP_ADDRESS", "id": "198.51.100.44", "role": "NETWORK"},
    {"type": "ACCOUNT", "id": "acc_chk_8819", "role": "SOURCE"},
    {"type": "ACCOUNT", "id": "acc_sav_1120", "role": "DESTINATION"}
  ],
  "payload": {
    "amount": 4500.00,
    "currency": "USD",
    "payment_method": "WIRE",
    "beneficiary_country": "CY"
  },
  "context": {
    "geo_lat": 51.5074,
    "geo_lon": -0.1278,
    "user_agent": "Mozilla/5.0 ...",
    "tenant_id": "tenant_enterprise_01"
  }
}
```

### 2.3 Entity Graph Relationship Model
Edges are created dynamically during event processing:
- `(USER)-[:USES_DEVICE]->(DEVICE)`
- `(USER)-[:LOGS_IN_FROM]->(IP_ADDRESS)`
- `(ACCOUNT)-[:TRANSFERS_FUNDS_TO {weight: amount}]->(ACCOUNT)`
- `(USER)-[:PLACES_ORDER]->(ORDER)-[:SHIPS_TO]->(ADDRESS)`
- `(DEVICE)-[:ACCESSED_ASSET]->(ASSET)`

---

## 3. Pluggable Domain Modules

```
                ┌──────────────────────────────────┐
                │     Generic BaseDomainModule     │
                │  - validate_event()              │
                │  - extract_entities()            │
                │  - evaluate_heuristics()         │
                │  - compute_domain_risk()         │
                │  - generate_evidence_narrative() │
                └─────────────────┬────────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  BankingModule   │    │  CybersecModule  │    │ EcommerceModule  │
│ • Structuring    │    │ • Impossible-    │    │ • Promo Abuse    │
│ • Mule Networks  │    │   Travel / ATO   │    │ • Refund Fraud   │
│ • AML Sanctions  │    │ • Privileged Esc │    │ • Bot Traffic    │
│ • Carding Botnet │    │ • Lateral Move   │    │ • Seller Rings   │
└──────────────────┘    └──────────────────┘    └──────────────────┘
```

---

## 4. Multi-Phase Implementation Roadmap

### Phase 1: Core Foundation, Generic Engine & Scaffold
- Monorepo directory scaffold (`apps/`, `services/`, `libs/`).
- Generic entity & event schema contracts.
- Database schema migrations for entities, events, relationships, alerts, and cases.
- Ingestion API with schema normalization and multi-domain validation.
- Alert deduplication and suppression window engine.
- Case management workflow transitions with audit logging.

### Phase 2: Anomaly Detection, Baselining & Graph Engine
- Rolling entity behavioral baselines (Z-score velocity, peer-group deviations).
- Graph syndicate and community clustering (NetworkX / PageRank).
- Threat intelligence IoC feeds (Tor, VPN, malicious IP lookups).
- Policy engine and automated triage dispatchers.

### Phase 3: Pluggable Domain Adapters, XAI & Compliance
- **Banking Adapter:** Wire structuring, carding sentinel, mule networks, AML.
- **Cybersecurity Adapter:** Impossible travel, brute force, lateral access, exfiltration.
- **E-Commerce Adapter:** Promo abuse, refund velocity, chargeback fraud, fake orders.
- Explainable AI (XAI) forensic narrative generation per domain.
- End-to-end integration test suite and seed scenario datasets.

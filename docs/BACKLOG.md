# 📋 FinCipher AI Platform Engineering Backlog
## Phase-by-Phase Implementation Plan

---

### Phase 1: Core Foundation, Ingestion & Generic Data Models
- [x] **Task 1.1: Architecture & Domain Model Blueprint** (`docs/ARCHITECTURE_AND_DESIGN.md`)
- [x] **Task 1.2: Monorepo Scaffold**
  - `libs/models`: Pydantic V2 schemas for generic `Entity`, `Event`, `Relationship`, `Alert`, `Case`, `AuditEntry`.
  - `libs/common`: Universal utilities, time/hash helpers, logging, error handling.
  - `libs/security`: Zero-trust tokenization, PII masking, RBAC.
  - `services/ingestion`: Multi-source ingestion normalizer.
  - `services/risk_engine`: Generic composite scoring & anomaly orchestration.
  - `services/case_management`: Case workflow state machine & evidence packaging.
- [x] **Task 1.3: Unified Database Layer & Schemas**
  - Tables for generic `entities`, `generic_events`, `entity_relationships`, `alerts`, `cases`, `case_notes`, `audit_ledger`.
  - Dual SQLite & PostgreSQL support with automatic table bootstrap.
- [x] **Task 1.4: Ingestion REST API**
  - `POST /api/v1/events/ingest`: Accepts any domain event, validates schema, resolves entities, and dispatches to risk pipeline.
  - `POST /api/v1/events/batch`: Bulk high-throughput event ingestion.
  - Convenience normalizers: `/ingest/banking`, `/ingest/cyber`, `/ingest/ecommerce`.
- [x] **Task 1.5: Alert Deduplication & Suppression Engine**
  - Fingerprint generator based on `(domain, primary_entity_id, rule_signature)`.
  - Configurable sliding window suppression to eliminate analyst alert fatigue.
- [x] **Task 1.6: Case Management Workflow Engine**
  - States: `OPEN` -> `IN_REVIEW` -> `ESCALATED` -> `RESOLVED` / `CLOSED`.
  - Automated case creation from alert clusters with priority scoring.

---

### Phase 2: Anomaly Engine, Entity Baselines & Graph Analytics
- [x] **Task 2.1: Entity Behavioral Baseline Engine**
  - Rolling mean, variance, and Z-score tracking per entity using Welford's algorithm.
  - Peer-group and historical deviation scoring.
- [x] **Task 2.2: Universal Graph Analytics Engine**
  - Multi-hop graph link traversal (Find all entities connected by shared IP/Device within 2-3 hops).
  - Syndicate ring classification (`COLLUDING_IDENTITIES_SHARED_INFRASTRUCTURE`).
- [x] **Task 2.3: Threat Intelligence Connector Layer**
  - Universal IoC matcher (Tor exit nodes, bulletproof proxies, disposable emails, OFAC SDN addresses).
  - Dynamic analyst blocklist registration.
- [x] **Task 2.4: Policy Engine & Automated Action Dispatcher**
  - Declarative policy rules with automated quarantine and P1 case escalation.

---

### Phase 3: Pluggable Domain Modules & Realistic Seed Data
- [x] **Task 3.1: Banking & Payment Module**
  - Velocity checks, carding botnet detection, AML structuring avoidance ($9k-$10k), sanctions matching.
- [x] **Task 3.2: Cybersecurity / SOC Module**
  - Impossible travel (>1,100 km/h), credential stuffing / brute force bursts, privileged access escalation.
- [x] **Task 3.3: E-Commerce & Retail Module**
  - Promo / coupon code farming, refund velocity abuse, fake order bot swarms.
- [x] **Task 3.4: Compliance, Audit & Explainability (XAI)**
  - Domain-specific forensic narratives (FinCEN SAR, SOC Incident Report, Chargeback Evidence).
  - SHA-256 Merkle chain cryptographic proof generation.
- [x] **Task 3.5: Seed Scenario Data & Verification Tests**
  - Realistic multi-domain seed generator: Banking attack, SOC credential stuffing attack, E-commerce promo blitz (`scripts/seed_multi_domain_scenarios.py`).
  - 100 comprehensive unit and integration tests asserting end-to-end flows across all 3 domains.

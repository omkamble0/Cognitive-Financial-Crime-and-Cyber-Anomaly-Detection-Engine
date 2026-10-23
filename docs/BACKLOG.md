# 📋 AegisNexus Platform Engineering Backlog
## Phase-by-Phase Implementation Plan

---

### Phase 1: Core Foundation, Ingestion & Generic Data Models
- [x] **Task 1.1: Architecture & Domain Model Blueprint** (`docs/ARCHITECTURE_AND_DESIGN.md`)
- [ ] **Task 1.2: Monorepo Scaffold**
  - `libs/models`: Pydantic V2 schemas for generic `Entity`, `Event`, `Relationship`, `Alert`, `Case`, `AuditEntry`.
  - `libs/common`: Universal utilities, time/hash helpers, logging, error handling.
  - `libs/security`: Zero-trust tokenization, PII masking, RBAC.
  - `services/ingestion`: Multi-source ingestion normalizer.
  - `services/risk_engine`: Generic composite scoring & anomaly orchestration.
  - `services/case_management`: Case workflow state machine & evidence packaging.
- [ ] **Task 1.3: Unified Database Layer & Schemas**
  - Tables for generic `entities`, `events`, `relationships`, `alerts`, `cases`, `case_notes`, `audit_ledger`.
  - Dual SQLite & PostgreSQL support with automatic table bootstrap.
- [ ] **Task 1.4: Ingestion REST API**
  - `POST /api/v1/events/ingest`: Accepts any domain event, validates schema, resolves entities, and dispatches to risk pipeline.
  - `POST /api/v1/events/batch`: Bulk high-throughput event ingestion.
- [ ] **Task 1.5: Alert Deduplication & Suppression Engine**
  - Fingerprint generator based on `(domain, primary_entity_id, rule_signature)`.
  - Configurable sliding window suppression to eliminate analyst alert fatigue.
- [ ] **Task 1.6: Case Management Workflow Engine**
  - States: `OPEN` -> `TRIAGED` -> `IN_INVESTIGATION` -> `ESCALATED` -> `RESOLVED` / `DISMISSED`.
  - Automated case creation from alert clusters with priority scoring.

---

### Phase 2: Anomaly Engine, Entity Baselines & Graph Analytics
- [ ] **Task 2.1: Entity Behavioral Baseline Engine**
  - Rolling mean, variance, and Z-score tracking per entity.
  - Peer-group behavior profiling.
- [ ] **Task 2.2: Universal Graph Analytics Engine**
  - Multi-hop graph link traversal (Find all entities connected by shared IP/Device within 3 hops).
  - PageRank centrality & Louvain community detection.
- [ ] **Task 2.3: Threat Intelligence Connector Layer**
  - Universal IoC matcher (Tor exit nodes, residential proxy detection, known threat actors).
- [ ] **Task 2.4: Policy Engine & Automated Action Dispatcher**
  - Declarative policy rules (`IF risk_score > 0.85 AND entity.tier == 'CRITICAL' THEN FREEZE_ACCOUNT`).

---

### Phase 3: Pluggable Domain Modules & Realistic Seed Data
- [ ] **Task 3.1: Banking & Payment Module**
  - Velocity checks, carding botnet detection, smurfing / structuring rings, AML sanctions matching.
- [ ] **Task 3.2: Cybersecurity / SOC Module**
  - Impossible travel, credential stuffing / brute force, lateral access abuse, data exfiltration.
- [ ] **Task 3.3: E-Commerce & Retail Module**
  - Promo / coupon code farming, refund abuse, fake order bot swarms, chargeback arbitration.
- [ ] **Task 3.4: Compliance, Audit & Explainability (XAI)**
  - Domain-specific forensic narratives (FinCEN SAR, SOC Incident Report, Chargeback Evidence).
  - SHA-256 Merkle chain cryptographic proof generation.
- [ ] **Task 3.5: Seed Scenario Data & Verification Tests**
  - Realistic multi-domain seed generator: Banking attack, SOC credential stuffing attack, E-commerce promo blitz.
  - Comprehensive unit and integration test suite asserting end-to-end flows across all 3 domains.

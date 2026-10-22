# FinCipher AI — Incident Response & SOC Operations Runbook

**Document Version:** 2.4-enterprise  
**Classification:** Confidential — Financial Crime & Cyber Operations  
**Author:** Om Kamble (Lead Platform Architect)  
**Target Audience:** Fraud Operations Analysts, Security Operations Center (SOC) Engineers, Site Reliability Engineers (SRE)  

---

## 1. Incident Classification & Response SLAs

| Severity | Definition | Target Triage SLA | Target Mitigation SLA | Escalation Target |
| :--- | :--- | :--- | :--- | :--- |
| **SEV-1 (Critical)** | Core payment gateway p95 latency $>3.5\text{ms}$, distributed botnet carding storm ($>100\text{ tx/s}$), or Merkle ledger tampering detected. | $< 5\text{ minutes}$ | $< 15\text{ minutes}$ | Lead Architect, VP Risk Ops, On-Call SRE |
| **SEV-2 (High)** | Feature Concept Drift $\text{PSI} > 0.25$, major mule syndicate detected ($>10\text{ nodes}$), or Common Point of Purchase (CPP) terminal breach. | $< 15\text{ minutes}$ | $< 60\text{ minutes}$ | Fraud Operations Lead, Senior ML Engineer |
| **SEV-3 (Medium)** | Canary model challenger underperforming champion, L1 cache hit ratio drop, or batch of suspicious transactions requiring supervisory triage. | $< 1\text{ hour}$ | $< 4\text{ hours}$ | Shift Risk Analyst, Data Operations |
| **SEV-4 (Low)** | Minor false-positive report, user entitlement query, or scheduled rule optimization request. | $< 8\text{ hours}$ | $< 24\text{ hours}$ | Junior Analyst Queue |

---

## 2. Standard Operating Procedures (SOPs)

### Playbook 1: In-Line Payment SLA Latency Breach (SEV-1)

#### Symptoms:
- Prometheus Alert: `FinCipherGatewayLatencyBreach` (`fincipher_inference_latency_ms{quantile="0.95"} > 3.5ms`).
- Grafana Dashboard Panel: *In-Line Gateway Latency vs. 3.5ms Financial SLA* turns Amber or Red.

#### Immediate Response Protocol:
1. **Verify Ingress Traffic Rate:**
   ```bash
   curl -s http://127.0.0.1:8000/ready | jq .
   ```
   Check `"load_shedder_mode"` and `"async_enrichment_pool"`.
2. **Activate Adaptive Fast-Path Load Shedder:**
   - If incoming load spikes beyond gateway capacity, activate shedding mode:
     ```bash
     curl -X POST http://127.0.0.1:8000/api/v1/rules/shedding-mode -H "Content-Type: application/json" -d '{"mode": "FAST_PATH_ONLY"}'
     ```
   - This routes non-critical graph clustering and drift estimation to the background worker pool (`background_transaction_enrichment_task`), preserving $<1.2\text{ms}$ decision latencies.
3. **Inspect Redis Feature Store Health:**
   - Check if Redis connection transitioned to in-memory fallback:
     ```bash
     curl -s http://127.0.0.1:8000/health/readiness | jq .checks.feature_store
     ```
   - If Redis connection dropped, verify Pod connectivity and restart Redis cluster.
4. **Post-Mortem Resolution:**
   - Record incident timeline and review `X-Response-Time-Ms` egress headers.

---

### Playbook 2: Distributed Carding Storm & BIN Probing (SEV-1)

#### Symptoms:
- Prometheus Metric: `fincipher_transactions_total{decision="BLOCK"}` velocity increases by $>300\%$.
- Bloom filter quarantine hits rise rapidly.

#### Immediate Response Protocol:
1. **Identify Attacking IP Subnets & Target BIN Ranges:**
   ```bash
   curl -s http://127.0.0.1:8000/api/v1/security/bot-sentinel/stats | jq .
   ```
2. **Execute Pre-Emptive Short-Circuit Quarantine:**
   - Quarantined cards or IPs are short-circuited in RAM via the Counting Bloom Filter in $<0.01\text{ms}$.
   - Add malicious CIDR or card identifier:
     ```bash
     curl -X POST http://127.0.0.1:8000/api/v1/rules -H "Content-Type: application/json" -d '{
       "id": "RULE_BOTNET_IP_QUARANTINE_01",
       "field": "ip_address",
       "operator": "==",
       "threshold": "198.51.100.99",
       "action": "BLOCK",
       "risk_boost": 1.0,
       "reason": "SEV-1 Botnet Probing Quarantined"
     }'
     ```
3. **Escalate to Case Management:**
   - Open a Critical investigation dossier in the FinCipher AI Cockpit (`Cases & Alerts` tab) assigning to the senior fraud operations shift.

---

### Playbook 3: Concept Drift Alert — Population Stability Index $\text{PSI} > 0.25$ (SEV-2)

#### Symptoms:
- Prometheus Metric: `fincipher_drift_psi > 0.25` (Significant Distribution Shift).
- Model classification accuracy or false positive rate starts drifting.

#### Immediate Response Protocol:
1. **Retrieve Feature-Level Drift Breakdown:**
   ```bash
   curl -s http://127.0.0.1:8000/api/v1/drift/metrics | jq .
   ```
2. **Isolate Drifting Features:**
   - Check deciles for `Amount`, `V14` (cardholder pattern), `V12` (merchant profile), and `V4` (velocity).
3. **Evaluate MLOps Canary Model Performance:**
   ```bash
   curl -s http://127.0.0.1:8000/api/v1/mlops/models | jq .
   ```
   - If a shadow/canary model trained on recent distribution performs with higher F1 score ($\ge 0.90$), execute promotion:
     ```bash
     curl -X POST http://127.0.0.1:8000/api/v1/mlops/models/v2.4.0-rc1/promote -H "Content-Type: application/json" -d '{
       "target_stage": "PRODUCTION",
       "operator": "lead_ml_engineer",
       "reason": "Resolved PSI 0.28 drift via retrained candidate"
     }'
     ```

---

### Playbook 4: Merkle Audit Hash Chain Tamper Alert (SEV-1)

#### Symptoms:
- Metric: `fincipher_merkle_integrity_intact == 0`.
- Grafana Panel *Merkle Hash Chain Status* flashes RED.

#### Immediate Response Protocol:
1. **Locate Corrupted Audit Block Index:**
   ```bash
   curl -s http://127.0.0.1:8000/api/v1/audit/verify | jq .
   ```
   - Returns the exact block index, expected hash, and actual hash.
2. **Freeze Audit Write Pool & Isolate Node:**
   - Pull the affected container instance out of Kubernetes ingress traffic:
     ```bash
     kubectl drain pod-fincipher-ai-xxx --ignore-daemonsets
     ```
3. **Re-synchronize Ledger from Consensus Peer:**
   - Replay verified transactions from PostgreSQL audit table `analyst_actions` and `rule_audits`.
4. **Trigger Compliance Audit Protocol:**
   - Document non-repudiation incident and notify Corporate Compliance Officer.

---

### Playbook 5: Canary Model Rollback & Emergency Degradation (SEV-2)

#### Symptoms:
- Newly promoted production model experiences anomalous latency ($>3.5\text{ms}$) or False Positive Rate ($>2\%$).

#### Immediate Response Protocol:
1. **Execute Zero-Downtime Rollback:**
   ```bash
   curl -X POST http://127.0.0.1:8000/api/v1/mlops/models/rollback -H "Content-Type: application/json" -d '{
     "target_version": "v2.3.0",
     "operator": "fraud_operations_manager",
     "reason": "Degraded p95 latency detected in v2.4 canary"
   }'
   ```
2. **Confirm Active Production Champion:**
   ```bash
   curl -s http://127.0.0.1:8000/api/v1/mlops/models/production | jq .
   ```
   - Ensure `"stage": "PRODUCTION"` is restored to `v2.3.0`.

---

## 3. Regulatory Reporting: FinCEN Suspicious Activity Report (SAR) SOP

When a fraud ring, smurfing swarm, or sanctioned entity transaction exceeds regulatory thresholds ($\ge \$2,000$ with suspected criminal activity):

1. **Access Cockpit Incident Dossier:**
   - Open FinCipher AI Cockpit $\to$ `Cases & Alerts` $\to$ Select Case.
2. **Generate Standardized FinCEN Narrative:**
   ```bash
   curl -X POST http://127.0.0.1:8000/api/v1/copilot/generate-sar -H "Content-Type: application/json" -d '{
     "transaction_id": "TXN_SAR_EVIDENTIARY",
     "institution_name": "FinCipher AI Financial Technologies Inc."
   }'
   ```
3. **File BSA E-Filing Document:**
   - Verify tracking ID `SAR-YYYYMMDD-XXXX` and append cryptographically signed Merkle block signature as proof of non-repudiation.

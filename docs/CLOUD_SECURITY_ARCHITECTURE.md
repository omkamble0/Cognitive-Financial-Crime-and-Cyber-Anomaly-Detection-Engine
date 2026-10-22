# AegisFlow — Industrial Cloud Security & Infrastructure Architecture
**Author:** Om Kamble  
**Version:** v2.3-core  
**Compliance Standards:** PCI-DSS 4.0 (Req 1.2, 1.3, 6.4, 10.2) | CIS Docker Benchmark | CIS Kubernetes Benchmark v1.8

---

## 1. Executive Summary & Security Posture
AegisFlow is engineered with a **defense-in-depth, zero-trust cloud architecture**. Every component from the base container image to cluster networking is hardened according to global financial cybersecurity regulations (PCI-DSS 4.0, SOC 2 Type II, ISO/IEC 27001).

```
                            [ Public / Ingress Traffic ]
                                          │
                    [ Ingress Controller (TLS 1.3 / Rate Limiting) ]
                                          │ (Port 8000)
    ══════════════════════════════════════╪════════════════════════════════════════
    AegisFlow Kubernetes Namespace (Zero-Trust NetworkPolicy Boundary)
    ══════════════════════════════════════╪════════════════════════════════════════
                                          ▼
                         ┌─────────────────────────────────┐
                         │   AegisFlow Engine Pods         │
                         │   - UID 10001 (aegisuser)       │
                         │   - readOnlyRootFilesystem: true│
                         │   - drop: [ALL] capabilities    │
                         │   - OWASP Security Middleware   │
                         └───────┬─────────────────┬───────┘
                                 │ (Port 6379)     │ (Port 9092)
                                 ▼                 ▼
                       ┌──────────────────┐ ┌──────────────────┐
                       │ Redis Stream     │ │ Kafka Broker     │
                       │ Feature Store    │ │ Event Pipeline   │
                       └──────────────────┘ └──────────────────┘
```

---

## 2. Container Hardening (CIS Docker Benchmark)
The multi-stage container build in [docker/Dockerfile](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/docker/Dockerfile) eliminates compiler tools from the final production runtime:

1. **Non-Root Service Account:**  
   Runs as `aegisuser` (UID: 10001, GID: 10001). Root execution is strictly disabled.
2. **Immutable Read-Only Filesystem:**  
   The application root `/app` is mounted with permission mode `550` (read-and-execute only). Write access is confined exclusively to in-memory ephemeral scratch volumes (`/tmp` and `/app/data`).
3. **Privilege Escalation Blocked:**  
   Linux capabilities are stripped (`drop: ["ALL"]`) with `allowPrivilegeEscalation: false`.
4. **Native Zero-Dependency Healthcheck:**  
   Evaluates container vitality via standard Python `urllib.request` against `/health` without requiring external binaries (`curl`/`wget`) in the container.

---

## 3. Kubernetes Pod Security Standards & Resiliency
The manifests in [docker/k8s/](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/docker/k8s/) enforce the **Restricted** profile of Kubernetes Pod Security Standards:

* **Seccomp Profile:** Enforced to `RuntimeDefault` to restrict unauthorized kernel syscalls.
* **Rolling Updates with Zero Downtime:** `maxSurge: 1`, `maxUnavailable: 0`.
* **Pod Anti-Affinity:** Distributes replicas across separate physical nodes and failure domains (`kubernetes.io/hostname`).
* **PodDisruptionBudget (PDB):** Guarantees at least 2 active replicas remain operational during cluster draining or maintenance.
* **Probes:**
  - `startupProbe`: Allows ML weights and models 60 seconds of initial load grace.
  - `livenessProbe`: Verifies event loop responsiveness on `/health` (RFC 8615).
  - `readinessProbe`: Validates ML model integrity, Redis feature store status, graph engine state, and Merkle ledger integrity on `/ready` before routing live financial ingress.

---

## 4. Zero-Trust Network Microsegmentation (PCI-DSS Req 1.2 & 1.3)
Defined in [docker/k8s/network-policy.yaml](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/docker/k8s/network-policy.yaml):

| Direction | Source / Destination | Protocol & Port | Justification |
| :--- | :--- | :--- | :--- |
| **Ingress** | `ingress-nginx` namespace | TCP 8000 | Ingress HTTP/REST traffic from authenticated edge gateway |
| **Ingress** | `monitoring` namespace | TCP 8000 | Prometheus scrape daemon (`/metrics`) |
| **Egress** | `kube-system` CoreDNS | UDP/TCP 53 | Internal service discovery DNS |
| **Egress** | `app: redis` | TCP 6379 | Sub-millisecond entity velocity feature lookups |
| **Egress** | `app: kafka` | TCP 9092 | Transaction event ingestion and DLQ streaming |
| **Egress** | *Public Internet / Other Pods* | **BLOCKED (DENY ALL)** | Mitigates data exfiltration & command-and-control backdoors |

---

## 5. OWASP & Cloud Security Middleware
Integrated in [src/api/main.py](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/src/api/main.py):

* **HSTS (`Strict-Transport-Security`):** `max-age=31536000; includeSubDomains; preload`
* **MIME Sniffing Guard:** `X-Content-Type-Options: nosniff`
* **Clickjacking Protection:** `X-Frame-Options: DENY`
* **Cross-Site Scripting Protection:** `X-XSS-Protection: 1; mode=block`
* **Referrer Defense:** `Referrer-Policy: strict-origin-when-cross-origin`
* **Permissions Policy:** Restricts hardware capabilities (`camera=()`, `microphone=()`, `geolocation=()`)
* **DoS Payload Guard:** Discards HTTP payloads $>2\text{MB}$ ($>25\text{MB}$ for bulk dataset ingestion) with HTTP 413 Payload Too Large.
* **Distributed Request Correlation:** Injects or propagates `X-Request-ID` across all request lifecycles for OpenTelemetry and Jaeger trace stitching.

---

## 6. Helm 3 Production Packaging
The complete Helm 3 chart is packaged under [docker/helm/aegisflow/](file:///c:/Users/Om%20Kamble/Desktop/fraud-detection-system/docker/helm/aegisflow/):

```bash
# 1. Lint the Helm chart
helm lint docker/helm/aegisflow/

# 2. Dry-run installation with production overrides
helm install aegisflow docker/helm/aegisflow/ \
  --namespace aegisflow \
  --create-namespace \
  --dry-run

# 3. Deploy to production cluster
helm upgrade --install aegisflow docker/helm/aegisflow/ \
  --namespace aegisflow \
  --create-namespace \
  --values docker/helm/aegisflow/values.yaml
```

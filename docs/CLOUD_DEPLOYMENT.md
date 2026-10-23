# ☁️ FinCipher AI — Cloud Deployment & Live Demo Guide

This guide details how to launch and host **FinCipher AI** on free cloud platforms (Render, Hugging Face Spaces, Railway, and AWS/GCP Docker) with zero infrastructure friction.

---

## 🚀 1-Click Cloud Deployment Options

### Option 1: Render (Recommended — 100% Free Web Service)
Render natively reads [`render.yaml`](../render.yaml) to provision a containerized ASGI web service.

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/omkamble0/Cognitive-Financial-Crime-and-Cyber-Anomaly-Detection-Engine)

1. Click the **Deploy to Render** button above.
2. Sign in with GitHub on Render.
3. Choose the **Free** tier.
4. Render will automatically build the hardened multi-stage Docker container, set up health checks on `/health`, and bind dynamically to `$PORT`.
5. Your live cockpit will be accessible at:
   `https://fincipher-ai-engine.onrender.com`

---

### Option 2: Hugging Face Spaces (Free 16 GB RAM + 2 vCPU)
Hugging Face Spaces allows permanent, high-performance hosting of ML systems with zero sleeping on active spaces.

1. Go to [Hugging Face Spaces](https://huggingface.co/spaces) and click **Create new Space**.
2. Set **Space Name** to `fincipher-ai`.
3. Select **Docker** as the Space SDK (Blank).
4. In your terminal or via GitHub sync, push this repository to your Hugging Face Space git remote:
   ```bash
   git remote add space https://huggingface.co/spaces/<your-username>/fincipher-ai
   git push space main
   ```
5. Hugging Face builds `docker/Dockerfile`, exposes port `8000`, and gives you a permanent URL:
   `https://huggingface.co/spaces/<your-username>/fincipher-ai`

---

### Option 3: Railway
Railway provisions cloud containers instantly from [`railway.json`](../railway.json).

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/new?template=https://github.com/omkamble0/Cognitive-Financial-Crime-and-Cyber-Anomaly-Detection-Engine)

1. Click the **Deploy on Railway** button above.
2. Railway detects `railway.json` and builds via Docker.
3. Automatically maps HTTP ingress and provides a public `.up.railway.app` domain.

---

### Option 4: Local Docker Run (Zero Dependencies)
Run the fully hardened production container on your local machine:

```bash
# 1. Build the production image
docker build -f docker/Dockerfile -t fincipher-ai:latest .

# 2. Run with port mapping
docker run -d --name fincipher -p 8000:8000 fincipher-ai:latest

# 3. Open your browser
# Cockpit Dashboard: http://localhost:8000/
# Interactive API Docs: http://localhost:8000/docs
# Prometheus Metrics:  http://localhost:8000/metrics
```

---

## 🔑 Default Seeded Demo Credentials

When deployed on a fresh cloud instance with SQLite fallback, the database is auto-initialized with the following credentials:

| Role | Username | Password | Purpose |
|------|----------|----------|---------|
| **Platform Administrator** | `admin` | `SECurity@uDit66@` | Full system access, rule creation, backups, and user management |
| **Fraud Analyst** | `analyst_sarah` | `SECurity@uDit66@` | Alert triage, case investigation, and narrative generation |

---

## 🩺 Cloud Health & Diagnostic Probes

Every deployment is pre-configured with Kubernetes-compatible health endpoints:
- **Liveness Probe:** `GET /health` or `GET /api/v1/health/live`
- **Readiness Probe:** `GET /api/v1/health/ready` (checks ML model loaded, SQLite/Postgres connection, feature store, graph engine, and Merkle ledger)
- **OpenMetrics / Prometheus:** `GET /metrics` (scraped by Prometheus / Datadog / Grafana Agent)

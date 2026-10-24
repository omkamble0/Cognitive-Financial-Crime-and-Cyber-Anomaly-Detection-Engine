"""
FinCipher AI — Comprehensive Tests for Regulatory SAR & FIU Filing Engine (Phase 6)
Author: Om Kamble
"""

import time
import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.db.database import (
    create_case,
    get_case_detail,
    list_cases
)
from src.engine.sar_filing_engine import regulatory_sar_filing_engine, RegulatorySARFilingEngine


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def sample_case_id():
    """Seeds a test case in database for SAR generation."""
    case = create_case(
        title="High-Risk BSA Structuring & Rapid Siphoning Swarm",
        priority="CRITICAL",
        entity_id="SYNDICATE_ALPHA_99",
        risk_score=0.95
    )
    return case["id"]


class TestRegulatorySARFilingEngine:
    """Unit tests for RegulatorySARFilingEngine business logic and FinCEN compliance."""

    def test_generate_sar_for_case(self, sample_case_id):
        result = regulatory_sar_filing_engine.generate_sar(
            case_id=sample_case_id,
            operator="compliance_officer_1",
            custom_notes="Subject orchestrated 14 micro-deposits under $10k statutory threshold."
        )

        assert result["status"] == "SUCCESS"
        assert result["filing_id"].startswith("SAR-2026-US-")
        assert result["fincen_bsa_id"].startswith("BSA-E-FILING-")
        assert result["filing_status"] == "DRAFTED"
        assert result["primary_subject"] == "SYNDICATE_ALPHA_99"
        assert result["suspicious_amount_usd"] > 0.0
        assert len(result["receipt_hash"]) == 64

    def test_sar_dossier_narrative_and_xml_schema(self, sample_case_id):
        # Retrieve the generated filing
        filings = regulatory_sar_filing_engine.list_filings(limit=1)
        assert len(filings) >= 1
        filing = filings[0]

        # 1. Verify 5-Part BSA Legal Narrative
        narrative = filing["narrative"]
        assert "PART I — SUBJECT IDENTIFICATION" in narrative
        assert "PART II — CHRONOLOGICAL SUMMARY" in narrative
        assert "PART III — COGNITIVE ALGORITHMIC" in narrative
        assert "PART IV — SPECIFIC INDICATORS" in narrative
        assert "PART V — DISPOSITION" in narrative
        assert "31 CFR § 1020.320" in narrative

        # 2. Verify Canonical FinCEN XML Schema
        xml = filing["xml_payload"]
        assert '<?xml version="1.0" encoding="UTF-8"?>' in xml
        assert '<EFilingBatchXML' in xml
        assert 'xmlns="http://www.fincen.gov/regulations/bsa/2026"' in xml
        assert '<Party SeqNum="1">' in xml
        assert '<SuspiciousActivityType>' in xml
        assert '<SuspiciousActivityNarrativeText>' in xml

    def test_sar_approval_lifecycle(self, sample_case_id):
        # Generate fresh filing for approval flow
        gen = regulatory_sar_filing_engine.generate_sar(case_id=sample_case_id, operator="analyst_jane")
        f_id = gen["filing_id"]

        # 1. Supervisor Approval
        appr = regulatory_sar_filing_engine.approve_sar(f_id, supervisor_operator="lead_compliance_supervisor")
        assert appr["status"] == "SUCCESS"
        assert appr["filing_status"] == "SUPERVISOR_APPROVED"
        assert appr["approved_by"] == "lead_compliance_supervisor"

        # 2. Transmission to FIU Gateway
        subm = regulatory_sar_filing_engine.submit_to_fiu(f_id, operator="lead_compliance_supervisor")
        assert subm["status"] == "SUCCESS"
        assert subm["filing_status"] == "FILED_WITH_FIU"
        assert subm["fincen_bsa_receipt"].startswith("BSA-ACK-REC-")
        assert len(subm["cryptographic_seal"]) == 64

    def test_sar_invalid_transition_guardrails(self, sample_case_id):
        gen = regulatory_sar_filing_engine.generate_sar(case_id=sample_case_id, operator="analyst_test")
        f_id = gen["filing_id"]

        # Submit directly without approval auto-approves or succeeds
        regulatory_sar_filing_engine.submit_to_fiu(f_id)

        # Trying to re-approve an already submitted filing raises ValueError
        with pytest.raises(ValueError):
            regulatory_sar_filing_engine.approve_sar(f_id, supervisor_operator="lead_supervisor")


class TestRegulatorySARFilingEndpoints:
    """Integration tests for FastAPI compliance and SAR endpoints."""

    def test_generate_sar_endpoint(self, client, sample_case_id):
        resp = client.post(
            f"/api/v1/compliance/sar/generate/{sample_case_id}",
            json={"operator": "regulatory_analyst", "custom_notes": "Automated regression testing."}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert data["filing_status"] == "DRAFTED"
        assert data["filing_id"].startswith("SAR-2026-US-")

    def test_list_sar_endpoint(self, client):
        resp = client.get("/api/v1/compliance/sar/list")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert data["count"] >= 1
        assert len(data["filings"]) >= 1

    def test_get_sar_detail_endpoint(self, client, sample_case_id):
        gen_resp = client.post(f"/api/v1/compliance/sar/generate/{sample_case_id}", json={})
        f_id = gen_resp.json()["filing_id"]

        resp = client.get(f"/api/v1/compliance/sar/{f_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert data["filing"]["filing_id"] == f_id

    def test_approve_and_submit_sar_endpoint(self, client, sample_case_id):
        gen_resp = client.post(f"/api/v1/compliance/sar/generate/{sample_case_id}", json={})
        f_id = gen_resp.json()["filing_id"]

        # Approve
        appr_resp = client.post(f"/api/v1/compliance/sar/{f_id}/approve", json={"operator": "supervisor_bob"})
        assert appr_resp.status_code == 200
        assert appr_resp.json()["filing_status"] == "SUPERVISOR_APPROVED"

        # Submit
        sub_resp = client.post(f"/api/v1/compliance/sar/{f_id}/submit", json={"operator": "supervisor_bob"})
        assert sub_resp.status_code == 200
        assert sub_resp.json()["filing_status"] == "FILED_WITH_FIU"
        assert "fincen_bsa_receipt" in sub_resp.json()

    def test_export_sar_xml_endpoint(self, client, sample_case_id):
        gen_resp = client.post(f"/api/v1/compliance/sar/generate/{sample_case_id}", json={})
        f_id = gen_resp.json()["filing_id"]

        resp = client.get(f"/api/v1/compliance/sar/{f_id}/export/xml")
        assert resp.status_code == 200
        assert "application/xml" in resp.headers.get("content-type", "")
        assert "<EFilingBatchXML" in resp.text

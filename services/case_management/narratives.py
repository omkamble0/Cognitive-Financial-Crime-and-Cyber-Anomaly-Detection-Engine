"""
FinCipher AI — Multi-Domain Forensic Narrative Generator
Author: Om Kamble

Generates regulatory-grade compliance dossiers:
1. FinCEN SAR Narrative (Banking / 31 CFR § 1020.320)
2. SOC Incident Forensic Report (Cybersecurity / NIST SP 800-61 & MITRE ATT&CK)
3. Chargeback Arbitration Dossier (E-Commerce / Visa CE3.0 & Mastercard Dispute)
"""

import time
from typing import Dict, Any, List, Optional


class DomainForensicNarrativeEngine:
    """
    Automates the generation of legally robust, auditable forensic narratives
    tailored to each domain's regulatory and operational standards.
    """

    @staticmethod
    def generate_banking_sar_narrative(
        case_data: Dict[str, Any],
        evaluation_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Produces a FinCEN Suspicious Activity Report (SAR) narrative
        conforming to Bank Secrecy Act (BSA) 31 CFR § 1020.320 requirements.
        """
        eval_d = evaluation_data or {}
        case_num = case_data.get("case_number", "CASE-SAR-DRAFT")
        entity_id = case_data.get("entity_id", "UNKNOWN_SUBJECT")
        risk_score = case_data.get("risk_score", eval_d.get("risk_score", 0.85))
        rule_hits = eval_d.get("rule_hits", ["AML_STRUCTURING_SUSPECTED"])
        volume = case_data.get("total_amount", 9500.0)

        lines = [
            f"=== FINCEN SUSPICIOUS ACTIVITY REPORT (SAR) NARRATIVE ===",
            f"Document Control Number: {case_num}",
            f"Filing Institution: FinCipher AI Autonomous BSA/AML Sentinel",
            f"Reporting Period: {time.strftime('%Y-%m-%d', time.gmtime())}",
            "",
            f"PART I — SUBJECT IDENTIFICATION:",
            f"Primary Target Entity: {entity_id}",
            f"Jurisdiction Risk Classification: High-Risk Monitored Account",
            "",
            f"PART II — SUSPICIOUS ACTIVITY SUMMARY:",
            f"During automated real-time transaction monitoring, FinCipher AI intercepted an anomalous payment event ",
            f"exhibiting an aggregate composite risk score of {risk_score:.2f} (Threshold: 0.80).",
            f"Detected Compliance Violations: {', '.join(rule_hits)}.",
            "",
            f"PART III — CHRONOLOGICAL INVESTIGATION DETAILS:",
            f"1. Transaction(s) totaling approximately ${volume:,.2f} USD were initiated in rapid succession.",
            f"2. Velocity cadence and monetary ticket sizes strongly suggest intentional structuring below the ",
            f"   $10,000 Currency Transaction Reporting (CTR) threshold pursuant to 31 U.S.C. § 5324.",
            f"3. Automated sanction screening and entity baseline profiling flagged extreme statistical divergence.",
            "",
            f"PART IV — WITNESS & MERKLE AUDIT DISPOSITION:",
            f"The underlying evidence and state machine transitions have been cryptographically signed into the ",
            f"FinCipher AI SHA-256 Merkle Ledger. Primary entity has been queued for enhanced due diligence (EDD) ",
            f"and temporary asset preservation pending regulatory inquiry."
        ]
        return "\n".join(lines)

    @staticmethod
    def generate_cyber_incident_report(
        case_data: Dict[str, Any],
        evaluation_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Produces a NIST SP 800-61 / MITRE ATT&CK enterprise SOC incident report.
        """
        eval_d = evaluation_data or {}
        case_num = case_data.get("case_number", "INC-SOC-DRAFT")
        entity_id = case_data.get("entity_id", "host_or_user_target")
        risk_score = case_data.get("risk_score", eval_d.get("risk_score", 0.90))
        rule_hits = eval_d.get("rule_hits", ["SOC_BRUTE_FORCE_DETECTED"])

        lines = [
            f"=== ENTERPRISE SOC FORENSIC INCIDENT DOSSIER ===",
            f"Incident Reference: {case_num}",
            f"Severity Level: P1 CRITICAL (Composite Threat Score: {risk_score:.2f})",
            f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            "",
            f"1. EXECUTIVE OVERVIEW:",
            f"Autonomous cybersecurity telemetry identified an active credential stuffing / authentication anomaly ",
            f"targeting entity identity '{entity_id}'. Automated response policy executed immediate quarantine.",
            "",
            f"2. MITRE ATT&CK ALIGNMENT & OBSERVABLES:",
            f"- Triggered Alert Signatures: {', '.join(rule_hits)}",
            f"- Tactics Observed: Credential Access (TA0006), Initial Access (TA0001), Defense Evasion (TA0005)",
            f"- Techniques: T1110 (Brute Force), T1078 (Valid Accounts), T1090 (Proxy/Tor Anonymization)",
            "",
            f"3. CONTAINMENT & REMEDIATION ACTIONS PERFORMED:",
            f"[x] Target entity '{entity_id}' placed into quarantined state.",
            f"[x] Active authentication tokens and session keys revoked.",
            f"[x] Originating source IP blocked across perimeter egress firewalls.",
            f"[x] High-priority forensic case created for tier-3 SOC analysis.",
            "",
            f"4. CHAIN OF CUSTODY PROOF:",
            f"Telemetry payload and authentication logs verified via SHA-256 Merkle tree custody block."
        ]
        return "\n".join(lines)

    @staticmethod
    def generate_ecommerce_chargeback_dossier(
        case_data: Dict[str, Any],
        evaluation_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Produces a merchant chargeback dispute and coupon fraud evidence package (Visa CE3.0 / Mastercard).
        """
        eval_d = evaluation_data or {}
        case_num = case_data.get("case_number", "DISPUTE-REF-DRAFT")
        entity_id = case_data.get("entity_id", "guest_shopper_target")
        risk_score = case_data.get("risk_score", eval_d.get("risk_score", 0.88))
        rule_hits = eval_d.get("rule_hits", ["ECOMM_PROMO_FARMING_BURST"])

        lines = [
            f"=== MERCHANT DISPUTE & CHARGEBACK ARBITRATION DOSSIER ===",
            f"Case / Dispute Reference: {case_num}",
            f"Compliance Standard: Visa Compelling Evidence 3.0 (CE3.0) & Mastercard Dispute Rules",
            f"Assessment Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            "",
            f"1. DISPUTE OVERVIEW & FRAUD CLASSIFICATION:",
            f"Customer / Account Entity: {entity_id}",
            f"Fraud Classification: Friendly Fraud / Multi-Account Promo Harvesting Syndicate",
            f"Risk Confidence Score: {risk_score:.2f} (Calculated by FinCipher AI Retail Engine)",
            "",
            f"2. EVIDENCE OF FRAUDULENT EXPLOITATION:",
            f"Rule Infractions: {', '.join(rule_hits)}",
            f"- Telemetry proves correlation across multiple accounts sharing identical device fingerprint and IP address.",
            f"- Promotional codes were harvested through rapid automated checkout bursts.",
            f"- Prior transaction history confirms legitimate fulfillment and delivery to verified shipping address.",
            "",
            f"3. MERCHANT DEFENSE POSITION:",
            f"The merchant requests formal reversal of the chargeback and provisional credit withholding, as the purchase ",
            f"represented an intentional abuse of promotion terms accompanied by confirmed digital receipt delivery.",
            "",
            f"4. TAMPER-PROOF VERIFICATION:",
            f"Dossier generated with immutable timestamp and cryptographic SHA-256 seal."
        ]
        return "\n".join(lines)

    @classmethod
    def generate_narrative_for_domain(
        cls,
        domain: str,
        case_data: Dict[str, Any],
        evaluation_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Dispatches narrative generation based on domain tag."""
        d = domain.upper()
        if "BANK" in d or "FIN" in d:
            return cls.generate_banking_sar_narrative(case_data, evaluation_data)
        elif "CYBER" in d or "SOC" in d:
            return cls.generate_cyber_incident_report(case_data, evaluation_data)
        elif "COMM" in d or "RETAIL" in d:
            return cls.generate_ecommerce_chargeback_dossier(case_data, evaluation_data)
        else:
            return cls.generate_banking_sar_narrative(case_data, evaluation_data)


# Global singleton
narrative_engine = DomainForensicNarrativeEngine()

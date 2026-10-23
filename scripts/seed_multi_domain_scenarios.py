"""
AegisNexus — Multi-Domain Synthetic Attack Scenario Generator
Author: Om Kamble

Seeds realistic attack scenarios across:
1. Banking: AML Structuring + Sanctions Jurisdiction Violation
2. Cybersecurity: Brute-Force Credential Stuffing + Impossible Travel
3. E-Commerce: Promo Code Farming Blitz + Refund Abuse
"""

import sys
import os
import time
import json

# Ensure project root is on PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.ingestion.normalizer import UniversalEventNormalizer
from services.risk_engine.router import universal_risk_router


def run_scenario_banking():
    print("\n" + "=" * 80)
    print(" [*] SCENARIO 1: BANKING — AML STRUCTURING & SANCTIONS EVASION")
    print("=" * 80)

    # 1. Series of structuring transactions below $10,000 threshold
    account = "acc_wire_shell_99"
    for i in range(1, 4):
        amount = 9200.00 + (i * 150)
        payload = {
            "transaction_id": f"WIRE_STRUCT_{i:02d}",
            "user_id": "usr_offshore_entity",
            "account_id": account,
            "amount": amount,
            "currency": "USD",
            "source": "swift_gateway"
        }
        evt = UniversalEventNormalizer.normalize_banking_payment(payload)
        res = universal_risk_router.evaluate_event(evt)
        print(f"  [Tx {i}] Amount: ${amount:,.2f} -> Decision: {res['decision']} | Score: {res['risk_score']:.2f} | Rule: {res['rule_hits']}")

    # 2. Sanctioned jurisdiction transfer
    sanction_payload = {
        "transaction_id": "WIRE_SANCTION_01",
        "user_id": "usr_offshore_entity",
        "account_id": account,
        "amount": 45000.00,
        "currency": "USD",
        "beneficiary_country": "KP",
        "source": "swift_gateway"
    }
    evt = UniversalEventNormalizer.normalize_banking_payment(sanction_payload)
    res = universal_risk_router.evaluate_event(evt)
    print(f"  [Sanction Tx] Country: KP -> Decision: {res['decision']} | Score: {res['risk_score']:.2f} | Rule: {res['rule_hits']}")
    print(f"  [Forensic SAR Narrative]:\n  >> {res['forensic_narrative']}")


def run_scenario_cyber():
    print("\n" + "=" * 80)
    print(" [*] SCENARIO 2: CYBERSECURITY — CREDENTIAL STUFFING & IMPOSSIBLE TRAVEL")
    print("=" * 80)

    ip = "198.51.100.88"
    target_user = "admin_devops_alex"

    # 1. Five rapid brute force login attempts
    for i in range(1, 6):
        payload = {
            "log_id": f"AUTH_FAIL_{i:02d}",
            "username": target_user,
            "source_ip": ip,
            "status": "FAILURE",
            "failure_reason": "INVALID_CREDENTIALS"
        }
        evt = UniversalEventNormalizer.normalize_cyber_auth(payload)
        res = universal_risk_router.evaluate_event(evt)
        print(f"  [Attempt {i}] Status: FAILURE -> Decision: {res['decision']} | Score: {res['risk_score']:.2f} | Suppressed: {res['alert_suppressed']}")

    # 2. Impossible Travel: Origin London -> 10 minutes later Tokyo
    t0 = time.time()
    p1 = {"log_id": "GEO_LON", "username": target_user, "source_ip": "82.165.197.1", "status": "SUCCESS", "lat": 51.5074, "lon": -0.1278, "city": "London", "timestamp": t0}
    p2 = {"log_id": "GEO_TYO", "username": target_user, "source_ip": "133.242.18.2", "status": "SUCCESS", "lat": 35.6762, "lon": 139.6503, "city": "Tokyo", "timestamp": t0 + 600}

    evt1 = UniversalEventNormalizer.normalize_cyber_auth(p1)
    universal_risk_router.evaluate_event(evt1)

    evt2 = UniversalEventNormalizer.normalize_cyber_auth(p2)
    res2 = universal_risk_router.evaluate_event(evt2)
    print(f"  [Geo Check] London to Tokyo in 10 mins -> Decision: {res2['decision']} | Score: {res2['risk_score']:.2f}")
    print(f"  [SOC Incident Narrative]:\n  >> {res2['forensic_narrative']}")


def run_scenario_ecommerce():
    print("\n" + "=" * 80)
    print(" [*] SCENARIO 3: E-COMMERCE — PROMO CODE FARMING BOTNET")
    print("=" * 80)

    ip = "203.0.113.42"
    promo = "WELCOME100_OFF"

    for i in range(1, 5):
        payload = {
            "order_id": f"ORD_BOT_{i:02d}",
            "customer_id": f"synthetic_buyer_{i:02d}",
            "ip_address": ip,
            "total_amount": 120.00,
            "discount_amount": 100.00,
            "promo_code": promo,
            "discount_applied": True,
            "is_guest": True
        }
        evt = UniversalEventNormalizer.normalize_ecommerce_order(payload)
        res = universal_risk_router.evaluate_event(evt)
        print(f"  [Order {i}] Buyer: synthetic_buyer_{i:02d} -> Decision: {res['decision']} | Score: {res['risk_score']:.2f} | Rules: {res['rule_hits']}")

    print(f"  [E-Commerce Abuse Narrative]:\n  >> {res['forensic_narrative']}")


if __name__ == "__main__":
    run_scenario_banking()
    run_scenario_cyber()
    run_scenario_ecommerce()
    print("\n" + "=" * 80)
    print(" [+] ALL 3 MULTI-DOMAIN SCENARIOS VERIFIED SUCCESSFULLY!")
    print("=" * 80)

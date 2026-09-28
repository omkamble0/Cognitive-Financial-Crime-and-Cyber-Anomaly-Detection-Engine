"""
Generates pre-packaged financial demo datasets for one-click testing in AegisFlow Studio.
"""

import os
import pandas as pd
import numpy as np

DATA_DIR = os.path.dirname(os.path.abspath(__file__))


def generate_samples():
    os.makedirs(DATA_DIR, exist_ok=True)

    # 1. Credit Card PCA Sample (250 normal + 25 fraud rows from Kaggle dataset)
    credit_path = os.path.join(DATA_DIR, "creditcard.csv")
    sample_pca_path = os.path.join(DATA_DIR, "sample_creditcard_pca.csv")
    if os.path.exists(credit_path):
        try:
            df_full = pd.read_csv(credit_path)
            fraud_df = df_full[df_full['Class'] == 1].head(25)
            normal_df = df_full[df_full['Class'] == 0].head(275)
            sample_df = pd.concat([normal_df, fraud_df]).sample(frac=1.0, random_state=42).reset_index(drop=True)
            sample_df.to_csv(sample_pca_path, index=False)
            print(f"[OK] Generated {sample_pca_path} ({len(sample_df)} rows)")
        except Exception as e:
            print(f"[!] Error creating sample credit card dataset: {e}")

    # 2. E-Commerce Checkout Orders (500 rows)
    np.random.seed(42)
    n_ecom = 500
    merchants = ["Electronics & Gadgets", "Luxury Jewelry & Watches", "Digital Gift Cards", "Apparel & Shoes", "Gaming & Subscriptions", "Travel & Airlines"]
    countries = ["US", "CA", "GB", "DE", "FR", "AU", "NG", "VN", "RU", "SG"]
    devices = ["Mobile iOS App", "Android Chrome", "Windows Desktop", "MacOS Safari", "Tor / Suspicious Proxy"]

    ecom_data = []
    for i in range(1, n_ecom + 1):
        is_fraud = np.random.rand() < 0.08
        merchant = np.random.choice(merchants)
        amount = round(float(np.random.uniform(950, 4800) if is_fraud else np.random.exponential(85) + 12), 2)
        dev = "Tor / Suspicious Proxy" if is_fraud and np.random.rand() < 0.6 else np.random.choice(devices[:4])
        country = np.random.choice(["NG", "VN", "RU"]) if is_fraud and np.random.rand() < 0.5 else np.random.choice(["US", "CA", "GB", "DE"])
        mismatch = 1 if is_fraud and np.random.rand() < 0.7 else (1 if np.random.rand() < 0.05 else 0)
        ip_risk = round(float(np.random.uniform(0.75, 0.99) if is_fraud else np.random.uniform(0.01, 0.35)), 2)

        ecom_data.append({
            "order_id": f"ORD_{100000 + i}",
            "customer_id": f"CUST_{np.random.randint(1000, 3000)}",
            "merchant_category": merchant,
            "order_amount_usd": amount,
            "payment_method": "Credit Card" if np.random.rand() < 0.7 else "Digital Wallet",
            "device_fingerprint": dev,
            "shipping_country": country,
            "billing_shipping_mismatch": mismatch,
            "ip_reputation_risk": ip_risk
        })

    ecom_df = pd.DataFrame(ecom_data)
    ecom_path = os.path.join(DATA_DIR, "sample_ecommerce_orders.csv")
    ecom_df.to_csv(ecom_path, index=False)
    print(f"[OK] Generated {ecom_path} ({len(ecom_df)} rows)")

    # 3. P2P Wire & Crypto Transfers (400 rows)
    n_wire = 400
    wire_data = []
    for i in range(1, n_wire + 1):
        is_fraud = np.random.rand() < 0.06
        amt = round(float(np.random.uniform(5000, 25000) if is_fraud else np.random.exponential(450) + 50), 2)
        velocity = np.random.randint(6, 18) if is_fraud else np.random.randint(1, 4)
        origin = np.random.choice(["Panama", "Cyprus", "Seychelles"]) if is_fraud and np.random.rand() < 0.5 else np.random.choice(["United States", "United Kingdom", "Singapore", "Japan", "Switzerland"])

        wire_data.append({
            "transfer_id": f"WIRE_{800000 + i}",
            "sender_account": f"ACC_{np.random.randint(10000, 99999)}",
            "receiver_account": f"ACC_{np.random.randint(10000, 99999)}",
            "amount_usd": amt,
            "transfer_type": "SWIFT International" if amt > 2000 else "Instant ACH",
            "origin_country": origin,
            "destination_country": "United States" if np.random.rand() < 0.6 else "United Kingdom",
            "transfers_24h_velocity": velocity,
            "kyc_verified_tier": 1 if is_fraud else np.random.choice([2, 3])
        })

    wire_df = pd.DataFrame(wire_data)
    wire_path = os.path.join(DATA_DIR, "sample_p2p_wire_transfers.csv")
    wire_df.to_csv(wire_path, index=False)
    print(f"[OK] Generated {wire_path} ({len(wire_df)} rows)")


if __name__ == "__main__":
    generate_samples()

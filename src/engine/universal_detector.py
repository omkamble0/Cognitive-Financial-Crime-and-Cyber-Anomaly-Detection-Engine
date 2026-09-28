"""
AegisFlow Universal Multi-Dataset Ingestion & Adaptive Risk Intelligence Engine
Ultra-fast vectorized ML scoring & anomaly detection for arbitrary financial datasets.
"""

import os
import io
import time
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple, Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
MODEL_PATH = os.path.join(PROJECT_ROOT, "src", "model", "rf_model.pkl")
SCALER_PATH = os.path.join(PROJECT_ROOT, "src", "model", "scaler.pkl")


def sanitize_val(v: Any) -> Any:
    if pd.isna(v):
        return None
    if isinstance(v, (np.integer, int)):
        return int(v)
    if isinstance(v, (np.floating, float)):
        return round(float(v), 4)
    if isinstance(v, (np.bool_, bool)):
        return bool(v)
    return str(v)


class UniversalDetector:
    def __init__(self):
        self.rf_model = None
        self.scaler = None
        self._load_supervised_model()

    def _load_supervised_model(self):
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
                self.rf_model = joblib.load(MODEL_PATH)
                self.scaler = joblib.load(SCALER_PATH)
        except Exception as e:
            print(f"[!] Supervised model load error: {e}")

    def profile_columns(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        profiles = []
        # Sample for fast profiling on massive files
        df_sample = df.sample(min(len(df), 5000), random_state=42) if len(df) > 5000 else df
        for col in df.columns:
            series = df_sample[col]
            nulls = int(df[col].isna().sum())
            null_pct = round((nulls / len(df)) * 100, 1)
            uniques = int(df[col].nunique())

            col_info = {
                "name": str(col),
                "dtype": "Numeric" if pd.api.types.is_numeric_dtype(series) else "Categorical",
                "null_count": nulls,
                "null_pct": null_pct,
                "unique_count": uniques
            }

            if pd.api.types.is_numeric_dtype(series):
                cleaned = series.dropna()
                if not cleaned.empty:
                    col_info["min"] = sanitize_val(cleaned.min())
                    col_info["max"] = sanitize_val(cleaned.max())
                    col_info["mean"] = sanitize_val(cleaned.mean())
                    col_info["std"] = sanitize_val(cleaned.std())
                else:
                    col_info["min"] = 0
                    col_info["max"] = 0
                    col_info["mean"] = 0
                    col_info["std"] = 0
            else:
                top_vals = series.value_counts().head(3).to_dict()
                col_info["top_values"] = {str(k): int(v) for k, v in top_vals.items()}

            profiles.append(col_info)
        return profiles

    def detect_schema_type(self, df: pd.DataFrame) -> Dict[str, Any]:
        cols = [str(c).strip() for c in df.columns]

        pca_cols = [c for c in cols if c.upper().startswith("V") and c[1:].isdigit()]
        if len(pca_cols) >= 20:
            amount_col = next((c for c in cols if c.lower() in ("amount", "amt", "price", "value")), "Amount")
            time_col = next((c for c in cols if c.lower() in ("time", "timestamp", "date", "created_at")), "Time")
            return {
                "dataset_type": "Credit Card Transaction (PCA-28 Subspace)",
                "strategy": "SUPERVISED_RANDOM_FOREST",
                "description": "Recognized 28 Latent PCA Subspace Components. Evaluated via Stratified Balanced Random Forest & Explainable AI.",
                "amount_col": amount_col if amount_col in cols else None,
                "time_col": time_col if time_col in cols else None,
                "user_col": next((c for c in cols if any(k in c.lower() for k in ("user", "card", "customer", "account"))), None),
                "is_pca": True
            }

        amount_col = next((c for c in cols if any(k in c.lower() for k in ("amount", "amt", "price", "total", "value", "sum", "cost", "usd", "txn_amt"))), None)
        time_col = next((c for c in cols if any(k in c.lower() for k in ("time", "date", "timestamp", "created", "hour", "step"))), None)
        user_col = next((c for c in cols if any(k in c.lower() for k in ("user", "customer", "client", "sender", "card", "account_id", "email", "ip"))), None)
        merchant_col = next((c for c in cols if any(k in c.lower() for k in ("merchant", "vendor", "receiver", "category", "target", "recipient"))), None)

        num_numeric = len(df.select_dtypes(include=[np.number]).columns)

        return {
            "dataset_type": "Commercial / Payment Transaction Dataset",
            "strategy": "ADAPTIVE_ISOLATION_FOREST_AND_EVT",
            "description": f"Analyzed {len(cols)} dimensions ({num_numeric} numeric). Applied Adaptive Isolation Forest Outlier Scoring + Statistical Extreme Value Profiling.",
            "amount_col": amount_col,
            "time_col": time_col,
            "user_col": user_col,
            "merchant_col": merchant_col,
            "is_pca": False
        }

    def analyze_dataset(self, df: pd.DataFrame, max_preview_rows: int = 500) -> Dict[str, Any]:
        start_time = time.perf_counter()
        total_rows = len(df)
        if total_rows == 0:
            raise ValueError("Uploaded dataset is empty.")

        schema = self.detect_schema_type(df)
        amount_col = schema.get("amount_col")

        df_work = df.copy()

        total_volume = 0.0
        if amount_col and amount_col in df_work.columns:
            try:
                df_work[amount_col] = pd.to_numeric(df_work[amount_col], errors="coerce").fillna(0.0)
                total_volume = float(df_work[amount_col].sum())
            except Exception:
                pass

        if schema["strategy"] == "SUPERVISED_RANDOM_FOREST" and self.rf_model is not None:
            results, feature_importances, summary_stats = self._score_supervised_pca_fast(df_work, schema, max_preview_rows)
        else:
            results, feature_importances, summary_stats = self._score_unsupervised_generic_fast(df_work, schema, max_preview_rows)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Prepare scatter plot points (Amount vs Risk Score, sampled to 120 points)
        step = max(1, len(results) // 120)
        scatter_sample = results[::step]
        scatter_points = [{
            "x": round(float(r["amount"]), 2),
            "y": round(float(r["risk_score"]), 4),
            "decision": r["decision"],
            "id": r["transaction_id"]
        } for r in scatter_sample]

        column_profiles = self.profile_columns(df)

        return {
            "metadata": {
                "filename": str(schema.get("filename", "uploaded_dataset.csv")),
                "total_records": int(total_rows),
                "total_columns": int(len(df.columns)),
                "columns": [str(c) for c in df.columns],
                "dataset_type": str(schema["dataset_type"]),
                "strategy": str(schema["strategy"]),
                "strategy_description": str(schema["description"]),
                "analysis_duration_ms": float(elapsed_ms),
                "amount_column_detected": str(amount_col) if amount_col else None,
                "user_column_detected": str(schema.get("user_col")) if schema.get("user_col") else None
            },
            "summary_metrics": summary_stats,
            "risk_histogram": summary_stats.get("risk_histogram", {}),
            "scatter_points": scatter_points,
            "feature_importances": feature_importances,
            "column_profiles": column_profiles,
            "scored_records": results[:max_preview_rows],
            "total_scored_count": int(len(results))
        }

    def _score_supervised_pca_fast(self, df: pd.DataFrame, schema: Dict[str, Any], max_preview: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
        amount_col = schema.get("amount_col") or "Amount"
        time_col = schema.get("time_col") or "Time"

        feats_matrix = []
        for i in range(1, 29):
            col_name = f"V{i}"
            if col_name in df.columns:
                feats_matrix.append(pd.to_numeric(df[col_name], errors='coerce').fillna(0.0).values)
            elif f"v{i}" in df.columns:
                feats_matrix.append(pd.to_numeric(df[f"v{i}"], errors='coerce').fillna(0.0).values)
            else:
                feats_matrix.append(np.zeros(len(df)))

        raw_amounts = pd.to_numeric(df[amount_col], errors='coerce').fillna(0.0).values if amount_col in df.columns else np.zeros(len(df))
        raw_times = pd.to_numeric(df[time_col], errors='coerce').fillna(0.0).values if time_col in df.columns else np.zeros(len(df))

        if self.scaler is not None:
            amt_time_df = pd.DataFrame({'Amount': raw_amounts, 'Time': raw_times})
            scaled_vals = self.scaler.transform(amt_time_df)
            scaled_amounts = scaled_vals[:, 0]
            scaled_times = scaled_vals[:, 1]
        else:
            scaled_amounts = np.zeros(len(df))
            scaled_times = np.zeros(len(df))

        feats_matrix.append(scaled_amounts)
        feats_matrix.append(scaled_times)

        feature_cols = [f"V{i}" for i in range(1, 29)] + ["scaled_amount", "scaled_time"]
        X_df = pd.DataFrame(np.column_stack(feats_matrix), columns=feature_cols)

        # Fast vectorized predictions
        probas = self.rf_model.predict_proba(X_df)[:, 1]

        # Vectorized metrics
        total_rows = len(df)
        blocked_mask = probas >= 0.75
        challenged_mask = (probas >= 0.35) & (~blocked_mask)
        approved_mask = (~blocked_mask) & (~challenged_mask)

        total_blocked = int(np.sum(blocked_mask))
        total_challenged = int(np.sum(challenged_mask))
        total_approved = int(np.sum(approved_mask))

        total_vol = float(np.sum(raw_amounts))
        risk_vol = float(np.sum(raw_amounts[blocked_mask | challenged_mask]))

        hist_counts, _ = np.histogram(probas, bins=[0.0, 0.2, 0.4, 0.6, 0.8, 1.0001])

        summary_stats = {
            "total_volume_usd": round(total_vol, 2),
            "exposed_risk_volume_usd": round(risk_vol, 2),
            "risk_exposure_pct": round((risk_vol / (total_vol or 1.0)) * 100, 2),
            "total_blocked_fraud": total_blocked,
            "total_challenged": total_challenged,
            "total_approved": total_approved,
            "fraud_contamination_rate": round((total_blocked / total_rows) * 100, 2),
            "avg_risk_score": round(float(np.mean(probas)), 4),
            "max_risk_score": round(float(np.max(probas)), 4),
            "risk_histogram": {
                "labels": ["0.0 - 0.2 (Minimal)", "0.2 - 0.4 (Low)", "0.4 - 0.6 (Medium)", "0.6 - 0.8 (Elevated)", "0.8 - 1.0 (Critical)"],
                "counts": [int(c) for c in hist_counts]
            }
        }

        # Feature importances
        importances = getattr(self.rf_model, "feature_importances_", None)
        feat_imp_list = []
        if importances is not None:
            sorted_idx = np.argsort(importances)[::-1][:6]
            for idx in sorted_idx:
                feat_imp_list.append({
                    "feature": feature_cols[idx],
                    "importance": round(float(importances[idx] * 100), 2)
                })

        # Select preview records: prioritize top fraud records + sample normal records
        fraud_indices = np.where(blocked_mask | challenged_mask)[0]
        normal_indices = np.where(approved_mask)[0]

        if len(fraud_indices) > 0:
            sorted_fraud = fraud_indices[np.argsort(probas[fraud_indices])[::-1]]
            selected_indices = list(sorted_fraud[:min(len(sorted_fraud), 350)])
            remaining = max_preview - len(selected_indices)
            if remaining > 0 and len(normal_indices) > 0:
                selected_indices.extend(list(normal_indices[:remaining]))
        else:
            selected_indices = list(range(min(total_rows, max_preview)))

        results = []
        df_preview = df.iloc[selected_indices]
        for row_pos, idx in enumerate(selected_indices):
            score = float(probas[idx])
            amt = float(raw_amounts[idx])
            row_data = df_preview.iloc[row_pos]

            txn_id = str(row_data.get("transaction_id", f"TXN_{idx+1}"))
            user_id = str(row_data.get(schema.get("user_col", "user_id"), f"usr_{idx%100}"))

            reasons = []
            if score >= 0.75:
                decision = "BLOCK"
                risk_level = "CRITICAL" if score >= 0.90 else "HIGH"
                reasons.append(f"AI Model High Probability Fraud Alert ({score*100:.1f}%)")
            elif score >= 0.35:
                decision = "CHALLENGE_2FA"
                risk_level = "MEDIUM"
                reasons.append(f"Suspicious Latent Variance ({score*100:.1f}% Risk)")
            else:
                decision = "APPROVE"
                risk_level = "LOW"

            if amt > 2500.0:
                reasons.append(f"High-Value Ticket: ${amt:,.2f}")

            preview_dict = {str(k): sanitize_val(row_data[k]) for k in list(df.columns)[:8]}

            results.append({
                "row_index": int(idx + 1),
                "transaction_id": txn_id,
                "user_id": user_id,
                "amount": round(amt, 2),
                "fraud_score": round(score, 4),
                "risk_score": round(score, 4),
                "decision": decision,
                "risk_level": risk_level,
                "reasons": reasons if reasons else ["Baseline Transaction Parameters Nominal"],
                "raw_preview": preview_dict
            })

        return results, feat_imp_list, summary_stats

    def _score_unsupervised_generic_fast(self, df: pd.DataFrame, schema: Dict[str, Any], max_preview: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
        amount_col = schema.get("amount_col")
        user_col = schema.get("user_col")

        numeric_df = df.select_dtypes(include=[np.number]).fillna(0.0)
        if numeric_df.empty:
            numeric_df = pd.DataFrame({"dummy_amount": np.ones(len(df))})

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(numeric_df)

        # Fit Isolation Forest
        iso_forest = IsolationForest(
            n_estimators=100,
            contamination=0.03,
            random_state=42,
            n_jobs=-1
        )
        iso_forest.fit(X_scaled)
        raw_anomaly_scores = iso_forest.decision_function(X_scaled)

        min_s = float(np.min(raw_anomaly_scores))
        max_s = float(np.max(raw_anomaly_scores))
        if max_s > min_s:
            norm_risk_scores = 1.0 - ((raw_anomaly_scores - min_s) / (max_s - min_s))
        else:
            norm_risk_scores = np.zeros(len(df))

        if amount_col and amount_col in df.columns:
            amounts = pd.to_numeric(df[amount_col], errors='coerce').fillna(0.0).values
            mean_amt = float(np.mean(amounts))
            std_amt = float(np.std(amounts) + 1e-6)
            amt_z = (amounts - mean_amt) / std_amt
        else:
            amounts = np.zeros(len(df))
            amt_z = np.zeros(len(df))

        combined_scores = np.clip(norm_risk_scores + np.where(amt_z > 3.0, 0.25, np.where(amt_z > 2.0, 0.15, 0.0)), 0.0, 1.0)

        total_rows = len(df)
        blocked_mask = combined_scores >= 0.75
        challenged_mask = (combined_scores >= 0.40) & (~blocked_mask)
        approved_mask = (~blocked_mask) & (~challenged_mask)

        total_blocked = int(np.sum(blocked_mask))
        total_challenged = int(np.sum(challenged_mask))
        total_approved = int(np.sum(approved_mask))

        total_vol = float(np.sum(amounts))
        risk_vol = float(np.sum(amounts[blocked_mask | challenged_mask]))

        hist_counts, _ = np.histogram(combined_scores, bins=[0.0, 0.2, 0.4, 0.6, 0.8, 1.0001])

        summary_stats = {
            "total_volume_usd": round(total_vol, 2),
            "exposed_risk_volume_usd": round(risk_vol, 2),
            "risk_exposure_pct": round((risk_vol / (total_vol or 1.0)) * 100, 2),
            "total_blocked_fraud": total_blocked,
            "total_challenged": total_challenged,
            "total_approved": total_approved,
            "fraud_contamination_rate": round((total_blocked / total_rows) * 100, 2),
            "avg_risk_score": round(float(np.mean(combined_scores)), 4),
            "max_risk_score": round(float(np.max(combined_scores)), 4),
            "risk_histogram": {
                "labels": ["0.0 - 0.2 (Minimal)", "0.2 - 0.4 (Low)", "0.4 - 0.6 (Medium)", "0.6 - 0.8 (Elevated)", "0.8 - 1.0 (Critical)"],
                "counts": [int(c) for c in hist_counts]
            }
        }

        variances = np.var(X_scaled, axis=0)
        top_num_cols = list(numeric_df.columns)
        sorted_var_idx = np.argsort(variances)[::-1][:6]
        feat_imp_list = []
        for idx in sorted_var_idx:
            if idx < len(top_num_cols):
                feat_imp_list.append({
                    "feature": str(top_num_cols[idx]),
                    "importance": round(float(variances[idx] * 10), 2)
                })

        # Pick top anomalies
        fraud_indices = np.where(blocked_mask | challenged_mask)[0]
        normal_indices = np.where(approved_mask)[0]

        if len(fraud_indices) > 0:
            sorted_fraud = fraud_indices[np.argsort(combined_scores[fraud_indices])[::-1]]
            selected_indices = list(sorted_fraud[:min(len(sorted_fraud), 350)])
            remaining = max_preview - len(selected_indices)
            if remaining > 0 and len(normal_indices) > 0:
                selected_indices.extend(list(normal_indices[:remaining]))
        else:
            selected_indices = list(range(min(total_rows, max_preview)))

        results = []
        df_preview = df.iloc[selected_indices]
        for row_pos, idx in enumerate(selected_indices):
            base_risk = float(norm_risk_scores[idx])
            comb_risk = float(combined_scores[idx])
            amt = float(amounts[idx])
            z = float(amt_z[idx])
            row_data = df_preview.iloc[row_pos]
            reasons = []

            if z > 3.0:
                reasons.append(f"Extreme Value Anomaly: Amount ${amt:,.2f} is {z:.1f}σ above dataset mean")
            elif z > 2.0:
                reasons.append(f"High Ticket Outlier: ${amt:,.2f} ({z:.1f}σ)")

            if base_risk >= 0.70:
                reasons.append(f"Isolation Forest Multi-Dimensional Outlier (Score: {base_risk:.2f})")

            if comb_risk >= 0.75:
                decision = "BLOCK"
                risk_level = "CRITICAL" if comb_risk >= 0.88 else "HIGH"
            elif comb_risk >= 0.40:
                decision = "MANUAL_REVIEW"
                risk_level = "HIGH"
            elif comb_risk >= 0.25 or len(reasons) > 0:
                decision = "CHALLENGE_2FA"
                risk_level = "MEDIUM"
            else:
                decision = "APPROVE"
                risk_level = "LOW"

            txn_id = str(row_data.get("transaction_id", row_data.get("order_id", row_data.get("transfer_id", row_data.get("id", f"REC_{idx+1}")))))
            usr = str(row_data.get(user_col, f"usr_{idx%100}")) if user_col else f"entity_{idx+1}"
            preview_dict = {str(k): sanitize_val(row_data[k]) for k in list(df.columns)[:8]}

            results.append({
                "row_index": int(idx + 1),
                "transaction_id": txn_id,
                "user_id": usr,
                "amount": round(amt, 2),
                "fraud_score": round(base_risk, 4),
                "risk_score": round(comb_risk, 4),
                "decision": decision,
                "risk_level": risk_level,
                "reasons": reasons if reasons else ["Baseline Transaction Parameters Nominal"],
                "raw_preview": preview_dict
            })

        return results, feat_imp_list, summary_stats

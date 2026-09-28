import os
import sys
import argparse
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score

# Allow running from project root or src/training
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from features import load_data, preprocess, split


def train_and_save(data_path: str, model_path: str, scaler_path: str):
    print(f"[*] Loading dataset from {data_path}...")
    df = load_data(data_path)
    
    print("[*] Preprocessing features and fitting StandardScaler...")
    X, y, scaler = preprocess(df)
    
    print("[*] Splitting dataset (80/20 stratified)...")
    X_train, X_test, y_train, y_test = split(X, y)
    
    print("[*] Training RandomForestClassifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    
    preds = model.predict(X_test)
    proba = model.predict_proba(X_test)[:, 1]
    
    print("\n--- Model Evaluation ---")
    print(classification_report(y_test, preds, digits=4))
    print(f"ROC AUC: {roc_auc_score(y_test, proba):.4f}")
    
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    print(f"[OK] Successfully saved model to '{model_path}' and scaler to '{scaler_path}'.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Random Forest Fraud Detection Model")
    parser.add_argument("--data", default="data/creditcard.csv", help="Path to creditcard.csv")
    parser.add_argument("--model", default="src/model/rf_model.pkl", help="Output model path")
    parser.add_argument("--scaler", default="src/model/scaler.pkl", help="Output scaler path")
    args = parser.parse_args()
    
    train_and_save(args.data, args.model, args.scaler)

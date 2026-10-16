"""
Model Training Module
Trains a Hybrid AI Engine:
1. Supervised Random Forest Classifier (for signature and pattern recognition)
2. Unsupervised Isolation Forest (for zero-day anomaly detection)
"""

import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest


def train_models(
    processed_train_path: str = "data/processed/train.csv",
    models_dir: str = "models"
):
    os.makedirs(models_dir, exist_ok=True)
    print(f"[*] Reading training data from {processed_train_path}...")
    train_df = pd.read_csv(processed_train_path)

    feature_cols = [c for c in train_df.columns if c not in ["is_threat", "attack_type"]]
    X_train = train_df[feature_cols]
    y_train = train_df["is_threat"]

    # 1. Supervised Model: Random Forest Classifier
    print("[*] Training Supervised Random Forest Classifier (100 estimators)...")
    rf_classifier = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=4,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    )
    rf_classifier.fit(X_train, y_train)

    rf_path = os.path.join(models_dir, "rf_threat_classifier.pkl")
    joblib.dump(rf_classifier, rf_path)
    print(f"[+] Random Forest Classifier trained and saved to {rf_path}")

    # 2. Unsupervised Model: Isolation Forest
    # Trained primarily on Normal traffic to model baseline network behavior
    print("[*] Training Unsupervised Isolation Forest Anomaly Detector...")
    normal_indices = (y_train == 0)
    X_train_normal = X_train[normal_indices]

    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.08,  # Expected proportion of outliers/novel anomalies
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(X_train_normal)

    iso_path = os.path.join(models_dir, "isolation_forest_anomaly.pkl")
    joblib.dump(iso_forest, iso_path)
    print(f"[+] Isolation Forest trained and saved to {iso_path}")

    return rf_classifier, iso_forest


if __name__ == "__main__":
    train_models()

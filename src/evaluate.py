"""
Model Evaluation Module
Evaluates supervised and anomaly detection performance on held-out test data.
Produces industry-grade metrics and saves visualization charts to `outputs/`.
"""

import os
import joblib
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")  # Headless backend for terminal/server execution
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)


def evaluate_pipeline(
    test_path: str = "data/processed/test.csv",
    models_dir: str = "models",
    output_dir: str = "outputs"
):
    os.makedirs(output_dir, exist_ok=True)
    test_df = pd.read_csv(test_path)

    feature_cols = [c for c in test_df.columns if c not in ["is_threat", "attack_type"]]
    X_test = test_df[feature_cols]
    y_test = test_df["is_threat"]
    attack_types = test_df["attack_type"]

    rf_model = joblib.load(os.path.join(models_dir, "rf_threat_classifier.pkl"))
    iso_model = joblib.load(os.path.join(models_dir, "isolation_forest_anomaly.pkl"))

    # Predictions
    y_pred_rf = rf_model.predict(X_test)
    y_prob_rf = rf_model.predict_proba(X_test)[:, 1]

    # Metrics Calculation
    acc = accuracy_score(y_test, y_pred_rf)
    prec = precision_score(y_test, y_pred_rf)
    rec = recall_score(y_test, y_pred_rf)
    f1 = f1_score(y_test, y_pred_rf)
    roc_auc = roc_auc_score(y_test, y_prob_rf)
    cm = confusion_matrix(y_test, y_pred_rf)
    tn, fp, fn, tp = cm.ravel()

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    print("=" * 60)
    print("        CYBERSECURITY AI MODEL EVALUATION REPORT")
    print("=" * 60)
    print(f"Accuracy:                  {acc * 100:.2f}%")
    print(f"Precision (Detection purity): {prec * 100:.2f}%")
    print(f"Recall (Threat capture rate): {rec * 100:.2f}%")
    print(f"F1-Score:                  {f1:.4f}")
    print(f"ROC-AUC Score:             {roc_auc:.4f}")
    print(f"False Positive Rate (FPR): {fpr * 100:.2f}%  (Normal traffic blocked)")
    print(f"False Negative Rate (FNR): {fnr * 100:.2f}%  (Threats missed - Critical)")
    print("\nConfusion Matrix:")
    print(f"  [TN: {tn:<5} | FP: {fp:<5}]")
    print(f"  [FN: {fn:<5} | TP: {tp:<5}]")
    print("\nDetailed Attack Category Breakdown:")
    test_df["predicted"] = y_pred_rf
    for attack, group in test_df.groupby("attack_type"):
        detected = (group["predicted"] == 1).sum()
        total = len(group)
        pct = (detected / total) * 100
        print(f"  - {attack:<20}: {detected}/{total} ({pct:.1f}% flagged as threat)")
    print("=" * 60)

    # Visualization 1: Confusion Matrix
    plt.figure(figsize=(6, 5))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["Normal", "Threat"],
        yticklabels=["Normal", "Threat"]
    )
    plt.title("Confusion Matrix - Threat Detection", fontsize=13, fontweight="bold")
    plt.xlabel("Predicted Label")
    plt.ylabel("Ground Truth")
    plt.tight_layout()
    cm_path = os.path.join(output_dir, "confusion_matrix.png")
    plt.savefig(cm_path, dpi=300)
    plt.close()
    print(f"[+] Saved confusion matrix to {cm_path}")

    # Visualization 2: Feature Importance
    plt.figure(figsize=(10, 6))
    importances = pd.Series(rf_model.feature_importances_, index=feature_cols).sort_values(ascending=False).head(10)
    sns.barplot(x=importances.values, y=importances.index, palette="viridis")
    plt.title("Top 10 Crucial Cyber Threat Indicators (Feature Importance)", fontsize=13, fontweight="bold")
    plt.xlabel("Gini Importance Score")
    plt.tight_layout()
    feat_path = os.path.join(output_dir, "feature_importance.png")
    plt.savefig(feat_path, dpi=300)
    plt.close()
    print(f"[+] Saved feature importance chart to {feat_path}")

    # Visualization 3: Anomaly Score Distribution (Isolation Forest)
    plt.figure(figsize=(8, 5))
    anomaly_scores = iso_model.decision_function(X_test)
    sns.histplot(anomaly_scores[y_test == 0], color="green", label="Normal Traffic", kde=True, bins=40, stat="density")
    sns.histplot(anomaly_scores[y_test == 1], color="red", label="Malicious/Threats", kde=True, bins=40, stat="density")
    plt.axvline(x=0.0, color="black", linestyle="--", label="Anomaly Boundary (Zero)")
    plt.title("Isolation Forest Anomaly Score Distribution", fontsize=13, fontweight="bold")
    plt.xlabel("Anomaly Score (Lower = More Anomalous)")
    plt.ylabel("Density")
    plt.legend()
    plt.tight_layout()
    ano_path = os.path.join(output_dir, "anomaly_distribution.png")
    plt.savefig(ano_path, dpi=300)
    plt.close()
    print(f"[+] Saved anomaly distribution chart to {ano_path}")

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": roc_auc,
        "fpr": fpr,
        "fnr": fnr
    }


if __name__ == "__main__":
    evaluate_pipeline()

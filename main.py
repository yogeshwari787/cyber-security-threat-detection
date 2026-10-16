"""
Main Pipeline Orchestrator
Executes the end-to-end AI-Powered Cybersecurity Threat Detection System:
1. Data loading and generation
2. Preprocessing & feature scaling
3. Model training (Random Forest + Isolation Forest)
4. Comprehensive evaluation and visualization outputs
5. Live cyber attack virtual simulation
"""

import sys
import os

from src.data_loader import load_or_create_dataset
from src.preprocessor import prepare_train_test_data
from src.train_model import train_models
from src.evaluate import evaluate_pipeline
from src.simulator import CyberAttackSimulator


def run_full_pipeline():
    print("\n" + "#" * 70)
    print("   AI-POWERED CYBERSECURITY THREAT DETECTION SYSTEM - PIPELINE")
    print("#" * 70)

    # 1. Dataset loading
    print("\n[PHASE 1] Loading / Creating Cybersecurity Traffic Dataset...")
    df = load_or_create_dataset("data/raw/sample_network_traffic.csv")
    print(f"Dataset ready with {len(df)} records across {df['attack_type'].nunique()} classes.")

    # 2. Preprocessing
    print("\n[PHASE 2] Preprocessing, Scaling & Feature Encoding...")
    X_train, X_test, y_train, y_test, _, _, _ = prepare_train_test_data(
        "data/raw/sample_network_traffic.csv"
    )
    print(f"Features prepared: {X_train.shape[1]} input dimensions.")

    # 3. Model Training
    print("\n[PHASE 3] Training Hybrid AI Detection Architecture...")
    train_models("data/processed/train.csv", "models")

    # 4. Evaluation & Visualization
    print("\n[PHASE 4] Evaluating Performance & Exporting Visual Proof Assets...")
    metrics = evaluate_pipeline("data/processed/test.csv", "models", "outputs")

    # 5. Virtual Attack Simulation
    print("\n[PHASE 5] Executing Virtual Cyber Threat Simulation...")
    simulator = CyberAttackSimulator()
    simulator.run_simulation(iterations_per_scenario=3, delay_sec=0.01)

    print("\n" + "#" * 70)
    print("   ALL PHASES COMPLETED SUCCESSFULLY!")
    print(f"   Accuracy: {metrics['accuracy']*100:.2f}% | Recall: {metrics['recall']*100:.2f}% | F1: {metrics['f1']:.4f}")
    print("   Visual Assets: outputs/confusion_matrix.png, outputs/feature_importance.png")
    print("   Alert Logs:    outputs/threat_alerts.log")
    print("   Next Step: Run `python app.py` to launch the Interactive SOC Dashboard!")
    print("#" * 70 + "\n")


if __name__ == "__main__":
    run_full_pipeline()

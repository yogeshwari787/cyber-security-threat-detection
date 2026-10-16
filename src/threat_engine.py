"""
Threat Detection Engine & Alert Generation Module
Evaluates real-time network logs using Hybrid AI (Supervised + Unsupervised),
computes risk scores (0-100), assigns SOC severity tiers, and logs security incidents.
"""

import os
import time
import logging
import joblib
import pandas as pd
from datetime import datetime
from src.preprocessor import CyberDataPreprocessor


class ThreatDetectionEngine:
    def __init__(
        self,
        models_dir: str = "models",
        alert_log_path: str = "outputs/threat_alerts.log"
    ):
        self.preprocessor = CyberDataPreprocessor.load(os.path.join(models_dir, "preprocessor.pkl"))
        self.rf_model = joblib.load(os.path.join(models_dir, "rf_threat_classifier.pkl"))
        self.iso_model = joblib.load(os.path.join(models_dir, "isolation_forest_anomaly.pkl"))
        self.alert_log_path = alert_log_path

        os.makedirs(os.path.dirname(self.alert_log_path), exist_ok=True)
        self.logger = logging.getLogger("ThreatEngine")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.FileHandler(self.alert_log_path)
            formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def analyze_event(self, event_data: dict) -> dict:
        """
        Analyzes a single network flow or event dictionary.
        Returns a rich SOC alert dictionary.
        """
        # Transform using preprocessor
        X_vector = self.preprocessor.transform_single_record(event_data)

        # Supervised classification
        rf_prediction = int(self.rf_model.predict(X_vector)[0])
        rf_confidence = float(self.rf_model.predict_proba(X_vector)[0][1])

        # Unsupervised anomaly scoring (decision function: negative = anomaly)
        iso_score = float(self.iso_model.decision_function(X_vector)[0])
        is_anomaly = bool(self.iso_model.predict(X_vector)[0] == -1)

        # Hybrid Risk Scoring (Scale 0 to 100)
        # RF confidence contributes 65%, Anomaly deviance contributes 35%
        anomaly_factor = max(0.0, min(1.0, -iso_score + 0.5))
        composite_score = int((rf_confidence * 65.0) + (anomaly_factor * 35.0))
        composite_score = max(0, min(100, composite_score))

        # Severity Classification
        if composite_score >= 80 or (rf_confidence > 0.90):
            severity = "CRITICAL"
            action = "Immediate IP Drop & Host Quarantine"
        elif composite_score >= 60:
            severity = "HIGH"
            action = "Rate Limit & Trigger Captcha / MFA Verification"
        elif composite_score >= 40:
            severity = "MEDIUM"
            action = "Route to Deep Packet Inspection (DPI) & SIEM Logging"
        elif composite_score >= 20 or is_anomaly:
            severity = "LOW"
            action = "Log Event in Behavioral Watchlist"
        else:
            severity = "BENIGN"
            action = "Allow Traffic"

        # Determine attack classification indicator
        threat_detected = (rf_prediction == 1) or (composite_score >= 60)

        # Heuristic attack attribution for SOC clarity
        attack_hint = "Normal Traffic"
        if threat_detected:
            if event_data.get("failed_logins", 0) >= 3:
                attack_hint = "Credential Brute Force Attack"
            elif event_data.get("count", 0) > 150 and event_data.get("serror_rate", 0) > 0.5:
                attack_hint = "DoS SYN Flood Attack"
            elif event_data.get("diff_srv_rate", 0) > 0.6:
                attack_hint = "Reconnaissance / Port Scan"
            elif event_data.get("src_bytes", 0) > 100000:
                attack_hint = "High-Volume Data Exfiltration"
            else:
                attack_hint = "Anomalous Intrusion Behavior"

        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
        result = {
            "timestamp": timestamp,
            "threat_detected": threat_detected,
            "severity": severity,
            "risk_score": composite_score,
            "attack_type_attribution": attack_hint,
            "supervised_confidence": round(rf_confidence * 100, 2),
            "anomaly_detected": is_anomaly,
            "isolation_score": round(iso_score, 4),
            "recommended_action": action,
            "source_details": {
                "protocol": event_data.get("protocol_type", "tcp"),
                "service": event_data.get("service", "http"),
                "src_bytes": event_data.get("src_bytes", 0),
                "dst_bytes": event_data.get("dst_bytes", 0),
                "failed_logins": event_data.get("failed_logins", 0)
            }
        }

        # Log alert if suspicious or threat
        if severity in ["MEDIUM", "HIGH", "CRITICAL"]:
            self.logger.warning(
                f"ALERT [{severity}] Score={composite_score}/100 | Attack={attack_hint} | "
                f"Action={action} | Proto={event_data.get('protocol_type')} Service={event_data.get('service')}"
            )
        elif severity == "LOW":
            self.logger.info(
                f"NOTICE [{severity}] Score={composite_score}/100 | Event={attack_hint}"
            )

        return result


if __name__ == "__main__":
    engine = ThreatDetectionEngine()
    test_packet = {
        "duration": 0.0,
        "protocol_type": "tcp",
        "service": "http",
        "src_bytes": 40,
        "dst_bytes": 0,
        "failed_logins": 0,
        "logged_in": 0,
        "count": 350,
        "srv_count": 350,
        "serror_rate": 0.95,
        "rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_count": 255,
        "dst_host_srv_count": 255
    }
    alert = engine.analyze_event(test_packet)
    print("Alert Analysis:")
    import json
    print(json.dumps(alert, indent=2))

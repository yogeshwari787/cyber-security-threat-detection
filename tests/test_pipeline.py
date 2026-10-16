"""
Unit & Integration Test Suite for AI Threat Detection System
Tests data generation, preprocessor transformations, threat scoring heuristics,
and Flask REST API endpoints.
"""

import pytest
import os
import json
import pandas as pd
from src.data_loader import generate_synthetic_cyber_dataset
from src.preprocessor import CyberDataPreprocessor
from src.threat_engine import ThreatDetectionEngine
from app import app


@pytest.fixture(scope="module")
def sample_dataset():
    return generate_synthetic_cyber_dataset(n_samples=200, random_state=42)


@pytest.fixture(scope="module")
def threat_engine():
    return ThreatDetectionEngine(models_dir="models")


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_dataset_generation_structure(sample_dataset):
    assert isinstance(sample_dataset, pd.DataFrame)
    assert len(sample_dataset) == 200
    expected_cols = [
        "duration", "protocol_type", "service", "src_bytes", "dst_bytes",
        "failed_logins", "logged_in", "count", "serror_rate", "is_threat"
    ]
    for col in expected_cols:
        assert col in sample_dataset.columns


def test_preprocessor_single_record_transform(sample_dataset):
    preprocessor = CyberDataPreprocessor.load("models/preprocessor.pkl")
    test_packet = {
        "protocol_type": "tcp",
        "service": "http",
        "duration": 1.0,
        "src_bytes": 450,
        "dst_bytes": 3500,
        "failed_logins": 0,
        "logged_in": 1,
        "count": 5,
        "srv_count": 5,
        "serror_rate": 0.0,
        "rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_count": 40,
        "dst_host_srv_count": 40
    }
    vector = preprocessor.transform_single_record(test_packet)
    assert vector.shape[0] == 1
    assert vector.shape[1] == len(preprocessor.feature_columns)


def test_threat_engine_syn_flood_detection(threat_engine):
    syn_flood_packet = {
        "protocol_type": "tcp",
        "service": "http",
        "duration": 0.0,
        "src_bytes": 40,
        "dst_bytes": 0,
        "failed_logins": 0,
        "logged_in": 0,
        "count": 450,
        "srv_count": 450,
        "serror_rate": 0.98,
        "rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_count": 255,
        "dst_host_srv_count": 255
    }
    alert = threat_engine.analyze_event(syn_flood_packet)
    assert alert["threat_detected"] is True
    assert alert["severity"] in ["CRITICAL", "HIGH"]
    assert alert["risk_score"] >= 60
    assert "DoS" in alert["attack_type_attribution"]


def test_threat_engine_brute_force_detection(threat_engine):
    brute_force_packet = {
        "protocol_type": "tcp",
        "service": "ssh",
        "duration": 4.0,
        "src_bytes": 320,
        "dst_bytes": 200,
        "failed_logins": 7,
        "logged_in": 0,
        "count": 45,
        "srv_count": 45,
        "serror_rate": 0.0,
        "rerror_rate": 0.3,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_count": 30,
        "dst_host_srv_count": 30
    }
    alert = threat_engine.analyze_event(brute_force_packet)
    assert alert["threat_detected"] is True
    assert "Brute Force" in alert["attack_type_attribution"]


def test_flask_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data["status"] == "online"
    assert data["models_loaded"] is True


def test_flask_predict_endpoint(client):
    payload = {
        "protocol_type": "tcp",
        "service": "http",
        "duration": 0.0,
        "src_bytes": 40,
        "dst_bytes": 0,
        "failed_logins": 0,
        "count": 400,
        "serror_rate": 0.95,
        "diff_srv_rate": 0.0,
        "dst_host_count": 255
    }
    res = client.post(
        "/predict",
        data=json.dumps(payload),
        content_type="application/json"
    )
    assert res.status_code == 200
    data = json.loads(res.data)
    assert "threat_detected" in data
    assert "severity" in data
    assert "risk_score" in data

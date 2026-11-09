"""Integration tests for FastAPI REST backend endpoints."""
import pytest
from fastapi.testclient import TestClient

from src.api.main import app

client = TestClient(app)


def test_api_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert data["models_active"]["preprocessor"] is True
    assert data["models_active"]["multiclass_classifier"] is True


def test_api_predict_single_flow():
    payload = {
        "source_ip": "172.16.0.1",
        "destination_ip": "192.168.10.50",
        "destination_port": 80,
        "protocol": 6,
        "features": {
            "Destination Port": 80,
            "Flow Duration": 150000,
            "Flow Packets/s": 5000.0,
            "Bwd Packets/s": 2500.0,
            "Average Packet Size": 450.0,
        },
    }
    response = client.post("/predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "predicted_class" in data
    assert "confidence" in data
    assert "risk_score" in data
    assert "risk_level" in data
    assert data["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert data["latency_ms"] >= 0.0


def test_api_predict_batch_flows():
    payload = {
        "flows": [
            {
                "source_ip": "192.168.10.15",
                "destination_ip": "172.16.0.1",
                "destination_port": 443,
                "features": {"Destination Port": 443, "Flow Duration": 50000},
            },
            {
                "source_ip": "172.16.0.1",
                "destination_ip": "192.168.10.50",
                "destination_port": 80,
                "features": {"Destination Port": 80, "Flow Duration": 1000},
            },
        ]
    }
    response = client.post("/predict/batch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_flows"] == 2
    assert len(data["predictions"]) == 2


def test_api_detect_anomalies_endpoint():
    payload = {
        "features": {
            "Destination Port": 4444,
            "Flow Duration": 99999999,
            "Flow Packets/s": 99999.0,
        }
    }
    response = client.post("/detect-anomalies", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "is_anomaly" in data
    assert "anomaly_score" in data
    assert data["decision"] in ("ANOMALOUS_OUTLIER", "NORMAL_TRAFFIC")


def test_api_explanations_endpoint():
    payload = {
        "flow": {
            "destination_port": 80,
            "features": {"Destination Port": 80, "Flow Duration": 120000},
        },
        "top_k": 3,
    }
    response = client.post("/explanations", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "top_positive_features" in data
    assert "top_negative_features" in data
    assert "all_feature_impacts" in data


def test_api_alerts_and_statistics_endpoints():
    # Test statistics
    stats_resp = client.get("/statistics")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert "total_alerts" in stats
    assert stats["system_status"] == "ONLINE"

    # Test alerts list
    alerts_resp = client.get("/alerts?limit=10")
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()
    assert "alerts" in alerts
    assert "total" in alerts


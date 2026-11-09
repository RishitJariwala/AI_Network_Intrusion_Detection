"""Unit tests for Threat Intelligence Client and SQLAlchemy Database layer."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.database.models import Base, SecurityAlert, ThreatIntelRecord
from src.intelligence.cti_client import CTIClient, get_cti_client


@pytest.fixture
def in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_database_insert_and_query_alert(in_memory_db):
    alert = SecurityAlert(
        flow_id="172.16.0.1-192.168.10.50-443-80-6",
        source_ip="172.16.0.1",
        destination_ip="192.168.10.50",
        destination_port=80,
        protocol=6,
        predicted_class="DDoS",
        confidence=0.99,
        is_anomaly=True,
        anomaly_score=0.88,
        risk_score=92.5,
        risk_level="CRITICAL",
        justification="High volume syn flood",
        status="NEW",
    )
    in_memory_db.add(alert)
    in_memory_db.commit()

    retrieved = in_memory_db.query(SecurityAlert).first()
    assert retrieved is not None
    assert retrieved.predicted_class == "DDoS"
    assert retrieved.risk_level == "CRITICAL"
    assert retrieved.is_anomaly is True

    d = retrieved.to_dict()
    assert d["id"] == 1
    assert d["source_ip"] == "172.16.0.1"


def test_cti_private_ip_detection():
    client = get_cti_client()
    report = client.lookup_ip("192.168.1.100")
    assert report.is_private is True
    assert report.reputation_score == 0.0
    assert "Private" in report.source


def test_cti_known_ioc_lookup():
    client = get_cti_client()
    report = client.lookup_ip("205.174.165.73")
    assert report.is_malicious is True
    assert report.reputation_score >= 80.0
    assert "Botnet C2" in report.tags
    assert report.country == "CA"


def test_cti_cache():
    client = CTIClient(cache_ttl_seconds=300)
    rep1 = client.lookup_ip("205.174.165.73")
    assert rep1.cached is False

    rep2 = client.lookup_ip("205.174.165.73")
    assert rep2.cached is True
    assert rep2.reputation_score == rep1.reputation_score


"""Dynamic Risk Assessment Engine for NIDS & SOC Operations.

Computes a deterministic, transparent, and defensible Risk Score (0-100)
and classifies alerts into:
- LOW (0 - 24)
- MEDIUM (25 - 54)
- HIGH (55 - 79)
- CRITICAL (80 - 100)

Grounded in:
1. Supervised attack classification confidence
2. Attack taxonomy severity weights
3. Unsupervised anomaly detection corroboration
4. Cyber Threat Intelligence (CTI) reputation score
5. Protocol/Port criticality heuristics
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Severity base weights by attack category
SEVERITY_WEIGHTS: Dict[str, float] = {
    "BENIGN": 0.0,
    "PortScan": 45.0,
    "DoS": 70.0,
    "BruteForce": 75.0,
    "DDoS": 85.0,
    "Botnet": 90.0,
    "WebAttack": 92.0,
    "Infiltration": 98.0,
}

CRITICAL_PORTS = {22: "SSH", 21: "FTP", 445: "SMB", 3389: "RDP", 8080: "HTTP-Proxy", 23: "Telnet"}


class RiskAssessmentEngine:
    """Multi-factor cyber risk evaluator for network security events."""

    @staticmethod
    def evaluate_risk(
        predicted_class: str,
        confidence: float,
        is_anomaly: bool = False,
        anomaly_score: float = 0.0,
        destination_port: Optional[int] = None,
        cti_reputation: Optional[float] = None,
        top_shap_features: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Compute holistic risk score, risk level, and explainable justification."""
        factors = []
        base_severity = SEVERITY_WEIGHTS.get(predicted_class, 50.0)

        # 1. Supervised probability contribution
        score = base_severity * confidence
        if predicted_class != "BENIGN":
            factors.append(f"Classified as '{predicted_class}' with {confidence:.1%} model confidence (+{score:.1f} pts)")
        else:
            factors.append(f"Traffic classified as normal BENIGN flow (base severity 0)")

        # 2. Anomaly detection corroboration
        if is_anomaly:
            anomaly_boost = min(15.0, max(5.0, (anomaly_score - 0.5) * 30.0 if anomaly_score > 0 else 10.0))
            score += anomaly_boost
            factors.append(f"Unsupervised Isolation Forest flagged flow as anomalous (+{anomaly_boost:.1f} pts)")

        # 3. Port criticality check
        if destination_port is not None and int(destination_port) in CRITICAL_PORTS:
            service = CRITICAL_PORTS[int(destination_port)]
            if predicted_class != "BENIGN":
                port_boost = 10.0
                score += port_boost
                factors.append(f"Targeting critical enterprise service '{service}' on port {destination_port} (+{port_boost:.1f} pts)")

        # 4. CTI reputation corroboration
        if cti_reputation is not None and cti_reputation > 0:
            cti_boost = (cti_reputation / 100.0) * 15.0
            score += cti_boost
            factors.append(f"Threat Intelligence indicates malicious IP reputation of {cti_reputation:.0f}/100 (+{cti_boost:.1f} pts)")

        # Clamp score to [0, 100]
        final_score = float(min(100.0, max(0.0, score)))

        # Determine Risk Level
        if final_score < 25.0:
            risk_level = "LOW"
            action = "Monitor routine traffic; no remediation required."
        elif final_score < 55.0:
            risk_level = "MEDIUM"
            action = "Flag for secondary review; inspect source IP for repeated scan patterns."
        elif final_score < 80.0:
            risk_level = "HIGH"
            action = "Apply temporary firewall rate-limit or host isolation; initiate incident ticket."
        else:
            risk_level = "CRITICAL"
            action = "IMMEDIATE MITIGATION: Block IP at border firewall; trigger SOC Tier-3 incident response."

        # Grounding in actual SHAP features if provided
        shap_narrative = ""
        if top_shap_features and len(top_shap_features) > 0:
            top_positive = [f["feature"] for f in top_shap_features if f.get("shap_value", 0) > 0][:3]
            if top_positive:
                shap_narrative = f" Primary risk drivers identified by SHAP: {', '.join(top_positive)}."

        justification = " ".join(factors) + shap_narrative

        return {
            "risk_score": round(final_score, 1),
            "risk_level": risk_level,
            "recommended_action": action,
            "justification": justification,
            "contributing_factors": factors,
        }


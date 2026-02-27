"""
Microsoft Sentinel Integration for AI PR Guard

Provides security compliance logging and alerts via Microsoft Sentinel.
This integrates with Azure Sentinel for enterprise security monitoring.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass(frozen=True)
class SentinelAlert:
    """Represents a security alert to be sent to Microsoft Sentinel."""
    pr_number: int
    repo_full_name: str
    severity: str
    alert_type: str
    title: str
    description: str
    findings: list[dict[str, Any]]
    scores: dict[str, Any]


class SentinelClient:
    """Client for sending security events to Microsoft Sentinel."""
    
    def __init__(self) -> None:
        self.enabled = os.environ.get("SENTINEL_ENABLED", "").lower() == "true"
        self.workspace_id = os.environ.get("SENTINEL_WORKSPACE_ID")
        self.shared_key = os.environ.get("SENTINEL_SHARED_KEY")
        self.webhook_url = os.environ.get("SENTINEL_WEBHOOK_URL")
    
    def is_configured(self) -> bool:
        if not self.enabled:
            return False
        return bool(self.webhook_url or (self.workspace_id and self.shared_key))
    
    def send_security_alert(self, alert: SentinelAlert) -> bool:
        if not self.is_configured():
            return False
        
        payload = self._build_payload(alert)
        
        if self.webhook_url:
            return self._send_via_webhook(payload)
        elif self.workspace_id and self.shared_key:
            return self._send_via_log_analytics(payload)
        
        return False
    
    def _build_payload(self, alert: SentinelAlert) -> dict[str, Any]:
        return {
            "TimeGenerated": datetime.now(timezone.utc).isoformat(),
            "PrNumber": alert.pr_number,
            "RepoFullName": alert.repo_full_name,
            "Severity": alert.severity.upper(),
            "AlertType": alert.alert_type,
            "Title": alert.title,
            "Description": alert.description,
            "Findings": json.dumps(alert.findings),
            "Scores": json.dumps(alert.scores),
            "Source": "ai-pr-guard",
        }
    
    def _send_via_webhook(self, payload: dict[str, Any]) -> bool:
        try:
            import requests
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            return response.status_code in (200, 201, 202)
        except Exception:
            return False
    
    def _send_via_log_analytics(self, payload: dict[str, Any]) -> bool:
        try:
            import base64
            import hashlib
            import hmac
            import requests
            
            api_url = "https://" + str(self.workspace_id) + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
            
            body = json.dumps(payload)
            date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
            content_length = len(body)
            
            string_to_sign = "POST\n" + str(content_length) + "\napplication/json\nx-ms-date:" + date + "\n/api/logs"
            
            key_bytes = base64.b64decode(self.shared_key)
            
            signature = hmac.new(key_bytes, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
            signature_b64 = base64.b64encode(signature).decode("utf-8")
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": "SharedKey " + str(self.workspace_id) + ":" + signature_b64,
                "Log-Type": "AIPRGuardSecurity",
                "x-ms-date": date,
            }
            
            response = requests.post(api_url, data=body, headers=headers, timeout=10)
            return response.status_code in (200, 201, 202)
        except Exception:
            return False


def create_security_alert(
    pr_number: int,
    repo_full_name: str,
    findings: list[dict[str, Any]],
    scores: dict[str, Any],
) -> Optional[SentinelAlert]:
    if not findings and not scores:
        return None
    
    severity = "low"
    alert_type = "general"
    title = "PR Review Completed"
    description = "PR #" + str(pr_number) + " in " + repo_full_name + " has been reviewed."
    
    risk_level = scores.get("risk_level", "low")
    security_score = scores.get("security_score", 100)
    
    if risk_level == "critical" or security_score < 30:
        severity = "critical"
        alert_type = "critical_security_issue"
        title = "Critical Security Issue Detected"
        description = "PR #" + str(pr_number) + " has critical security issues that require immediate attention."
    elif risk_level == "high" or security_score < 50:
        severity = "high"
        alert_type = "high_security_risk"
        title = "High Security Risk Detected"
        description = "PR #" + str(pr_number) + " has high-risk security issues."
    
    critical_findings = [f for f in findings if f.get("severity") == "critical"]
    if critical_findings:
        alert_type = "security_violation"
        count = len(critical_findings)
        title = "Security Violation: " + str(count) + " Critical Issue(s)"
        description = "PR #" + str(pr_number) + " contains " + str(count) + " critical security issue(s) that must be addressed before merging."
    
    return SentinelAlert(
        pr_number=pr_number,
        repo_full_name=repo_full_name,
        severity=severity,
        alert_type=alert_type,
        title=title,
        description=description,
        findings=findings,
        scores=scores,
    )


def check_pr_compliance(
    scores: dict[str, Any],
    security_threshold: int = 70,
    risk_threshold: str = "high",
) -> dict[str, Any]:
    security_score = scores.get("security_score", 100)
    risk_level = scores.get("risk_level", "low")
    
    risk_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    current_risk = risk_levels.get(risk_level, 0)
    max_risk = risk_levels.get(risk_threshold, 2)
    
    compliant = security_score >= security_threshold and current_risk <= max_risk
    
    failures = []
    if not compliant:
        if security_score < security_threshold:
            failures.append("Security score " + str(security_score) + " is below threshold " + str(security_threshold))
        if current_risk > max_risk:
            failures.append("Risk level " + risk_level + " exceeds threshold " + risk_threshold)
    
    return {
        "compliant": compliant,
        "security_score": security_score,
        "security_threshold": security_threshold,
        "risk_level": risk_level,
        "risk_threshold": risk_threshold,
        "passed": compliant,
        "failures": failures,
    }

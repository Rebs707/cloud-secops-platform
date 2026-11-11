from collections import Counter

from app.agents.security_scan_agent import SecurityScanAgent
from app.agents.vulnerability_agent import VulnerabilityAgent
from app.agents.threat_detection_agent import ThreatDetectionAgent
from app.agents.compliance_agent import ComplianceAgent
from app.core.findings import SEVERITY_WEIGHT
from app.models.schemas import ScanResponse, ScanRequest, Severity


class SecOpsWorkflow:
    def __init__(self):
        self.security = SecurityScanAgent()
        self.vulnerability = VulnerabilityAgent()
        self.threat = ThreatDetectionAgent()
        self.compliance = ComplianceAgent()

    def run(self, request: ScanRequest) -> ScanResponse:
        resource = request.model_dump()

        results = {
            "security_scan": self.security.scan(resource),
            "vulnerability": self.vulnerability.analyze(resource),
            "threat_detection": self.threat.detect(resource),
            "compliance": self.compliance.check(resource),
        }

        findings = [
            item
            for result in results.values()
            for item in result.findings
        ]

        counts = Counter(item.severity.value for item in findings)
        risk_score = min(
            100,
            sum(SEVERITY_WEIGHT[item.severity] for item in findings),
        )

        if any(item.severity == Severity.critical for item in findings):
            overall_status = "critical"
        elif any(item.severity == Severity.high for item in findings):
            overall_status = "high_risk"
        elif findings:
            overall_status = "review_required"
        elif not any(result.checks_performed for result in results.values()):
            overall_status = "not_assessed"
        else:
            overall_status = "no_issues_detected"

        return ScanResponse(
            resource_id=request.resource_id,
            overall_status=overall_status,
            risk_score=risk_score,
            summary={
                "total_findings": len(findings),
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
                "info": counts["info"],
            },
            results=results,
            findings=findings,
            limitations=[
                "Analysis is limited to evidence supplied in the request.",
                "Package checks use an illustrative local rule catalogue, not a live CVE database.",
                "Event detection uses deterministic patterns, not a trained AI model.",
                "Compliance results do not constitute formal certification or an independent audit.",
                "No cloud account or infrastructure is queried or modified.",
            ],
        )

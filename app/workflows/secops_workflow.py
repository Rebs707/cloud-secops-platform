from app.agents.security_scan_agent import SecurityScanAgent
from app.agents.vulnerability_agent import VulnerabilityAgent
from app.agents.threat_detection_agent import ThreatDetectionAgent
from app.agents.compliance_agent import ComplianceAgent


class SecOpsWorkflow:

    def run(self, resource):

        return {
            "security_scan": SecurityScanAgent().scan(resource),
            "vulnerability": VulnerabilityAgent().analyze(resource),
            "threat_detection": ThreatDetectionAgent().detect(resource),
            "compliance": ComplianceAgent().check(resource)
        }

from app.core.findings import finding, status_for
from app.models.schemas import AgentResult, Severity


class ThreatDetectionAgent:
    """Detects simple suspicious patterns in supplied event records."""

    def detect(self, resource: dict) -> AgentResult:
        events = resource.get("events", [])
        findings = []

        for index, event in enumerate(events):
            event_type = str(event.get("event_type", "")).lower()
            outcome = str(event.get("outcome", "")).lower()
            source_ip = str(event.get("source_ip", "unknown"))

            if event_type in {"login", "authentication"} and outcome == "failure":
                findings.append(finding(
                    f"THREAT-{index + 1:03d}",
                    "authentication",
                    Severity.medium,
                    "Failed authentication event",
                    "A failed authentication event was present in the supplied evidence.",
                    f"event_type={event_type}, source_ip={source_ip}",
                    "Correlate repeated failures, validate the source and review authentication controls.",
                    "threat_detection",
                ))

            if event_type in {"privilege_escalation", "policy_change"}:
                findings.append(finding(
                    f"THREAT-{index + 1:03d}",
                    "privilege",
                    Severity.high,
                    "Sensitive privilege or policy event",
                    "A privilege escalation or policy change event was supplied.",
                    f"event_type={event_type}, source_ip={source_ip}",
                    "Verify authorization, review the actor and inspect related audit events.",
                    "threat_detection",
                ))

        return AgentResult(
            status=status_for(findings, len(events)),
            findings=findings,
            checks_performed=len(events),
        )

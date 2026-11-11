from app.core.findings import finding, status_for
from app.models.schemas import AgentResult, Severity


class ComplianceAgent:
    """Evaluates supplied control outcomes; missing controls remain unassessed."""

    REQUIRED_CONTROLS = {
        "encryption_at_rest": "Encryption at rest",
        "audit_logging": "Audit logging",
        "least_privilege": "Least privilege",
        "mfa": "Multi-factor authentication",
    }

    def check(self, resource: dict) -> AgentResult:
        controls = resource.get("controls", {})
        findings = []
        assessed = 0

        for key, label in self.REQUIRED_CONTROLS.items():
            value = controls.get(key)
            if value is None:
                continue

            assessed += 1
            if value is False:
                findings.append(finding(
                    f"COMP-{key.upper()}",
                    "compliance",
                    Severity.high,
                    f"Control failed: {label}",
                    f"The supplied control result indicates that {label.lower()} is not satisfied.",
                    f"{key}=false",
                    f"Implement and verify the {label.lower()} control.",
                    "compliance",
                ))

        return AgentResult(
            status=status_for(findings, assessed),
            findings=findings,
            checks_performed=assessed,
        )

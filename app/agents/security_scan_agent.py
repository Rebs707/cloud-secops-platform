from app.core.findings import finding, status_for
from app.models.schemas import AgentResult, Severity


class SecurityScanAgent:
    """Evaluates explicitly supplied cloud configuration evidence."""

    def scan(self, resource: dict) -> AgentResult:
        config = resource.get("configuration", {})
        findings = []
        checks = 0

        rules = [
            ("public_access", "SEC-001", Severity.critical,
             "Public access enabled",
             "A resource is configured to allow public access.",
             "Restrict access to approved networks and identities."),
            ("encryption_enabled", "SEC-002", Severity.high,
             "Encryption disabled",
             "Encryption is explicitly disabled.",
             "Enable encryption at rest and in transit where applicable."),
            ("logging_enabled", "SEC-003", Severity.medium,
             "Logging disabled",
             "Audit or access logging is explicitly disabled.",
             "Enable and retain security-relevant audit logs."),
            ("mfa_enabled", "SEC-004", Severity.high,
             "MFA disabled",
             "Multi-factor authentication is explicitly disabled.",
             "Require MFA for privileged and interactive access."),
        ]

        for key, rule_id, severity, title, description, recommendation in rules:
            if key not in config or config[key] is None:
                continue
            checks += 1
            if key == "public_access" and config[key] is True:
                findings.append(finding(
                    rule_id, "configuration", severity, title, description,
                    f"{key}={config[key]}", recommendation, "security_scan"
                ))
            elif key != "public_access" and config[key] is False:
                findings.append(finding(
                    rule_id, "configuration", severity, title, description,
                    f"{key}={config[key]}", recommendation, "security_scan"
                ))

        return AgentResult(
            status=status_for(findings, checks),
            findings=findings,
            checks_performed=checks,
        )

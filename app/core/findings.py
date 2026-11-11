from app.models.schemas import Finding, Severity


SEVERITY_WEIGHT = {
    Severity.critical: 40,
    Severity.high: 25,
    Severity.medium: 15,
    Severity.low: 5,
    Severity.info: 0,
}


def finding(
    finding_id: str,
    category: str,
    severity: Severity,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    source: str,
) -> Finding:
    return Finding(
        id=finding_id,
        category=category,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
        source=source,
    )


def status_for(findings: list[Finding], checks: int) -> str:
    if checks == 0:
        return "not_assessed"
    if any(f.severity in (Severity.critical, Severity.high) for f in findings):
        return "issues_detected"
    if findings:
        return "review_required"
    return "no_issues_detected"

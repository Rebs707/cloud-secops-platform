from fastapi.testclient import TestClient

from app.main import app
from app.models.schemas import ScanRequest
from app.workflows.secops_workflow import SecOpsWorkflow

client = TestClient(app)


def test_clean_resource_is_not_assumed_secure():
    request = ScanRequest(resource_id="clean-test")
    result = SecOpsWorkflow().run(request)
    assert result.overall_status == "not_assessed"
    assert result.summary["total_findings"] == 0


def test_configuration_risks_are_detected():
    request = ScanRequest(
        resource_id="public-bucket",
        configuration={
            "public_access": True,
            "encryption_enabled": False,
            "logging_enabled": False,
            "mfa_enabled": True,
        },
    )
    result = SecOpsWorkflow().run(request)
    assert result.overall_status == "critical"
    assert result.summary["critical"] == 1
    assert result.summary["high"] == 1
    assert result.summary["medium"] == 1


def test_package_rule_detects_legacy_version():
    request = ScanRequest(
        resource_id="dependency-test",
        packages={"django": "1.2.0"},
    )
    result = SecOpsWorkflow().run(request)
    assert result.results["vulnerability"].checks_performed == 1
    assert result.results["vulnerability"].findings[0].id == "VULN-001-django"


def test_unknown_package_is_not_flagged_by_local_catalogue():
    request = ScanRequest(
        resource_id="package-test",
        packages={"example-package": "99.0.0"},
    )
    result = SecOpsWorkflow().run(request)
    assert result.results["vulnerability"].findings == []
    assert result.results["vulnerability"].checks_performed == 1


def test_threat_patterns_are_detected():
    request = ScanRequest(
        resource_id="event-test",
        events=[
            {"event_type": "login", "outcome": "failure", "source_ip": "192.0.2.10"},
            {"event_type": "privilege_escalation", "outcome": "success"},
        ],
    )
    result = SecOpsWorkflow().run(request)
    assert len(result.results["threat_detection"].findings) == 2


def test_compliance_failed_control_is_reported():
    request = ScanRequest(
        resource_id="compliance-test",
        controls={
            "encryption_at_rest": True,
            "audit_logging": False,
            "least_privilege": None,
        },
    )
    result = SecOpsWorkflow().run(request)
    compliance = result.results["compliance"]
    assert compliance.checks_performed == 2
    assert len(compliance.findings) == 1


def test_api_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_api_scan_returns_structured_result():
    response = client.post(
        "/secops/scan",
        json={
            "resource_id": "api-test",
            "configuration": {"public_access": True},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["overall_status"] == "critical"
    assert body["findings"][0]["id"] == "SEC-001"


def test_api_rejects_unknown_fields():
    response = client.post(
        "/secops/scan",
        json={"resource_id": "bad-request", "unexpected": "value"},
    )
    assert response.status_code == 422


def test_api_rejects_empty_resource_id():
    response = client.post(
        "/secops/scan",
        json={"resource_id": ""},
    )
    assert response.status_code == 422


def test_rules_endpoint():
    response = client.get("/secops/rules")
    assert response.status_code == 200
    assert "public_access" in response.json()["configuration_checks"]

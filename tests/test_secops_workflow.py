from app.workflows.secops_workflow import SecOpsWorkflow


def test_secops_workflow():

    result = SecOpsWorkflow().run("production-resource")

    assert result["security_scan"]["status"] == "scan completed"
    assert result["vulnerability"]["status"] == "secure"
    assert result["threat_detection"]["status"] == "no threats detected"
    assert result["compliance"]["compliant"] is True

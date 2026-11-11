from fastapi import APIRouter
from app.models.schemas import ScanRequest, ScanResponse
from app.workflows.secops_workflow import SecOpsWorkflow

router = APIRouter(prefix="/secops", tags=["Security Operations"])
workflow = SecOpsWorkflow()


@router.post("/scan", response_model=ScanResponse)
def run_scan(request: ScanRequest):
    return workflow.run(request)


@router.get("/rules")
def list_analysis_rules():
    return {
        "configuration_checks": [
            "public_access",
            "encryption_enabled",
            "logging_enabled",
            "mfa_enabled",
        ],
        "event_patterns": [
            "failed login",
            "failed authentication",
            "privilege escalation",
            "policy change",
        ],
        "compliance_controls": [
            "encryption_at_rest",
            "audit_logging",
            "least_privilege",
            "mfa",
        ],
        "package_catalogue": "Illustrative local rules only; not a live CVE feed.",
    }

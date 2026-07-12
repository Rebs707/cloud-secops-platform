from fastapi import APIRouter
from app.workflows.secops_workflow import SecOpsWorkflow

router = APIRouter()

workflow = SecOpsWorkflow()


@router.get("/secops/{resource}")
def secops_check(resource: str):
    return workflow.run(resource)

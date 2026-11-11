from fastapi import FastAPI
from app.api.secops import router as secops_router

app = FastAPI(
    title="CloudSecOps Platform",
    description="Evidence-driven cloud security analysis prototype.",
    version="2.0.0",
)

app.include_router(secops_router)


@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy", "platform": "CloudSecOps Platform"}

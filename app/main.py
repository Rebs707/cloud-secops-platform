from fastapi import FastAPI
from app.api.secops import router as secops_router

app = FastAPI(
    title="CloudSecOps Platform",
    version="1.0.0"
)

app.include_router(secops_router)


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "platform": "CloudSecOps Platform"
    }

from fastapi import FastAPI
from app.api.analysis import router as analysis_router
from app.api.auth import router as auth_router

app = FastAPI(
    title="Security AI Platform",
    description=(
        "AI-assisted cybersecurity investigation platform."
    ),
    version="0.1.0",
)

app.include_router(analysis_router)
app.include_router(auth_router)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
    }
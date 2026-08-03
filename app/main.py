from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.api.analysis import router as analysis_router
from app.core.database import create_database_tables



@asynccontextmanager
async def lifespan(
        _: FastAPI,
) -> AsyncIterator[None]:
    """Prepare app resources during startup"""

    create_database_tables()
    yield
    

app = FastAPI(
    title="Security AI Platform",
    description="AI-assisted cybersecurity investigation platform",
    version="0.1.0",
    lifespan=lifespan,

)

app.include_router(analysis_router)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "healthy"}

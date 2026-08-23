from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from app.api.analysis import router as analysis_router
from app.api.auth import router as auth_router
from app.api.ai_reports import router as ai_reports_router
from app.api.cases import router as cases_router
from app.api.anomaly import router as anomaly_router
from app.api.workspace import router as workspace_router
from app.dashboard.router import router as dashboard_router
from app.core.config import get_settings
app = FastAPI(
    title="Security AI Platform",
    description=(
        "AI-assisted cybersecurity investigation platform."
    ),
    version="0.1.0",
)

app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static",
)


@app.middleware("http")
async def security_headers(
        request: Request,
        call_next,
) -> Response:
    """
    Add baseline browser-security headers.

    The strict Content Security Policy is applied to the
    server-rendered dashboard rather than the FastAPI documentation,
    which loads its own documentation assets.
    """

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"

    response.headers["X-Frame-Options"] = "DENY"

    response.headers["Referrer-Policy"] = "no-referrer"

    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    path = request.url.path

    is_dashboard_page = (
        path == "/login"
        or path == "/logout"
        or path == "/dashboard"
        or path.startswith("/dashboard/")
    )

    if is_dashboard_page:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'"
        )

        response.headers["Cache-Control"] = "no-store, max-age=0"

        response.headers["Pragma"] = "no-cache"

    settings = get_settings()

    if settings.dashboard_cookie_secure:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    return response

app.include_router(analysis_router)
app.include_router(auth_router)
app.include_router(ai_reports_router)
app.include_router(cases_router)
app.include_router(anomaly_router)
app.include_router(workspace_router)
app.include_router(dashboard_router)
@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
    }
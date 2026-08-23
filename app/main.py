from urllib.parse import urlsplit
from fastapi import FastAPI, Request
from fastapi.responses import Response, JSONResponse
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

SAFE_HTTP_METHODS = {
    "GET",
    "HEAD",
    "OPTIONS",
}

def _is_dashboard_browser_path(
        path: str
) -> bool:
    """
    Return True for browser-dashboard routes that use
    cookie-based authentication.

    Bearer-token API routes are intentionally excluded.
    """

    return (
        path == "/login"
        or path == "/logout"
        or path == "/dashboard"
        or path.startswith("/dashboard/")
    )

def _request_origin(
        request: Request,
) -> str:
    """
    Return the origin represented by the incoming request.
    """

    return  (
        f"{request.url.scheme}://"
        f"{request.url.netloc}"
    )

def _same_origin(
        candidate: str,
        expected: str,
) -> bool:
    """
    Compare two origins by scheme and network location.

    Paths, queries and fragments are intentionally ignored.
    """

    try:
        candidate_url = urlsplit(candidate)
        expected_url = urlsplit(expected)
    except ValueError:
        return False

    return (
        candidate_url.scheme.lower() == expected_url.scheme.lower()
        and
        candidate_url.netloc.lower() == expected_url.netloc.lower()
    )

def _csrf_request_is_allowed(
        request: Request,
) -> bool:
    """
    Validate browser metadata for a state-changing
    cookie-authenticated dashboard request.

    This complements SameSite=Strict cookies.

    Modern browsers send Sec-Fetch-Site and/or Origin/
    Referer information. Cross-site browser requests are
    rejected before dashboard route logic executes.

    Requests without these optional browser headers remain
    accepted. This preserves support for trusted non-browser
    clients and the application's TestClient while the
    SameSite cookie continues to provide an independent
    browser-level CSRF boundary.
    """

    fetch_site = (request.headers.get("sec-fetch-site"))

    if (
        fetch_site is not None
        and fetch_site.lower() == "cross-site"
    ):
        return False

    expected_origin = _request_origin(request)

    origin = request.headers.get("origin")

    if origin:
        return _same_origin(origin, expected_origin)

    referer = request.headers.get("referer")

    if referer:
        return _same_origin(referer, expected_origin)

    return True


@app.middleware("http")
async def dashboard_csrf_protection(
        request: Request,
        call_next,
) -> Response:
    """
    Reject cross-site state-changing requests targeting
    cookie-authenticated dashboard routes.

    API routes using Bearer authentication are not subject
    to this browser-specific protection.
    """

    if (
        request.method.upper()
        not in SAFE_HTTP_METHODS
        and _is_dashboard_browser_path(request.url.path)
        and not _csrf_request_is_allowed(request)
    ):
        return JSONResponse(
            status_code=403,
            content={
                "detail": (
                    "Cross-site dashboard "
                    "request rejected."
                )
            },
        )

    return await call_next(request)


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
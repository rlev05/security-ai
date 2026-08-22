from typing import Annotated
from fastapi import APIRouter, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.database import get_database_session
from app.models.user_record import UserRecord
from app.services.analysis_history_service import get_analysis_record, list_analysis_records
from app.services.analysis_history_service import get_analysis_record, list_analysis_records
from app.services.dashboard_service import get_dashboard_metrics
from app.services.security_service import create_access_token, decode_access_token
from app.services.user_service import authenticate_user

router = APIRouter(
    tags=["Dashboard"],
)

templates = Jinja2Templates(directory="app/templates")

DASHBOARD_COOKIE_NAME = (
    "security_ai_session"
)

DatabaseSession = Annotated[Session, Depends(get_database_session)]

def _get_dashboard_user(
         request: Request,
         session: Session
 ) -> UserRecord | None:
     token = request.cookies.get(DASHBOARD_COOKIE_NAME)

     if token is None:
         return None

     try:
         user_id = decode_access_token(token)
     except ValueError:
         return None

     user = session.get(
         UserRecord,
         user_id
     )

     if (
         user is None
         or not user.is_active
     ):
         return None

     return user

@router.get(
    "/",
    include_in_schema=False,
)
def root() -> RedirectResponse:
    return RedirectResponse(
        url="/dashboard",
        status_code=(
            status.HTTP_303_SEE_OTHER
        ),
    )


@router.get(
    "/login",
    response_class=HTMLResponse,
)
def login_page(
    request: Request,
    session: DatabaseSession,
) -> Response:
    user = _get_dashboard_user(
        request,
        session,
    )

    if user is not None:
        return RedirectResponse(
            url="/dashboard",
            status_code=(
                status.HTTP_303_SEE_OTHER
            ),
        )

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "page_title": (
                "Security AI Login"
            ),
            "error": None,
        },
    )


@router.post(
    "/login",
    response_class=HTMLResponse,
)
def login(
    request: Request,
    session: DatabaseSession,
    login: Annotated[
        str,
        Form(),
    ],
    password: Annotated[
        str,
        Form(),
    ],
) -> Response:
    user = authenticate_user(
        session,
        login=login,
        password=password,
    )

    if user is None:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "page_title": (
                    "Security AI Login"
                ),
                "error": (
                    "Incorrect username, email, "
                    "or password."
                ),
            },
            status_code=(
                status.HTTP_401_UNAUTHORIZED
            ),
        )

    token = create_access_token(
        user.id
    )

    settings = get_settings()

    response = RedirectResponse(
        url="/dashboard",
        status_code=(
            status.HTTP_303_SEE_OTHER
        ),
    )

    response.set_cookie(
        key=DASHBOARD_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=(
            settings
            .access_token_expire_minutes
            * 60
        ),
        path="/",
    )

    return response


@router.post(
    "/logout",
)
def logout() -> RedirectResponse:
    response = RedirectResponse(
        url="/login",
        status_code=(
            status.HTTP_303_SEE_OTHER
        ),
    )

    response.delete_cookie(
        key=DASHBOARD_COOKIE_NAME,
        path="/",
    )

    return response


@router.get(
    "/dashboard",
    response_class=HTMLResponse,
)
def dashboard(
    request: Request,
    session: DatabaseSession,
) -> Response:
    user = _get_dashboard_user(
        request,
        session,
    )

    if user is None:
        return RedirectResponse(
            url="/login",
            status_code=(
                status.HTTP_303_SEE_OTHER
            ),
        )

    metrics = get_dashboard_metrics(
        session,
        owner_user_id=user.id,
    )

    recent_analyses = (
        list_analysis_records(
            session,
            owner_user_id=user.id,
            limit=10,
            offset=0,
        )
    )

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "page_title": (
                "Security AI Dashboard"
            ),
            "current_user": user,
            "metrics": metrics,
            "recent_analyses": (
                recent_analyses
            ),
        },
    )


@router.get(
    "/dashboard/analysis/{analysis_id}",
    response_class=HTMLResponse,
)
def analysis_workspace(
    analysis_id: str,
    request: Request,
    session: DatabaseSession,
) -> Response:
    user = _get_dashboard_user(
        request,
        session,
    )

    if user is None:
        return RedirectResponse(
            url="/login",
            status_code=(
                status.HTTP_303_SEE_OTHER
            ),
        )

    analysis = get_analysis_record(
        session,
        analysis_id,
        owner_user_id=user.id,
    )

    if analysis is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Analysis not found",
        )

    return templates.TemplateResponse(
        request=request,
        name="analysis_workspace.html",
        context={
            "page_title": (
                "Security Investigation"
            ),
            "current_user": user,
            "analysis": analysis,
        },
    )
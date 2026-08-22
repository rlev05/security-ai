from _collections_abc import Callable
from typing import Annotated, Any
from fastapi import APIRouter, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.anomaly.detector import DEFAULT_CONTAMINATION, detect_event_anomalies
from app.core.config import get_settings
from app.core.database import get_database_session
from app.models.case import CaseSeverity
from app.models.investigation_report import InvestigationReportStatus
from app.models.user import UserRole
from app.models.user_record import UserRecord
from app.services.analysis_history_service import get_analysis_record, list_analysis_records
from app.services.anomaly_run_service import get_latest_anomaly_run, load_anomaly_result, save_anomaly_run
from app.services.case_service import create_case, get_case, get_case_analyses, link_analysis_to_case, list_cases
from app.services.dashboard_service import get_dashboard_metrics
from app.services.investigation_report_service import get_latest_investigation_report, fail_report, create_pending_report
from app.services.security_service import create_access_token, decode_access_token
from app.services.user_service import authenticate_user
from app.tasks.dependencies import get_report_enqueuer

router = APIRouter(
    tags=["Dashboard"],
)


templates = Jinja2Templates(
    directory="app/templates",
)


DASHBOARD_COOKIE_NAME = (
    "security_ai_session"
)


DatabaseSession = Annotated[
    Session,
    Depends(get_database_session),
]


ReportEnqueuer = Annotated[
    Callable[[str], None],
    Depends(get_report_enqueuer),
]


def _is_admin(
    user: UserRecord,
) -> bool:
    return (
        user.role
        == UserRole.ADMIN.value
    )


def _owner_filter(
    user: UserRecord,
) -> str | None:
    if _is_admin(user):
        return None

    return user.id


def _get_dashboard_user(
    request: Request,
    session: Session,
) -> UserRecord | None:
    token = request.cookies.get(
        DASHBOARD_COOKIE_NAME
    )

    if token is None:
        return None

    try:
        user_id = decode_access_token(
            token
        )
    except ValueError:
        return None

    user = session.get(
        UserRecord,
        user_id,
    )

    if (
        user is None
        or not user.is_active
    ):
        return None

    return user


def _get_visible_analysis(
    session: Session,
    *,
    analysis_id: str,
    user: UserRecord,
):
    analysis = get_analysis_record(
        session,
        analysis_id,
        owner_user_id=(
            _owner_filter(user)
        ),
    )

    if analysis is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Analysis not found",
        )

    return analysis


def _normalise_event_list(
    value: Any,
) -> list[dict[str, Any]]:
    if not isinstance(
        value,
        list,
    ):
        return []

    return [
        event
        for event in value
        if isinstance(
            event,
            dict,
        )
    ]


def _find_nested_events(
    value: Any,
) -> list[dict[str, Any]]:
    if isinstance(
        value,
        dict,
    ):
        if "events" in value:
            events = (
                _normalise_event_list(
                    value["events"]
                )
            )

            if events:
                return events

        for nested_value in (
            value.values()
        ):
            if not isinstance(
                nested_value,
                (
                    dict,
                    list,
                ),
            ):
                continue

            events = (
                _find_nested_events(
                    nested_value
                )
            )

            if events:
                return events

    elif isinstance(
        value,
        list,
    ):
        for item in value:
            if not isinstance(
                item,
                (
                    dict,
                    list,
                ),
            ):
                continue

            events = (
                _find_nested_events(
                    item
                )
            )

            if events:
                return events

    return []


def _extract_events(
    result_json: dict[str, Any],
) -> list[dict[str, Any]]:
    return _find_nested_events(
        result_json
    )


def _get_result_list(
    result_json: dict[str, Any],
    key: str,
) -> list:
    value = result_json.get(
        key,
        [],
    )

    if isinstance(
        value,
        list,
    ):
        return value

    return []


def _get_case_groups(
    session: Session,
    *,
    analysis_id: str,
    user: UserRecord,
) -> tuple[list, list]:
    visible_cases = list_cases(
        session,
        user_id=user.id,
        is_admin=_is_admin(user),
    )

    linked_cases = []
    available_cases = []

    for case_record in visible_cases:
        analyses = get_case_analyses(
            session,
            case_id=case_record.id,
        )

        linked = any(
            analysis.id
            == analysis_id
            for analysis in analyses
        )

        if linked:
            linked_cases.append(
                case_record
            )
        else:
            available_cases.append(
                case_record
            )

    return (
        linked_cases,
        available_cases,
    )


def _build_workspace_context(
    session: Session,
    *,
    analysis,
    user: UserRecord,
    action_message: str | None = None,
    action_error: str | None = None,
) -> dict[str, Any]:
    result_json = (
        analysis.result_json
        if isinstance(
            analysis.result_json,
            dict,
        )
        else {}
    )

    events = _extract_events(
        result_json
    )

    incidents = _get_result_list(
        result_json,
        "incidents",
    )

    anomaly_run = (
        get_latest_anomaly_run(
            session,
            analysis_id=analysis.id,
        )
    )

    anomaly_result = None

    if anomaly_run is not None:
        anomaly_result = (
            load_anomaly_result(
                anomaly_run
            )
        )

    investigation_report = (
        get_latest_investigation_report(
            session,
            analysis_id=analysis.id,
        )
    )

    (
        linked_cases,
        available_cases,
    ) = _get_case_groups(
        session,
        analysis_id=analysis.id,
        user=user,
    )

    return {
        "current_user": user,
        "analysis": analysis,
        "events": events,
        "incidents": incidents,
        "anomaly_run": anomaly_run,
        "anomaly_result": (
            anomaly_result
        ),
        "investigation_report": (
            investigation_report
        ),
        "linked_cases": (
            linked_cases
        ),
        "available_cases": (
            available_cases
        ),
        "action_message": (
            action_message
        ),
        "action_error": (
            action_error
        ),
    }


def _render_workspace_content(
    request: Request,
    session: Session,
    *,
    analysis,
    user: UserRecord,
    action_message: str | None = None,
    action_error: str | None = None,
) -> Response:
    context = (
        _build_workspace_context(
            session,
            analysis=analysis,
            user=user,
            action_message=(
                action_message
            ),
            action_error=(
                action_error
            ),
        )
    )

    return templates.TemplateResponse(
        request=request,
        name=(
            "partials/"
            "workspace_content.html"
        ),
        context=context,
    )


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
        samesite="strict",
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

    analysis = _get_visible_analysis(
        session,
        analysis_id=analysis_id,
        user=user,
    )

    context = (
        _build_workspace_context(
            session,
            analysis=analysis,
            user=user,
        )
    )

    context["page_title"] = (
        "Security Investigation"
    )

    return templates.TemplateResponse(
        request=request,
        name="analysis_workspace.html",
        context=context,
    )


@router.get(
    "/dashboard/analysis/{analysis_id}/workspace-content",
    response_class=HTMLResponse,
)
def workspace_content(
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

    analysis = _get_visible_analysis(
        session,
        analysis_id=analysis_id,
        user=user,
    )

    return _render_workspace_content(
        request,
        session,
        analysis=analysis,
        user=user,
    )


@router.post(
    "/dashboard/analysis/{analysis_id}/actions/run-anomaly",
    response_class=HTMLResponse,
)
def dashboard_run_anomaly(
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

    analysis = _get_visible_analysis(
        session,
        analysis_id=analysis_id,
        user=user,
    )

    result_json = (
        analysis.result_json
        if isinstance(
            analysis.result_json,
            dict,
        )
        else {}
    )

    events = _extract_events(
        result_json
    )

    result = detect_event_anomalies(
        events,
        contamination=(
            DEFAULT_CONTAMINATION
        ),
    )

    save_anomaly_run(
        session,
        analysis_id=analysis.id,
        requested_by_user_id=user.id,
        result=result,
    )

    return _render_workspace_content(
        request,
        session,
        analysis=analysis,
        user=user,
        action_message=(
            "Anomaly detection completed "
            "and the result was persisted."
        ),
    )


@router.post(
    "/dashboard/analysis/{analysis_id}/actions/generate-report",
    response_class=HTMLResponse,
)
def dashboard_generate_report(
    analysis_id: str,
    request: Request,
    session: DatabaseSession,
    enqueue_report: ReportEnqueuer,
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

    analysis = _get_visible_analysis(
        session,
        analysis_id=analysis_id,
        user=user,
    )

    latest = (
        get_latest_investigation_report(
            session,
            analysis_id=analysis.id,
        )
    )

    if (
        latest is not None
        and latest.status
        == InvestigationReportStatus.PENDING.value
    ):
        return _render_workspace_content(
            request,
            session,
            analysis=analysis,
            user=user,
            action_message=(
                "An AI investigation is "
                "already queued."
            ),
        )

    record = create_pending_report(
        session,
        analysis_id=analysis.id,
        requested_by_user_id=user.id,
    )

    try:
        enqueue_report(
            record.id
        )
    except Exception:
        fail_report(
            session,
            record=record,
            error_message=(
                "The investigation could "
                "not be queued for "
                "background processing."
            ),
        )

        return _render_workspace_content(
            request,
            session,
            analysis=analysis,
            user=user,
            action_error=(
                "The AI investigation "
                "queue is unavailable."
            ),
        )

    return _render_workspace_content(
        request,
        session,
        analysis=analysis,
        user=user,
        action_message=(
            "AI investigation queued. "
            "This page will refresh "
            "automatically while it runs."
        ),
    )


@router.post(
    "/dashboard/analysis/{analysis_id}/actions/link-case",
    response_class=HTMLResponse,
)
def dashboard_link_case(
    analysis_id: str,
    request: Request,
    session: DatabaseSession,
    case_id: Annotated[
        str,
        Form(),
    ],
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

    analysis = _get_visible_analysis(
        session,
        analysis_id=analysis_id,
        user=user,
    )

    case_record = get_case(
        session,
        case_id=case_id,
        user_id=user.id,
        is_admin=_is_admin(user),
    )

    if case_record is None:
        return _render_workspace_content(
            request,
            session,
            analysis=analysis,
            user=user,
            action_error=(
                "The selected case could "
                "not be found."
            ),
        )

    link = link_analysis_to_case(
        session,
        case_record=case_record,
        analysis=analysis,
        actor_user_id=user.id,
    )

    if link is None:
        return _render_workspace_content(
            request,
            session,
            analysis=analysis,
            user=user,
            action_message=(
                "This analysis is already "
                "linked to that case."
            ),
        )

    return _render_workspace_content(
        request,
        session,
        analysis=analysis,
        user=user,
        action_message=(
            f"Analysis linked to case "
            f"'{case_record.title}'."
        ),
    )


@router.post(
    "/dashboard/analysis/{analysis_id}/actions/create-case",
    response_class=HTMLResponse,
)
def dashboard_create_case(
    analysis_id: str,
    request: Request,
    session: DatabaseSession,
    title: Annotated[
        str,
        Form(
            min_length=1,
            max_length=200,
        ),
    ],
    severity: Annotated[
        CaseSeverity,
        Form(),
    ] = CaseSeverity.MEDIUM,
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

    analysis = _get_visible_analysis(
        session,
        analysis_id=analysis_id,
        user=user,
    )

    case_record = create_case(
        session,
        title=title,
        description=(
            "Created from security "
            f"analysis {analysis.id}."
        ),
        severity=severity,
        created_by_user_id=user.id,
        assigned_to_user_id=None,
    )

    link_analysis_to_case(
        session,
        case_record=case_record,
        analysis=analysis,
        actor_user_id=user.id,
    )

    return _render_workspace_content(
        request,
        session,
        analysis=analysis,
        user=user,
        action_message=(
            f"Case '{case_record.title}' "
            "created and linked."
        ),
    )
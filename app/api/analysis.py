from pathlib import Path
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from app.api.schemas import (
    AnalysisHistoryResponse,
    AnalysisHistorySummaryResponse,
    AnalysisResponse,
    AnalysisSubmissionResponse,
    LogAnalysisRequest,
)
from app.core.database import get_database_session
from app.models.analysis import AnalysisResult
from app.models.analysis_record import AnalysisRecord
from app.services.analysis_history_service import (
    get_analysis_record,
    list_analysis_records,
    save_analysis_result,
)
from app.services.analysis_service import analyse_auth_log


router = APIRouter(
    prefix="/analysis",
    tags=["analysis"],
)

MAX_UPLOAD_BYTES = 1_000_000

ALLOWED_FILE_SUFFIXES = {
    ".log",
    ".txt",
}


def run_analysis(content: str) -> AnalysisResult:
    """Run log analysis and translate domain errors into API errors."""

    try:
        return analyse_auth_log(content)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(error),
        ) from error


def create_submission_response(
    result: AnalysisResult,
    record: AnalysisRecord,
) -> AnalysisSubmissionResponse:
    """Combine analysis output with persistence metadata."""

    analysis_response = AnalysisResponse.model_validate(
        result
    )

    return AnalysisSubmissionResponse(
        **analysis_response.model_dump(),
        analysis_id=record.id,
        created_at=record.created_at,
        source_type=record.source_type,
        source_name=record.source_name,
    )


def create_history_summary(
    record: AnalysisRecord,
) -> AnalysisHistorySummaryResponse:
    """Convert a database record into an API history summary."""

    return AnalysisHistorySummaryResponse(
        analysis_id=record.id,
        created_at=record.created_at,
        source_type=record.source_type,
        source_name=record.source_name,
        total_lines=record.total_lines,
        ignored_lines=record.ignored_lines,
        event_count=record.event_count,
        incident_count=record.incident_count,
    )


@router.post(
    "/auth-log",
    response_model=AnalysisSubmissionResponse,
    status_code=status.HTTP_200_OK,
)
def analyse_authentication_log(
    request: LogAnalysisRequest,
    session: Annotated[
        Session,
        Depends(get_database_session),
    ],
) -> AnalysisSubmissionResponse:
    """Analyse submitted authentication-log text and persist it."""

    result = run_analysis(request.content)

    record = save_analysis_result(
        session,
        result,
        source_type="text",
    )

    return create_submission_response(
        result,
        record,
    )


@router.post(
    "/auth-log/file",
    response_model=AnalysisSubmissionResponse,
    status_code=status.HTTP_200_OK,
)
async def analyse_authentication_log_file(
    file: Annotated[
        UploadFile,
        File(),
    ],
    session: Annotated[
        Session,
        Depends(get_database_session),
    ],
) -> AnalysisSubmissionResponse:
    """Analyse an uploaded authentication-log file and persist it."""

    filename = file.filename or ""
    file_suffix = Path(filename).suffix.lower()

    try:
        if file_suffix not in ALLOWED_FILE_SUFFIXES:
            raise HTTPException(
                status_code=(
                    status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
                ),
                detail=(
                    "Only .log and .txt files are supported."
                ),
            )

        file_bytes = await file.read(
            MAX_UPLOAD_BYTES + 1
        )

        if len(file_bytes) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=(
                    "Uploaded file must not exceed 1 MB."
                ),
            )

        try:
            content = file_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise HTTPException(
                status_code=(
                    status.HTTP_422_UNPROCESSABLE_CONTENT
                ),
                detail=(
                    "Uploaded file must contain valid UTF-8 text."
                ),
            ) from error

        result = run_analysis(content)

        record = save_analysis_result(
            session,
            result,
            source_type="file",
            source_name=filename,
        )

        return create_submission_response(
            result,
            record,
        )
    finally:
        await file.close()


@router.get(
    "/history",
    response_model=list[AnalysisHistorySummaryResponse],
    status_code=status.HTTP_200_OK,
)
def get_analysis_history(
    session: Annotated[
        Session,
        Depends(get_database_session),
    ],
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=100,
        ),
    ] = 20,
    offset: Annotated[
        int,
        Query(
            ge=0,
        ),
    ] = 0,
) -> list[AnalysisHistorySummaryResponse]:
    """Return persisted analyses from newest to oldest."""

    records = list_analysis_records(
        session,
        limit=limit,
        offset=offset,
    )

    return [
        create_history_summary(record)
        for record in records
    ]


@router.get(
    "/history/{analysis_id}",
    response_model=AnalysisHistoryResponse,
    status_code=status.HTTP_200_OK,
)
def get_analysis_history_record(
    analysis_id: str,
    session: Annotated[
        Session,
        Depends(get_database_session),
    ],
) -> AnalysisHistoryResponse:
    """Return one complete persisted analysis."""

    record = get_analysis_record(
        session,
        analysis_id,
    )

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis record not found.",
        )

    summary = create_history_summary(record)

    return AnalysisHistoryResponse(
        **summary.model_dump(),
        result=AnalysisResponse.model_validate(
            record.result_json
        ),
    )
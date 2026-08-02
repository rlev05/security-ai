from pathlib import Path
from fastapi import APIRouter, File, HTTPException, UploadFile, status
from app.api.schemas import AnalysisResponse, LogAnalysisRequest
from app.services.analysis_service import analyse_auth_log

router = APIRouter(
    prefix="/analysis",
    tags=["analysis"],
)

MAX_UPLOAD_BYTES = 1_000_000
ALLOWED_FILE_SUFFIXES = {".log", ".txt"}

def create_analysis_response(content: str) -> AnalysisResponse:
    """ Run the analysis pipelineand convert the result for the api"""

    try:
        result = analyse_auth_log(content)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(error),
        ) from error

    return AnalysisResponse.model_validate(result)

@router.post(
    "/auth-log",
    response_model=AnalysisResponse,
    status_code=status.HTTP_200_OK,
)
def analyse_authentication_log(
        request: LogAnalysisRequest,
) -> AnalysisResponse:
    return create_analysis_response(request.content)

@router.post(
    "/auth-log/file",
    response_model=AnalysisResponse,
    status_code=status.HTTP_200_OK,
)
async def analyse_authentication_log_file(
        file: UploadFile = File(...),
) -> AnalysisResponse:
    filename = file.filename or ""
    file_suffix = Path(filename).suffix.lower()

    if file_suffix not in ALLOWED_FILE_SUFFIXES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Only .log and .txt files are allowed"
        )
    file_bytes = await file.read(MAX_UPLOAD_BYTES + 1)

    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Uploaded file must not exceed 1 MB.",
        )

    try:
        content = file_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Uploaded file must contain valid UTF-8 text.",
        ) from error
    finally:
        await file.close()

    return create_analysis_response(content)

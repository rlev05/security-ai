from fastapi import APIRouter, HTTPException, status
from app.api.schemas import AnalysisResponse, LogAnalysisRequest
from app.services.analysis_service import analyse_auth_log

router = APIRouter(
    prefix="/analysis",
    tags=["analysis"],
)


@router.post(
    "/auth-log",
    response_model=AnalysisResponse,
    status_code=status.HTTP_200_OK,
)
def analyse_authentication_log(
        request: LogAnalysisRequest,
) -> AnalysisResponse:
    try:
        result = analyse_auth_log(request.content)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(error),
        ) from error

    return AnalysisResponse.model_validate(result)




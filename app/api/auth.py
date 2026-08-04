from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.api.auth_dependencies import get_current_user
from app.api.auth_schemas import (
    TokenResponse,
    UserCreateRequest,
    UserResponse,
)
from app.core.database import get_database_session
from app.models.user_record import UserRecord
from app.services.security_service import create_access_token
from app.services.user_service import (
    UserAlreadyExistsError,
    authenticate_user,
    create_user,
)


router = APIRouter(
    prefix="/auth",
    tags=["authentication"],
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_user(
    request: UserCreateRequest,
    session: Annotated[
        Session,
        Depends(get_database_session),
    ],
) -> UserRecord:
    """Register a new user account."""

    try:
        return create_user(
            session,
            email=str(request.email),
            username=request.username,
            password=request.password,
        )
    except UserAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@router.post(
    "/token",
    response_model=TokenResponse,
)
def issue_access_token(
    form_data: Annotated[
        OAuth2PasswordRequestForm,
        Depends(),
    ],
    session: Annotated[
        Session,
        Depends(get_database_session),
    ],
) -> TokenResponse:
    """Authenticate a user and issue an access token."""

    user = authenticate_user(
        session,
        login=form_data.username,
        password=form_data.password,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    return TokenResponse(
        access_token=create_access_token(user.id),
    )


@router.get(
    "/me",
    response_model=UserResponse,
)
def read_current_user(
    current_user: Annotated[
        UserRecord,
        Depends(get_current_user),
    ],
) -> UserRecord:
    """Return the authenticated user's profile."""

    return current_user
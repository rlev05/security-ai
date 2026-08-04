from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy.testing.pickleable import User

from app.core.database import get_database_session
from app.models.user import UserRole
from app.models.user_record import UserRecord
from app.services.security_service import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

def get_current_user(
        token: Annotated[
            str, Depends(oauth2_scheme),
        ],
        session: Annotated[
            Session, Depends(get_database_session),
        ],
) -> UserRecord:
    """Return the user represented by the token"""

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication credentials",
        headers={
            "WWW-Authenticate": "Bearer",
        },
    )

    try:
        user_id = decode_access_token(token)
    except ValueError as exc:
        raise credentials_exception from exc

    user = session.get(
        UserRecord,
        user_id,
    )

    if user is None or not user.is_active:
        raise credentials_exception

    return user

def require_admin(
        current_user: Annotated[
            User, Depends(get_current_user),
        ],
) -> UserRecord:
    """Require the current user to have admin role"""

    if current_user.role != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access is required",
        )
    return current_user


from sqlalchemy import or_, select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.models.user import UserRole
from app.models.user_record import UserRecord
from app.services.security_service import hash_pashword, verify_password


class UserAlreadyExistsError(ValueError):
    """Raised when the user is already registered"""

def normalise_email(email: str) -> str:
    """Prepare an email address for storage and comparison"""

    return email.strip().lower()


def normalise_username(username: str) -> str:
    """Prepare an email address for storage and comparison"""
    return username.strip().lower()


def create_user(
        session: Session,
        *,
        email: str,
        username: str,
        password: str,
        role: UserRole = UserRole.USER,
) -> UserRecord:
    """Create and store a user account"""

    normalised_email = normalise_email(email)
    normalised_username = normalise_username(username)

    statement = select(UserRecord).where(
        or_(
            UserRecord.email == normalised_email,
            UserRecord.username == normalised_username,
        )
    )

    existing_user = session.scalar(statement)

    if existing_user is not None:
        if existing_user.email == normalised_email:
            raise UserAlreadyExistsError(
                "A user with this email address already exists."
            )

        raise UserAlreadyExistsError(
            "A user with this email address already exists."
        )

    user = UserRecord(
        email=normalised_email,
        username=normalised_username,
        password_hash=hash_pashword(password),
        role=role.value,
    )

    try:
        session.add(user)
        session.commit()
        session.refresh(user)
    except IntegrityError as exc:
        session.rollback()

        raise UserAlreadyExistsError(
            "A user with this email address or username already exists"
        ) from exc
    except Exception:
        session.rollback()
        raise

    return user


def get_user_by_login(
        session: Session,
        login: str,
) -> UserRecord | None:
    """Find a user by email address or username"""

    normalised_login = login.strip().lower()

    statement = select(UserRecord).where(
        or_(
            UserRecord.email == normalised_login,
            UserRecord.username == normalised_login,
        )
    )

    return session.scalar(statement)

def authenticate_user(
        session: Session,
        *,
        login: str,
        password: str,
) -> UserRecord | None:
    """Check login details"""

    user = get_user_by_login(session, login)

    if user is None:
        return None

    if not user.is_active:
        return None

    if not verify_password(
        password,
        user.password_hash,
    ):
        return None

    return user



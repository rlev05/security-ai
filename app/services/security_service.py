from datetime import datetime, timedelta, timezone
import jwt
from jwt import InvalidTokenError
from pwdlib import PasswordHash
from app.core.config import get_settings


password_hasher = PasswordHash.recommended()


def hash_pashword(password: str) -> str:
    """Create a secure Argon2 password hash"""

    return password_hasher.hash(password)


def verify_password(
        password: str,
        password_hash: str,
) -> bool:
    """Verify a password against a stored hash"""

    return password_hasher.verify(
        password,
        password_hash,
    )


def create_access_token(user_id: str) -> str:
    """Created a signed access token for a user"""

    settings = get_settings()

    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.access_token_expire_minutes
    )

    payload = {
        "sub": user_id,
        "type": "access",
        "exp": expires_at,
    }

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

def decode_access_token(token: str) -> str:
    """Decode a signed access token"""

    settings = get_settings()

    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except InvalidTokenError as exc:
        raise ValueError("Invalid or expired access token"
                         ) from exc

    if payload.get("type") != "access":
        raise ValueError("Invalid token type")

    user_id = payload.get("sub")

    if not isinstance(user_id, str) or not user_id:
        raise ValueError("Access token does not contain a valid user ID")

    return user_id



from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base

def generate_uuid() -> str:
    return str(uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AnomalyRunRecord(Base):
    """Persisted snapshot of one ML detection run"""

    __tablename__ = "anomaly_runs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )

    analysis_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey(
            "analysis_records.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    requested_by_user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    model_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    model_version: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    contamination: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )

    total_events: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    analysed_events: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    anomaly_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    result_json: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
        index=True,
    )


    
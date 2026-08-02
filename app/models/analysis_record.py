from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


def generate_uuid() -> str:
    """Generate a UUID suitable for use as a public record id"""
    return str(uuid4())



def utc_now() -> datetime:
    """Return Current time """

    return datetime.now(timezone.utc)

class AnalysisRecord(Base):
    """Persisted snap  of one completed security analysis"""

    __tablename__ = "analysis_records"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
        index=True,
    )

    source_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    source_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    total_lines: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    ignored_lines: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    event_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    incident_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    result_json: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
    )
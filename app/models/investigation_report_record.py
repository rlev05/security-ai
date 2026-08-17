import uuid
from datetime import datetime
from typing import Any
from sqlalchemy import DateTime, ForeignKey, JSON, String, func
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base
from app.models.investigation_report import InvestigationReportStatus

def generate_investigation_report_id() -> str:
    return str(uuid.uuid4())

class InvestigationReportRecord(Base):
    __tablename__ = 'investigation_reports'

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_investigation_report_id,
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

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=InvestigationReportStatus.PENDING.value,
        server_default=InvestigationReportStatus.PENDING.value,
    )

    provider: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    model: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    report_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )

    grounding_json: Mapped[
        dict[str, Any] | None
    ] = mapped_column(
        JSON,
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


import uuid
from datetime import datetime
from typing import Any
from sqlalchemy import DateTime, JSON, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base

def generate_threat_intel_record_id() -> str:
    return str(uuid.uuid4())

class ThreatIntelEnrichmentRecord(Base):
    __tablename__ = "threat_intel_enrichment_record"

    __table_args__ = (
        UniqueConstraint(
            "provider",
            "indicator_type",
            "indicator_value",
            name=(
                "uq_threat_intel_provider_indicator"
            ),
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_threat_intel_record_id,
    )

    provider: Mapped[str] = mapped_column(
        String(50),
        nullable = False,
        index=True,
    )

    indicator_type: Mapped[str] = mapped_column(
        String(30),
        nullable = False,
        index=True,
    )

    indicator_value: Mapped[str] = mapped_column(
        String(255),
        nullable = False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable = False,
    )

    result_json: Mapped[
        dict[str, Any] | None
    ] = mapped_column(
        JSON,
        nullable = True,
    )

    error_message: Mapped[str | None] = mapped_column(
        String(500),
        nullable = True,
    )

    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable = False,
        server_default=func.now(),
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable = False,
    )



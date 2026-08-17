from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.grounding import validate_and_normalise_grounded_report

from app.ai.provider import (
    AIProviderError,
    InvestigationReportProvider,
)
from app.ai.schemas import AnalysisEvidence
from app.knowledge.attack_repository import AttackKnowledgeRepository
from app.models.analysis_record import AnalysisRecord
from app.models.investigation_report import (
    InvestigationReportStatus,
)
from app.models.investigation_report_record import (
    InvestigationReportRecord,
)


def build_analysis_evidence(
    analysis: AnalysisRecord,
    repository: AttackKnowledgeRepository,
) -> AnalysisEvidence:
    """Convert a stored analysis into evidence for the AI provider."""

    attack_context = (
        repository.build_grounding_context(
            analysis.result_json
        )
    )

    return AnalysisEvidence(
        analysis_id=analysis.id,
        source_type=analysis.source_type,
        source_name=analysis.source_name,
        total_lines=analysis.total_lines,
        ignored_lines=analysis.ignored_lines,
        result=analysis.result_json,
        attack_context=attack_context
    )


def create_pending_report(
    session: Session,
    *,
    analysis_id: str,
    requested_by_user_id: str,
    provider: InvestigationReportProvider,
) -> InvestigationReportRecord:
    """Create a pending investigation-report record."""

    record = InvestigationReportRecord(
        analysis_id=analysis_id,
        requested_by_user_id=requested_by_user_id,
        status=InvestigationReportStatus.PENDING.value,
        provider=provider.provider_name,
        model=provider.model_name,
    )

    try:
        session.add(record)
        session.commit()
        session.refresh(record)
    except Exception:
        session.rollback()
        raise

    return record


def complete_report(
    session: Session,
    *,
    record: InvestigationReportRecord,
    provider_name: str,
    model_name: str,
    report_json: dict[str, object],
    grounding_json: dict[str, object],
) -> InvestigationReportRecord:
    """Mark an investigation report as successfully completed."""

    record.status = InvestigationReportStatus.COMPLETED.value
    record.provider = provider_name
    record.model = model_name
    record.report_json = report_json
    record.grounding_json = grounding_json
    record.error_message = None
    record.completed_at = datetime.now(timezone.utc)

    try:
        session.commit()
        session.refresh(record)
    except Exception:
        session.rollback()
        raise

    return record


def fail_report(
    session: Session,
    *,
    record: InvestigationReportRecord,
    error_message: str,
) -> InvestigationReportRecord:
    """Mark an investigation-report attempt as failed."""

    record.status = InvestigationReportStatus.FAILED.value
    record.error_message = error_message[:500]
    record.completed_at = datetime.now(timezone.utc)

    try:
        session.commit()
        session.refresh(record)
    except Exception:
        session.rollback()
        raise

    return record


def generate_investigation_report(
    session: Session,
    *,
    analysis: AnalysisRecord,
    requested_by_user_id: str,
    provider: InvestigationReportProvider,
    repository: AttackKnowledgeRepository,
) -> InvestigationReportRecord:
    """Generate a grounded AI investigation report."""

    record = create_pending_report(
        session,
        analysis_id=analysis.id,
        requested_by_user_id=(
            requested_by_user_id
        ),
        provider=provider,
    )

    evidence = build_analysis_evidence(
        analysis,
        repository,
    )

    try:
        generated = provider.generate_report(
            evidence
        )

        grounded_report = (
            validate_and_normalise_grounded_report(
                generated.content,
                evidence.attack_context,
            )
        )
    except AIProviderError as exc:
        fail_report(
            session,
            record=record,
            error_message=str(exc),
        )

        raise

    return complete_report(
        session,
        record=record,
        provider_name=generated.provider,
        model_name=generated.model,
        report_json=(
            grounded_report.model_dump(
                mode="json"
            )
        ),
        grounding_json=(
            evidence.attack_context.model_dump(
                mode="json"
            )
        ),
    )


def get_latest_investigation_report(
    session: Session,
    *,
    analysis_id: str,
) -> InvestigationReportRecord | None:
    """Return the newest AI report attempt for an analysis."""

    statement = (
        select(InvestigationReportRecord)
        .where(
            InvestigationReportRecord.analysis_id
            == analysis_id
        )
        .order_by(
            InvestigationReportRecord.created_at.desc(),
            InvestigationReportRecord.id.desc(),
        )
        .limit(1)
    )

    return session.scalar(statement)
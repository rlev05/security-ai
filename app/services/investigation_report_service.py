from datetime import datetime, timezone
from app.ai.schemas import AnalysisEvidence, AnomalyEvidenceContext
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.services.anomaly_run_service import get_latest_anomaly_run, load_anomaly_result
from app.ai.grounding import (
    validate_and_normalise_grounded_report,
)
from app.ai.provider import (
    AIProviderError,
    InvestigationReportProvider,
)
from app.ai.schemas import AnalysisEvidence
from app.knowledge.attack_repository import (
    AttackKnowledgeRepository,
)
from app.models.analysis_record import AnalysisRecord
from app.models.investigation_report import (
    InvestigationReportStatus,
)
from app.models.investigation_report_record import (
    InvestigationReportRecord,
)

from app.intel.provider import (
    ThreatIntelProvider,
)
from app.intel.schemas import (
    ThreatIntelContext,
)
from app.ioc.extractor import (
    extract_indicators,
)
from app.services.threat_intel_service import (
    enrich_indicators,
)


def build_anomaly_evidence_context(
        session: Session,
        *,
        analysis_id: str,
) -> AnomalyEvidenceContext:
    """
    Build AI-ready anomaly evidence from the latest persisted
    ML run for an analysis.

    Investigation generation does not automatically retrain the
    anomaly model. Only previously persisted ML evidence is used.
    """

    record = get_latest_anomaly_run(
        session,
        analysis_id=analysis_id
    )

    if record is None:
        return AnomalyEvidenceContext()

    result = load_anomaly_result(record)

    return AnomalyEvidenceContext(
        run_id=record.id,
        created_at=record.created_at,
        result=result
    )

def build_analysis_evidence(
    analysis: AnalysisRecord,
    repository: AttackKnowledgeRepository,
    threat_intel_context: (
        ThreatIntelContext | None
    ) = None,
    anomaly_context: (
        AnomalyEvidenceContext | None
    ) = None,
) -> AnalysisEvidence:
    """Build AI evidence with trusted ATT&CK grounding."""

    attack_context = (
        repository.build_grounding_context(
            analysis.result_json
        )
    )

    if threat_intel_context is None:
        threat_intel_context = ThreatIntelContext()


    if anomaly_context is None:
        anomaly_context = AnomalyEvidenceContext()

    return AnalysisEvidence(
        analysis_id=analysis.id,
        source_type=analysis.source_type,
        source_name=analysis.source_name,
        total_lines=analysis.total_lines,
        ignored_lines=analysis.ignored_lines,
        result=analysis.result_json,
        attack_context=attack_context,
        threat_intel_context=threat_intel_context,
        anomaly_context=anomaly_context
    )


def create_pending_report(
    session: Session,
    *,
    analysis_id: str,
    requested_by_user_id: str,
) -> InvestigationReportRecord:
    """Create the database record before work is queued."""

    record = InvestigationReportRecord(
        analysis_id=analysis_id,
        requested_by_user_id=requested_by_user_id,
        status=InvestigationReportStatus.PENDING.value,
    )

    try:
        session.add(record)
        session.commit()
        session.refresh(record)
    except Exception:
        session.rollback()
        raise

    return record


def set_report_provider(
    session: Session,
    *,
    record: InvestigationReportRecord,
    provider: InvestigationReportProvider,
) -> InvestigationReportRecord:
    """Record which provider and model will process the job."""

    record.provider = provider.provider_name
    record.model = provider.model_name

    try:
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
    threat_intel_json: dict[str, object],
) -> InvestigationReportRecord:
    """Mark a report as successfully completed."""

    record.status = (
        InvestigationReportStatus.COMPLETED.value
    )

    record.provider = provider_name
    record.model = model_name

    record.report_json = report_json
    record.grounding_json = grounding_json
    record.threat_intel_json = threat_intel_json

    record.error_message = None

    record.completed_at = datetime.now(
        timezone.utc
    )

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
    """Mark a report attempt as failed."""

    record.status = (
        InvestigationReportStatus.FAILED.value
    )

    record.error_message = (
        error_message[:500]
    )

    record.completed_at = datetime.now(
        timezone.utc
    )

    try:
        session.commit()
        session.refresh(record)
    except Exception:
        session.rollback()
        raise

    return record


def process_investigation_report(
    session: Session,
    *,
    report_id: str,
    provider: InvestigationReportProvider,
    repository: AttackKnowledgeRepository,
    threat_intel_provider: (ThreatIntelProvider | None) = None,
    threat_intel_cache_ttl_hours: int = 24,
) -> InvestigationReportRecord | None:
    """Process an already-created pending investigation report.

    This function is intentionally independent of Celery so it can be
    tested deterministically without starting Redis or a worker.
    """

    record = session.get(
        InvestigationReportRecord,
        report_id,
    )

    if record is None:
        return None

    if (
        record.status
        != InvestigationReportStatus.PENDING.value
    ):
        return record

    analysis = session.get(
        AnalysisRecord,
        record.analysis_id,
    )

    if analysis is None:
        return fail_report(
            session,
            record=record,
            error_message=(
                "The analysis associated with this "
                "investigation report no longer exists."
            ),
        )

    set_report_provider(
        session,
        record=record,
        provider=provider,
    )

    threat_intel_context = ThreatIntelContext()

    if threat_intel_provider is not None:
        indicators = extract_indicators(analysis.result_json)

        threat_intel_context = (
            enrich_indicators(
                session,
                indicators=indicators,
                provider=threat_intel_provider,
                cache_ttl_hours=threat_intel_cache_ttl_hours,
            )
        )

    anomaly_context = (
        build_anomaly_evidence_context(
            session,
            analysis_id=analysis.id
        )
    )

    evidence = build_analysis_evidence(
        analysis,
        repository,
        threat_intel_context,
        anomaly_context,
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

        return record

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
        threat_intel_json=(
            evidence
            .threat_intel_context.model_dump(mode="json")
        )
    )


def get_investigation_report(
    session: Session,
    *,
    report_id: str,
) -> InvestigationReportRecord | None:
    return session.get(
        InvestigationReportRecord,
        report_id,
    )


def get_latest_investigation_report(
    session: Session,
    *,
    analysis_id: str,
) -> InvestigationReportRecord | None:
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
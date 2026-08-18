import logging
from app.ai.dependencies import get_ai_provider
from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.knowledge.dependencies import get_attack_repository
from app.models.investigation_report import InvestigationReportStatus
from app.models.investigation_report_record import InvestigationReportRecord
from app.services.investigation_report_service import fail_report, process_investigation_report


logger = logging.getLogger(__name__)

@celery_app.task(
    name="security_ai.generate_investigation_report",
)
def generate_investigation_report_task(
        report_id: str,
) -> None:
    """Generate one persisted AI investigation report."""

    session = SessionLocal()

    try:
        report = session.get(
            InvestigationReportRecord,
            report_id
        )

        if report is None:
            logger.warning(
                "Investigation report %s no longer exists.",
                report_id
            )
            return

        if (
            report.status
            != InvestigationReportStatus.PENDING.value
        ):
            logger.info(
                "Investigation report %s is already %s",
                report_id,
                report.status,
            )
            return

        provider = get_ai_provider()
        repository = get_attack_repository()

        process_investigation_report(
            session,
            report_id=report_id,
            provider=provider,
            repository=repository,
        )

    except Exception:
        session.rollback()

        report = session.get(
            InvestigationReportRecord,
            report_id
        )

        if (
            report is not None
            and report.status == InvestigationReportStatus.PENDING.value
        ):
            try:
                fail_report(
                    session,
                    record=report,
                    error_message=(
                        "The background investigation job "
                        "failed unexpectedly."
                    ),
                )
            except Exception:
                logger.exception(
                    "Could not persist failure status for "
                    "investigation report %s.",
                    report_id,
                )
        logger.exception(
            "Unexpected failure while processing "
            "investigation report %s.",
            report_id,
        )

        raise
    finally:
        session.close()



from _collections_abc import Callable
from app.tasks.investigation_reports import generate_investigation_report_task

ReportEnqueuer = Callable[[str], None]

def enqueue_investigation_report(
        report_id: str,
) -> None:
    """Submit an investigation report to Celery"""

    generate_investigation_report_task.delay(report_id)


def get_report_enqueuer() -> ReportEnqueuer:
    """FastAPI dependency for queue submission"""

    return enqueue_investigation_report



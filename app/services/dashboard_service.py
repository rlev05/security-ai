from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.analysis_record import AnalysisRecord


@dataclass(frozen=True)
class DashboardMetrics:
    analyses: int
    events: int
    incidents: int
    ignored_lines: int


def get_dashboard_metrics(session: Session, *, owner_user_id: str) -> DashboardMetrics:
    statement = select(
        func.count(AnalysisRecord.id),
        func.coalesce(func.sum(AnalysisRecord.event_count), 0),
        func.coalesce(func.sum(AnalysisRecord.incident_count), 0),
        func.coalesce(func.sum(AnalysisRecord.ignored_lines), 0),
    ).where(AnalysisRecord.owner_user_id == owner_user_id)

    row = session.execute(statement).one()

    return DashboardMetrics(
        analyses=int(row[0]),
        events=int(row[1]),
        incidents=int(row[2]),
        ignored_lines=int(row[3]),
    )

from datetime import datetime, timedelta, timezone
from sqlalchemy import or_, select
from sqlalchemy.orm import Session
from app.models.analysis_record import AnalysisRecord
from app.models.case import CaseSeverity, CaseStatus, CaseTimelineEventType
from app.models.case_record import CaseRecord, CaseAnalysisLink, CaseNoteRecord, CaseTimelineEventRecord
from app.models.user_record import UserRecord

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _commit_and_refresh(
        session: Session,
        record,
):
    """Commit a change and refresh the supplied ORM record"""

    try:
        session.commit()
        session.refresh(record)
    except Exception:
        session.rollback()
        raise
    return record


def _add_timeline_event(
        session: Session,
        *,
        case_id: str,
        event_type: CaseTimelineEventRecord,
        actor_user_id: str | None,
        event_json: dict[str, object] | None = None,
) ->  CaseTimelineEventRecord:
    """Add an append-only event to a case timeline"""

    event = CaseTimelineEventRecord(
        case_id=case_id,
        event_type=event_type.value,
        actor_user_id=actor_user_id,
        event_json=event_json or {},
    )

    session.add(event)

    return event


def create_case(
        session: Session,
        *,
        title: str,
        description: str | None,
        severity: CaseSeverity,
        created_by_user_id: str,
        assigned_to_user_id: str | None = None,
) -> CaseRecord:
    """CReate a new analyst case"""


    record = CaseRecord(
        title=title,
        description=description,
        severity=severity.value,
        status=CaseStatus.OPEN.value,
        created_by_user_id=created_by_user_id,
        assigned_to_user_id=assigned_to_user_id,
    )

    session.add(record)

    session.flush()

    _add_timeline_event(
        session,
        case_id=record.id,
        event_type=CaseTimelineEventType.CASE_CREATED,
        actor_user_id=created_by_user_id,
        event_json={
            "severity": severity.value,
            "assigned_to_user_id": assigned_to_user_id,
        }
    )

    return _commit_and_refresh(session, record)


def get_case(
        session: Session,
        *,
        case_id: str,
        user_id: str,
        is_admin: bool,
) -> CaseRecord | None:
    """Return a case visible to the supplied user"""

    statement = (
        select(CaseRecord).where(CaseRecord.id == case_id)
    )

    if not is_admin:
        statement = statement.where(
            or_(
                CaseRecord.created_by_user_id == user_id,
                CaseRecord.assigned_to_user_id == user_id,
            )
        )

    return session.scalar(statement)

def list_cases(
        session: Session,
        *,
        user_id: str,
        is_admin: bool,
) -> list[CaseRecord]:
    """List cases visible to a user"""

    status = select(CaseRecord)

    if not is_admin:
        statement = status.where(
            or_(
                CaseRecord.created_by_user_id == user_id,
                CaseRecord.assigned_to_user_id == user_id,
            )
        )

    statement = statement.order_by(
        CaseRecord.updated_at.desc(),
        CaseRecord.created_at.desc(),
    )

    return list(
        session.scalars(statement).all()
    )


def get_case_analysis_links(
        session: Session,
        *,
        case_id: str,
) -> list[CaseAnalysisLink]:
    """Return analysis links for a case"""

    statement = (
        select(AnalysisRecord)
        .join(
            CaseAnalysisLink,
            CaseAnalysisLink.analysis_id == AnalysisRecord.id,
        )
        .where(
            CaseAnalysisLink.case_id == case_id,
        )
        .order_by(
            AnalysisRecord.created_at.asc(),
        )
    )

    return list(
        session.scalars(statement).all()
    )


def link_analysis_to_case(
    session: Session,
    *,
    case_record: CaseRecord,
    analysis: AnalysisRecord,
    actor_user_id: str,
) -> CaseAnalysisLink | None:
    """Link an analysis to a case.

    Returns None when the analysis is already linked.
    """

    statement = select(
        CaseAnalysisLink
    ).where(
        CaseAnalysisLink.case_id
        == case_record.id,
        CaseAnalysisLink.analysis_id
        == analysis.id,
    )

    existing = session.scalar(
        statement
    )

    if existing is not None:
        return None

    link = CaseAnalysisLink(
        case_id=case_record.id,
        analysis_id=analysis.id,
        linked_by_user_id=actor_user_id,
    )

    session.add(link)

    _add_timeline_event(
        session,
        case_id=case_record.id,
        event_type=(
            CaseTimelineEventType.ANALYSIS_LINKED
        ),
        actor_user_id=actor_user_id,
        event_json={
            "analysis_id": analysis.id,
            "source_type": (
                analysis.source_type
            ),
            "source_name": (
                analysis.source_name
            ),
        },
    )

    case_record.updated_at = (
        _utc_now()
    )

    try:
        session.commit()
        session.refresh(link)
        session.refresh(case_record)

    except Exception:
        session.rollback()
        raise

    return link


def add_case_note(
        session: Session,
        *,
        case_record: CaseRecord,
        author_user_id: str,
        content: str
) -> CaseNoteRecord:
    """Append an analyst note to a case"""

    note = CaseNoteRecord(
        case_id=case_record.id,
        author_user_id=author_user_id,
        content=content,
    )

    session.add(note)

    session.flush()

    _add_timeline_event(
        session,
        case_id=case_record.id,
        event_type=(CaseTimelineEventType.NOTE_ADDED),
        actor_user_id=author_user_id,
        event_json={
            "note_id": note.id,
        }
    )

    case_record.updated_at = _utc_now()

    try:
        session.commit()
        session.refresh(note)
        session.refresh(case_record)
    except Exception:
        session.rollback()
        raise
    return note


def list_case_notes(
        session: Session,
        *,
        case_id: str,
) -> list[CaseNoteRecord]:
    """Return analyst notes for a case"""

    statement = (
        select(CaseNoteRecord)
        .where(CaseNoteRecord.case_id == case_id)
        .order_by(CaseNoteRecord.created_at.asc())
    )

    return list(session.scalars(statement).all())


def list_case_timeline(
        session: Session,
        *,
        case_id: str,
) -> list[CaseTimelineEventRecord]:
    """Return the chronological event timeline"""

    statement = (
        select(CaseTimelineEventRecord)
        .where(CaseTimelineEventRecord.case_id == case_id)
        .order_by(CaseTimelineEventRecord.created_at.asc())
    )

    return list(session.scalars(statement).all())


def assign_case(
        session: Session,
        *,
        case_record: CaseRecord,
        actor_user_id: str,
        assigned_to_user_id: str | None,
) -> CaseRecord:
    """Change the analyst assigned to a case"""

    previous_assignee = case_record.assigned_to_user_id

    if previous_assignee == assigned_to_user_id:
        return case_record

    case_record.assigned_to_user_id = assigned_to_user_id

    case_record.updated_at = _utc_now()

    _add_timeline_event(
        session,
        case_id=case_record.id,
        event_type=(CaseTimelineEventType.ASSIGNEE_CHANGED),
        actor_user_id=actor_user_id,
        event_json={
            "previous_assigned_to_user_id": previous_assignee,
            "assigned_to_user_id": assigned_to_user_id,
        }
    )

    return _commit_and_refresh(session, case_record)

def set_case_status(
        session: Session,
        *,
        case_record: CaseRecord,
        actor_user_id: str,
        new_status: CaseStatus
) -> CaseRecord:
    """Change case workflow status"""

    previous_status = case_record.status

    if previous_status == new_status.value:
        return case_record

    now = _utc_now()

    case_record.status = new_status.value

    case_record.updated_at = now

    if new_status == CaseStatus.CLOSED:
        case_record.closed_at = now
    elif previous_status == CaseStatus.CLOSED.value:
        case_record.closed_at = None

    _add_timeline_event(
        session,
        case_id=case_record.id,
        event_type=(
            CaseTimelineEventType.STATUS_CHANGED
        ),
        actor_user_id=actor_user_id,
        event_json={
            "previous_status": previous_status,
            "status": new_status.value,
        }
    )

    return _commit_and_refresh(session, case_record)


def set_case_severity(
        session: Session,
        *,
        case_record: CaseRecord,
        actor_user_id: str,
        new_severity: CaseSeverity
) -> CaseRecord:
    """Change the severity assigned to a case"""

    previous_severity = case_record.severity

    if previous_severity == new_severity.value:
        return case_record

    case_record.severity = new_severity.value

    case_record.updated_at = _utc_now()

    _add_timeline_event(
        session,
        case_id=case_record.id,
        event_type=(
            CaseTimelineEventType.SEVERITY_CHANGED
        ),
        actor_user_id=actor_user_id,
        event_json={
            "previous_severity": previous_severity,
            "severity": new_severity.value,
        }
    )

    return _commit_and_refresh(session, case_record)


def get_active_user(
        session: Session,
        *,
        user_id: str
) -> UserRecord | None:
    """Return an active user that can be assigned to a case"""

    statement = (
        select(UserRecord)
        .where(
            UserRecord.id == user_id,
            UserRecord.is_active.is_(True),
        )
    )

    return session.scalar(statement)




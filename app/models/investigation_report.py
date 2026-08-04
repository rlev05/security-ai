from enum import StrEnum


class InvestigationReportStatus(StrEnum):
    PENDING = 'pending'
    COMPLETED = 'completed'
    FAILED = 'failed'


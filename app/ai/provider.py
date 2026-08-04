from dataclasses import dataclass
from typing import Protocol
from app.ai.schemas import AnalysisEvidence, InvestigationReportContent

class AIProviderError(RuntimeError):
    """AI Provider error"""


class AIProviderUnavailableError(AIProviderError):
    """Raised when provider is unavailable"""


class AIProviderResponseError(AIProviderError):
    """Raised when a provider returns an unusable response."""


@dataclass(frozen=True, slots=True)
class GeneratedInvestigationReport:
    provider: str
    model: str
    content: InvestigationReportContent

class InvestigationReportProvider(Protocol):
    provider_name: str
    model_name: str

    def generate_report(self,
                        evidence: AnalysisEvidence,) -> GeneratedInvestigationReport:
        """Generate a structure report from evidence"""


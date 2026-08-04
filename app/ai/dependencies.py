from functools import lru_cache

from anyio.functools import lru_cache_items

from app.ai.openai_provider import OpenAIInvestigationProvider
from app.ai.provider import AIProviderUnavailableError, GeneratedInvestigationReport, InvestigationReportProvider
from app.ai.schemas import AnalysisEvidence
from app.core.config import get_settings


class DisabledInvestigationProvider:
    provider_name = "disabled"
    model_name = "none"

    def generate_report(self,
                        evidence: AnalysisEvidence,
                        ) -> GeneratedInvestigationReport:
        raise AIProviderUnavailableError(
            "AI report generation is not configured"
        )

@lru_cache
def get_ai_provider() -> InvestigationReportProvider:
    """Build and cache the configured AI provider"""

    settings = get_settings()

    if settings.ai_provider == "openai":
        if settings.openai_api_key is None:
            return DisabledInvestigationProvider()

        api_key = settings.openai_api_key.get_secret_value().strip()

        if not api_key:
            return DisabledInvestigationProvider()

        return OpenAIInvestigationProvider(
            api_key=api_key,
            model=settings.openai_model,
            timeout_seconds=settings.ai_request_timeout_seconds,
            max_input_characters=settings.ai_max_input_characters,
        )

    return DisabledInvestigationProvider()




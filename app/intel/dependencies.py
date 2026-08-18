from functools import lru_cache

from sqlalchemy import false

from app.core.config import get_settings
from app.intel.abuseipdb_provider import AbuseIPDBProvider
from app.intel.provider import ThreatIntelProvider, ThreatIntelProviderUnavailableError
from app.intel.schemas import IPReputation
from app.ioc.schemas import Indicator, IndicatorType


class DisabledThreatIntelProvider:
    provider_name = "disabled"

    def supports(self,
                 indicator_type: IndicatorType,
                 ) -> bool:

        return False

    def enrich(self,
               indicator: Indicator,
               ) -> IPReputation:
        raise ThreatIntelProviderUnavailableError(
            "Threat-intelligence enrichment is disabled."
        )


@lru_cache
def get_threat_intel_provider() -> (
    ThreatIntelProvider
):

    settings = get_settings()

    if (
        settings.threat_intel_provider == "abuseipdb"
    ):
        if (
            settings.abuseipdb_api_key
            is None
        ):
            return DisabledThreatIntelProvider()

        api_key = (
            settings.abuseipdb_api_key.get_secret_value().strip()
        )

        if not api_key:
            return DisabledThreatIntelProvider()

        return AbuseIPDBProvider(
            api_key=api_key,
            base_url=(settings.abuseipdb_base_url),
            timeout_seconds=settings.threat_intel_timeout_seconds,
            max_age_days=settings.abuseipdb_max_age_days,
        )

    return DisabledThreatIntelProvider()




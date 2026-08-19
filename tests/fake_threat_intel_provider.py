from app.intel.provider import ThreatIntelProviderUnavailableError
from app.intel.schemas import IPReputation
from app.ioc.schemas import Indicator, IndicatorType

class FakeThreatIntelProvider:
    provider_name = "fake-intel"

    def __init__(self) -> None:
        self.call_count = 0
        self.queried_values: list[str] = []


    def supports(self,
                 indicator_type: IndicatorType,) -> bool:

        return(
            indicator_type == IndicatorType.IP_ADDRESS
        )

    def enrich(self,
               indicator: Indicator) -> IPReputation:
        self.call_count += 1

        self.queried_values.append(indicator.value)

        return IPReputation(
            ip_address=indicator.value,
            abuse_confidence_score=87,
            is_public=True,
            ip_version=4,
            is_whitelisted=False,
            country_code="GB",
            usage_type="Data Center/Web Hosting/Transit",
            isp="Example ISP",
            domain="example.net",
            hostnames=[],
            is_tor=False,
            total_reports=42,
            num_distinct_users=12,
            last_reported_at=None,
        )

class FailingThreatIntelProvider(FakeThreatIntelProvider):

    provider_name = "failing-intel"

    def enrich(self,
               indicator: Indicator) -> IPReputation:

        self.call_count += 1

        raise ThreatIntelProviderUnavailableError("Threat intelligence unavailable.")

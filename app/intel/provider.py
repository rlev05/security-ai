from typing import Protocol
from app.intel.schemas import IPReputation
from app.ioc.schemas import Indicator, IndicatorType


class ThreatIntelProviderError(
    RuntimeError
):
    """Base threat-intelligence provider error."""


class ThreatIntelProviderUnavailableError(
    ThreatIntelProviderError
):
    """Provider could not be contacted."""


class ThreatIntelProviderResponseError(
    ThreatIntelProviderError
):
    """Provider returned an invalid response."""


class ThreatIntelProvider(Protocol):
    provider_name: str

    def supports(self, indicator_type: IndicatorType) -> bool:
        """Return whether this provider supports the indicator"""

    def enrich(self, indicator: Indicator) -> IPReputation:
        """Enrich one security indicator."""


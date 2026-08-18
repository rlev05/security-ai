from typing import Any
import httpx
from pydantic import ValidationError
from app.intel.provider import ThreatIntelProviderResponseError, ThreatIntelProviderUnavailableError, \
    ThreatIntelProvider
from app.intel.schemas import IPReputation
from app.ioc.schemas import Indicator, IndicatorType


class AbuseIPDBProvider:
    provider_name = "abuseipdb"

    def __init__(
            self,
            *,
            api_key: str,
            base_url: str,
            timeout_seconds: float,
            max_age_days: int,
    ) -> None:
        self.api_key = api_key
        self.max_age_days = max_age_days
        self.client = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout_seconds,
            headers={
                "Accept": "application/json",
                "Key": api_key,
            },
        )

    def supports(self,
                 indicator_type: IndicatorType) -> bool:
        return (
            indicator_type
            == IndicatorType.IP_ADDRESS
        )

    def enrich(self,
               indicator: Indicator,) -> IPReputation:
        if not self.supports(indicator.type):
            raise ThreatIntelProviderUnavailableError(
                "AbuseIPDB only supports IP address indicators."
            )

        try:
            response = self.client.get(
                "/check",
                params={
                    "ipAddress": indicator.value,
                    "maxAgeInDays": (self.max_age_days),
                },
            )

            response.raise_for_status()

        except (
            httpx.TimeoutException,
            httpx.NetworkError,
        ) as exc:
            raise ThreatIntelProviderUnavailableError(
                "AbuseIPDB rejected the enrichment request."
            ) from exc

        try:
            payload: Any = response.json()

            data = payload["data"]

            if not isinstance(
                data,
                dict,
            ):
                raise TypeError(
                    "data must be an object"
                )

            return IPReputation(
                ip_address=str(
                    data.get(
                        "ipAddress",
                        indicator.value,
                    )
                ),
                abuse_confidence_score=int(
                    data.get(
                        "abuseConfidenceScore",
                        0,
                    )
                ),
                is_public=data.get(
                    "isPublic"
                ),
                ip_version=data.get(
                    "ipVersion"
                ),
                is_whitelisted=data.get(
                    "isWhitelisted"
                ),
                country_code=data.get(
                    "countryCode"
                ),
                usage_type=data.get(
                    "usageType"
                ),
                isp=data.get(
                    "isp"
                ),
                domain=data.get(
                    "domain"
                ),
                hostnames=(
                    data.get(
                        "hostnames"
                    )
                    or []
                ),
                is_tor=data.get(
                    "isTor"
                ),
                total_reports=int(
                    data.get(
                        "totalReports",
                        0,
                    )
                ),
                num_distinct_users=int(
                    data.get(
                        "numDistinctUsers",
                        0,
                    )
                ),
                last_reported_at=data.get(
                    "lastReportedAt"
                ),
            )


        except (
            KeyError,
            TypeError,
            ValueError,
            ValidationError,
        ) as exc:
            raise ThreatIntelProviderResponseError(
                "AbuseIPDB returned an invalid response."
            ) from exc

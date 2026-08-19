import ipaddress
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.intel.provider import ThreatIntelProvider, ThreatIntelProviderError
from app.intel.schemas import IPReputation, ThreatIntelContext, ThreatIntelItem, ThreatIntelLookupStatus
from app.ioc.schemas import IndicatorType, Indicator
from app.models.threat_intel_record import ThreatIntelEnrichmentRecord


def is_public_ip(
        value: str,
) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False


    return address.is_global


def get_cached_environment(
        session: Session,
        *,
        provider_name: str,
        indicator: Indicator
) -> ThreatIntelEnrichmentRecord | None:
    now = datetime.now(timezone.utc)

    statement = (
        select(ThreatIntelEnrichmentRecord)
        .where(
            ThreatIntelEnrichmentRecord.provider == provider_name,
            ThreatIntelEnrichmentRecord.indicator_type == indicator.type.value,
            ThreatIntelEnrichmentRecord.indicator_value == indicator.value,
            ThreatIntelEnrichmentRecord.status == "completed",
            ThreatIntelEnrichmentRecord.expires_at > now,
        )
        .limit(1)
    )

    return session.scalar(statement)


def save_enrichment(
        session: Session,
        *,
        provider_name: str,
        indicator: Indicator,
        reputation: IPReputation,
        cache_ttl_hours: int,
) -> ThreatIntelEnrichmentRecord:
    now = datetime.now(timezone.utc)

    statement = (
        select(ThreatIntelEnrichmentRecord)
        .where(
            ThreatIntelEnrichmentRecord.provider == provider_name,
            ThreatIntelEnrichmentRecord.indicator_type == indicator.type.value,
            ThreatIntelEnrichmentRecord.indicator_value == indicator.value,
            ThreatIntelEnrichmentRecord.status == "completed",
            ThreatIntelEnrichmentRecord.expires_at > now,
        )
        .limit(1)
    )

    record = session.scalar(statement)

    if record is None:
        record = ThreatIntelEnrichmentRecord(
            provider=provider_name,
            indicator_type=(
                indicator.type.value
            ),
            indicator_value=(
                indicator.value
            ),
            status="completed",
            expires_at=(
                now
                + timedelta(
                    hours=cache_ttl_hours
                )
            ),
        )

        session.add(record)

    record.status = "completed"

    record.result_json = (
        reputation.model_dump(mode="json")
    )

    record.error_message = None
    record.checked_at = now

    record.expires_at = now + timedelta(hours=cache_ttl_hours)

    try:
        session.commit()
        session.refresh(record)
    except Exception:
        session.rollback()
        raise

    return record


def save_enrichment_failure(
        session: Session,
        *,
        provider_name: str,
        indicator: Indicator,
        error_message: str,
) -> ThreatIntelEnrichmentRecord:

    now = datetime.now(timezone.utc)

    statement = select(ThreatIntelEnrichmentRecord).where(
        ThreatIntelEnrichmentRecord.provider == provider_name,
        ThreatIntelEnrichmentRecord.indicator_type == indicator.type.value,
        ThreatIntelEnrichmentRecord.indicator_value == indicator.value,
    )

    record = session.scalar(statement)

    if record is None:
        record = ThreatIntelEnrichmentRecord(
            provider=provider_name,
            indicator_type=(indicator.type.value),
            indicator_value=(indicator.value),
            status="failed",
            expires_at=now,
        )

        session.add(record)


    record.status = "failed"
    record.result_json = None

    record.error_message = error_message[:500]

    record.checked_at = now
    record.expires_at = now

    try:
        session.commit()
        session.refresh(record)
    except Exception:
        session.rollback()
        raise

    return record


def enrich_indicators(
        session: Session,
        *,
        indicators: list[Indicator],
        provider: ThreatIntelProvider,
        cache_ttl_hours: int,
) -> ThreatIntelContext:
    """Enrich indicators without making provider failure fatal"""

    items: list[
        ThreatIntelItem
    ] = []

    for indicator in indicators:
        if not provider.supports(
                indicator.type
        ):
            items.append(
                ThreatIntelItem(
                    indicator=indicator,
                    status=(
                        ThreatIntelLookupStatus.SKIPPED
                    ),
                    provider=(
                        provider.provider_name
                    ),
                    reason=(
                        "The configured provider does "
                        "not support this indicator type."
                    ),
                )
            )

            continue


        if (indicator.type
            == IndicatorType.IP_ADDRESS
            and not is_public_ip(
                    indicator.value
                )
        ):
            items.append(
                ThreatIntelItem(
                    indicator=indicator,
                    status=(ThreatIntelLookupStatus.SKIPPED),
                    provider=(provider.provider_name),
                    reason=(
                        "Non-public IP addresses are "
                        "not sent to external providers."
                    ),
                )
            )

            continue

        cached = get_cached_environment(
            session,
            provider_name=provider.provider_name,
            indicator=indicator,
        )

        if cached is not None:
            reputation = (
                IPReputation.model_validate(
                    cached.result_json
                )
            )

            items.append(
                ThreatIntelItem(
                    indicator=indicator,
                    status=(ThreatIntelLookupStatus.CACHED),
                    provider=(provider.provider_name),
                    reputation=reputation,
                )
            )

            continue

        try:
            reputation = provider.enrich(indicator)

        except ThreatIntelProviderError as exc:
            save_enrichment_failure(
                session,
                provider_name=provider.provider_name,
                indicator=indicator,
                error_message=str(exc),
            )

            items.append(
                ThreatIntelItem(
                    indicator=indicator,
                    status=(ThreatIntelLookupStatus.FAILED),
                    provider=(provider.provider_name),
                    reason=str(exc),
                )
            )

            continue

        save_enrichment(
            session,
            provider_name=(provider.provider_name),
            indicator=indicator,
            reputation=reputation,
            cache_ttl_hours=(cache_ttl_hours),
        )

        items.append(
            ThreatIntelItem(
                indicator=indicator,
                status=(ThreatIntelLookupStatus.ENRICHED),
                provider=(provider.provider_name),
                reputation=reputation,
            )
        )

    return ThreatIntelContext(items=items)





            





from sqlalchemy.orm import Session
from app.intel.schemas import ThreatIntelLookupStatus
from app.ioc.schemas import IndicatorType, Indicator
from app.services.threat_intel_service import enrich_indicators
from tests.fake_threat_intel_provider import FakeThreatIntelProvider, FailingThreatIntelProvider


def test_public_ip_is_enriched(
        database_session: Session,
) -> None:
    provider = FakeThreatIntelProvider()

    context = enrich_indicators(
        database_session,
        indicators=[
            Indicator(
                type=IndicatorType.IP_ADDRESS,
                value="8.8.8.8",
            )
        ],
        provider=provider,
        cache_ttl_hours=24
    )

    assert len(context.items) == 1

    item = context.items[0]

    assert (
        item.status == ThreatIntelLookupStatus.ENRICHED
    )

    assert item.reputation is not None


    assert item.reputation.abuse_confidence_score == 87

    assert provider.call_count == 1

def test_private_ip_is_not_sent_externally(
        database_session: Session,
) -> None:
    provider = FakeThreatIntelProvider()

    context = enrich_indicators(
        database_session,
        indicators=[
            Indicator(
                type=IndicatorType.IP_ADDRESS,
                value="192.168.1.5",
            )
        ],
        provider=provider,
        cache_ttl_hours=24
    )

    assert provider.call_count == 0

    assert context.items[0].status == ThreatIntelLookupStatus.SKIPPED


def test_repeated_lookup_uses_cache(
        database_session: Session,
) -> None:
    provider = FakeThreatIntelProvider()

    indicator = Indicator(
        type=IndicatorType.IP_ADDRESS,
        value="8.8.8.8",
    )

    first = enrich_indicators(
        database_session,
        indicators=[indicator],
        provider=provider,
        cache_ttl_hours=24
    )

    second = enrich_indicators(
        database_session,
        indicators=[indicator],
        provider=provider,
        cache_ttl_hours=24
    )

    assert first.items[0].status == ThreatIntelLookupStatus.ENRICHED

    assert second.items[0].status == ThreatIntelLookupStatus.CACHED

    assert provider.call_count == 1


def test_unsupported_indicator_is_skipped(
        database_session: Session,
) -> None:
    provider = FakeThreatIntelProvider()

    context = enrich_indicators(
        database_session,
        indicators=[
            Indicator(
                type=IndicatorType.DOMAIN,
                value="example.com",
            )
        ],
        provider=provider,
        cache_ttl_hours=24
    )

    assert provider.call_count == 0
    assert context.items[0].status == ThreatIntelLookupStatus.SKIPPED

def test_provider_failure_does_not_raise(
        database_session: Session,
) -> None:
    provider = FailingThreatIntelProvider()

    context = enrich_indicators(
        database_session,
        indicators=[
            Indicator(
                type=IndicatorType.IP_ADDRESS,
                value="8.8.4.4",
            )
        ],
        provider=provider,
        cache_ttl_hours=24
    )

    assert len(context.items) == 1

    assert context.items[0].status == ThreatIntelLookupStatus.FAILED

    assert context.items[0].reason == "Threat intelligence unavailable."


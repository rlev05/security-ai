from app.ioc.extractor import extract_indicators
from app.ioc.schemas import Indicator, IndicatorType


def test_extracts_supported_indicators() -> None:
    sha256 = "a" * 64
    sha1 = "b" * 40
    md5 = "c" * 32

    result = {
        "events": [
            {
                "source_ip": "8.8.8.8",
                "raw_log": (
                    "Connection from 8.8.8.8 to "
                    "malware.example "
                    f"{sha256} "
                    f"{sha1} "
                    f"{md5}"
                )
            }
        ]
    }

    indicators = extract_indicators(result)

    assert (
        Indicator(
            type=IndicatorType.IP_ADDRESS,
            value="8.8.8.8",
        )
        in indicators
    )

    assert (
        Indicator(
            type=IndicatorType.DOMAIN,
            value="malware.example",
        )
        in indicators
    )

    assert (
        Indicator(
            type=IndicatorType.SHA256,
            value=sha256,
        )
        in indicators
    )

    assert (
        Indicator(
            type=IndicatorType.SHA1,
            value=sha1,
        )
        in indicators
    )

    assert (
        Indicator(
            type=IndicatorType.MD5,
            value=md5,
        )
        in indicators
    )


def test_deduplicates_indicators() -> None:
    result = {
        "source_ip": "8.8.8.8",
        "raw_log": (
            "8.8.8.8 repeated 8.8.8.8"
        ),
    }

    indicators = extract_indicators(result)

    matching = [
        indicator
        for indicator in indicators
        if (indicator.type == IndicatorType.IP_ADDRESS and indicator.value == "8.8.8.8")
    ]

    assert len(matching) == 1

def test_invalid_ip_is_not_extracted() -> None:
    result = {
        "source_ip": "999.999.999.999",
    }

    indicators = extract_indicators(
        result
    )

    assert indicators == []


def test_private_ip_is_still_extracted() -> None:
    result = {
        "source_ip": "192.168.1.10"
    }

    indicators = extract_indicators(
        result
    )


    assert Indicator(
        type=IndicatorType.IP_ADDRESS,
        value="192.168.1.10",
    ) in indicators


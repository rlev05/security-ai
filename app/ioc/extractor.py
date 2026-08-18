import ipaddress
import re
from typing import Any
from app.ioc.schemas import Indicator, IndicatorType

IPV4_PATTERN = re.compile(
    r"(?<![\d.])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?![\d.])"
)

DOMAIN_PATTERN = re.compile(
    r"(?<![@A-Za-z0-9_-])"
    r"(?:"
    r"[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"\."
    r")+"
    r"[A-Za-z]{2,63}"
    r"(?![A-Za-z0-9_-])"
)

SHA256_PATTERN = re.compile(
    r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])"
)

SHA1_PATTERN = re.compile(
    r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])"
)

MD5_PATTERN = re.compile(
    r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])"
)


IP_FIELD_NAMES = {
    "source_ip",
    "destination_ip",
    "src_ip",
    "dst_ip",
    "ip",
    "ip_address",
}


def normalise_ip(
        value: str,
) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def add_indicator(
        indicators: dict[
            tuple[IndicatorType, str],
            Indicator,
        ],
        *,
        indicator_type: IndicatorType,
        value: str,
) -> None:
    normalised_value = value.strip()

    if indicator_type == IndicatorType.IP_ADDRESS:
        parsed_ip = normalise_ip(normalised_value)
        if parsed_ip is None:
            return

        normalised_value = parsed_ip

    elif indicator_type == IndicatorType.DOMAIN:
        normalised_value = normalise_ip(normalised_value.rstrip(".").lower())

        try:
            ipaddress.ip_address(normalised_value)
            return
        except ValueError:
            pass

    else:
        normalised_value = (
            normalised_value.lower()
        )

    key = (
        indicator_type,
        normalised_value,
    )

    indicators[key] = Indicator(
        type=indicator_type,
        value=normalised_value,
    )

def extract_from_text(
        text: str,
        indicators: dict[
            tuple[IndicatorType, str],
            Indicator,
        ],
) -> None:
    for match in IPV4_PATTERN.finditer(text):
        add_indicator(
            indicators,
            indicator_type=(
                IndicatorType.IP_ADDRESS
            ),
            value=match.group(0),
        )

    for match in SHA256_PATTERN.finditer(text):
        add_indicator(
            indicators,
            indicator_type=(
                IndicatorType.SHA256
            ),
            value=match.group(0),
        )

    for match in SHA1_PATTERN.finditer(text):
        add_indicator(
            indicators,
            indicator_type=(
                IndicatorType.SHA1
            ),
            value=match.group(0),
        )

    for match in MD5_PATTERN.finditer(text):
        add_indicator(
            indicators,
            indicator_type=(
                IndicatorType.MD5
            ),
            value=match.group(0),
        )

    for match in DOMAIN_PATTERN.finditer(text):
        add_indicator(
            indicators,
            indicator_type=(
                IndicatorType.DOMAIN
            ),
            value=match.group(0),
        )


def extract_indicators(
        value: Any,
) -> list[Indicator]:
    """Extract supported indicators from analysis data"""

    indicators: dict[
        tuple[IndicatorType, str],
        Indicator,
    ] = {}

    def visit(
            current: Any,
            *,
            parent_key: str | None = None,
    ) -> None:
        if isinstance(current, dict):
            for key, child in current.items():
                if (
                    isinstance(child, str)
                    and key in IP_FIELD_NAMES
                ):
                    add_indicator(
                        indicators,
                        indicator_type=(
                            IndicatorType.IP_ADDRESS
                        ),
                        value=child,
                    )
                visit(child, parent_key=key)

            return

        if isinstance(current, list):
            for child in current:
                visit(child, parent_key=parent_key)

            return
        if isinstance(current, str):
            extract_from_text(current, indicators)

    visit(value)

    return sorted(
        indicators.values(),
        key=lambda indicator: (
            indicator.type.value,
            indicator.value,
        ),
    )








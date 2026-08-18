from enum import StrEnum
from pydantic import BaseModel, ConfigDict

class IndicatorType(StrEnum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"

class Indicator(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    type: IndicatorType
    value: str




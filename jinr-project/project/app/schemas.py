from pydantic import BaseModel
from datetime import datetime


class Summary(BaseModel):
    total_hits: int
    attacker_hits: int
    unique_ips: int
    attacker_unique_ips: int
    window_start: datetime
    window_end: datetime


class KindCount(BaseModel):
    attack_kind: str
    count: int


class IpCount(BaseModel):
    ip: str
    count: int
    country: str | None = None
    fraction: float


class CountryCount(BaseModel):
    country: str
    count: int


class CityCount(BaseModel):
    city: str
    count: int


class TimelinePoint(BaseModel):
    bucket: datetime
    count: int


class BotFraction(BaseModel):
    bucket: datetime
    fraction: float


class ExtendedSummary(BaseModel):
    attacker_hits: int
    fraction: float
    max_per_minute: int
    avg_top_three_hrs: int
    unique_ips: int
    unique_countries: int
    window_start: datetime
    window_end: datetime


class UserAgentCount(BaseModel):
    user_ag: str
    count: int


class MethodCount(BaseModel):
    methd: str
    count: int


class CountryFraction(BaseModel):
    country: str
    fraction: float

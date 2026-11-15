import geoip2.database
from .config import GEOIP_DB
import os

_reader = None

def _get_reader():
    global _reader
    if _reader is None and os.path.exists(GEOIP_DB):
        _reader = geoip2.database.Reader(GEOIP_DB)
    return _reader

def lookup(ip: str) -> tuple[str | None, str | None]:
    r = _get_reader()
    if not r:
        return None, None
    try:
        resp = r.city(ip)
        country = resp.country.name
        city = resp.city.name
        return country, city
    except Exception:
        return None, None

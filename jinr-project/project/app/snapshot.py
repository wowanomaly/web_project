from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from sqlalchemy import distinct, func

from .db import SessionLocal
from .models import Hit
from .schemas import (
    Summary, KindCount, IpCount, TimelinePoint, CountryCount, CityCount,
    BotFraction, ExtendedSummary, UserAgentCount, MethodCount, CountryFraction,
)

DATA_DIR = Path("/app/data")
MAX_ROWS = 500           # API allows up to 500; precompute that many

_pending: list[tuple[Path, Path]] = []   # (tmp, final) for atomic commit


def _stage(name: str, payload) -> None:
    """Write JSON to <name>.json.tmp; defer the rename to commit()."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    final = DATA_DIR / f"{name}.json"
    tmp = DATA_DIR / f"{name}.json.tmp"
    tmp.write_text(json.dumps(payload, ensure_ascii=False))
    _pending.append((tmp, final))


def _commit() -> None:
    """Rename every staged file atomically after all succeeded."""
    for tmp, final in _pending:
        os.replace(tmp, final)          # atomic on POSIX
    _pending.clear()


def _rollback() -> None:
    for tmp, _ in _pending:
        tmp.unlink(missing_ok=True)
    _pending.clear()


def _dump(models) -> list[dict]:
    """Pydantic models → JSON-safe dicts (datetime → ISO string)."""
    return [m.model_dump(mode="json") for m in models]


# ── one function per endpoint ────────────────────────────────────
def snap_summary(db):
    total = db.query(func.count(Hit.id)).scalar()
    atk   = db.query(func.count(Hit.id)).filter(Hit.is_attacker).scalar()
    uips  = db.query(func.count(distinct(Hit.ip))).scalar()
    auips = db.query(func.count(distinct(Hit.ip))).filter(Hit.is_attacker).scalar()
    first = db.query(func.min(Hit.ts)).scalar()
    last  = db.query(func.max(Hit.ts)).scalar()
    _stage("summary", Summary(
        total_hits=total, attacker_hits=atk,
        unique_ips=uips, attacker_unique_ips=auips,
        window_start=first, window_end=last,
    ).model_dump(mode="json"))


def snap_by_kind(db):
    rows = (
        db.query(Hit.attack_kind, func.count(Hit.id))
        .filter(Hit.is_attacker)
        .group_by(Hit.attack_kind)
        .all()
    )
    _stage("by-kind", _dump(KindCount(attack_kind=k, count=c) for k, c in rows))


def snap_top_ips(db):
    atk = db.query(func.count(Hit.id)).filter(Hit.is_attacker).scalar()
    rows = (
        db.query(Hit.ip, func.count(Hit.id), func.mode().within_group(Hit.country))
        .filter(Hit.is_attacker)
        .group_by(Hit.ip)
        .order_by(func.count(Hit.id).desc())
        .limit(MAX_ROWS)
        .all()
    )
    _stage("top-ips", _dump(
        IpCount(ip=ip, count=c, country=cn,
                fraction=(c / atk) * 100 if atk else 0.0)
        for ip, c, cn in rows
    ))


def snap_by_country(db):
    rows = (
        db.query(Hit.country, func.count(Hit.id))
        .filter(Hit.is_attacker, Hit.country.isnot(None))
        .group_by(Hit.country)
        .order_by(func.count(Hit.id).desc())
        .limit(MAX_ROWS)
        .all()
    )
    _stage("by-country", _dump(CountryCount(country=cn, count=c) for cn, c in rows))


def snap_by_city(db):
    rows = (
        db.query(Hit.city, func.count(Hit.id))
        .filter(Hit.is_attacker, Hit.city.isnot(None))
        .group_by(Hit.city)
        .order_by(func.count(Hit.id).desc())
        .limit(MAX_ROWS)
        .all()
    )
    _stage("by-city", _dump(CityCount(city=ci, count=c) for ci, c in rows))


def snap_timeline(db, interval: str):
    bucket = func.date_trunc(interval, Hit.ts)
    rows = (
        db.query(bucket.label("b"), func.count(Hit.id))
        .filter(Hit.is_attacker)
        .group_by("b")
        .order_by("b")
        .all()
    )
    _stage(f"timeline-{interval}",
           _dump(TimelinePoint(bucket=b, count=c) for b, c in rows))


def snap_bot_fraction(db, interval: str):
    bucket    = func.date_trunc(interval, Hit.ts).label("b")
    attackers = func.count(Hit.id).filter(Hit.is_attacker).label("attackers")
    total     = func.count(Hit.id).label("total")
    rows = (
        db.query(bucket, attackers, total)
        .group_by(bucket)
        .order_by(bucket)
        .all()
    )
    _stage(f"bot-fraction-{interval}",
           _dump(BotFraction(bucket=b, fraction=(a / t) * 100 if t else 0.0)
                 for b, a, t in rows))


def snap_extended_summary(db):
    atk        = db.query(func.count(Hit.id)).filter(Hit.is_attacker).scalar()
    total      = db.query(func.count(Hit.id)).scalar()
    auips      = db.query(func.count(distinct(Hit.ip))).filter(Hit.is_attacker).scalar()
    ucountries = db.query(func.count(distinct(Hit.country))).filter(Hit.is_attacker).scalar()
    first      = db.query(func.min(Hit.ts)).scalar()
    last       = db.query(func.max(Hit.ts)).scalar()

    minutes = (
        db.query(
            func.date_trunc("minute", Hit.ts).label("m"),
            func.count(Hit.id).label("c"),
        )
        .filter(Hit.is_attacker)
        .group_by("m")
        .subquery()
    )
    m_p_m = db.query(func.coalesce(func.max(minutes.c.c), 0)).scalar()

    top_hours = (
        db.query(
            func.date_trunc("hour", Hit.ts).label("h"),
            func.count(Hit.id).label("c"),
        )
        .filter(Hit.is_attacker)
        .group_by("h")
        .order_by(func.count(Hit.id).desc())
        .limit(3)
        .all()
    )
    counts   = [c for _, c in top_hours]
    a_t_th_h = sum(counts) / max(len(counts), 1)

    _stage("extended_summary", ExtendedSummary(
        attacker_hits=atk,
        fraction=(atk / total) * 100 if total else 0.0,
        max_per_minute=int(m_p_m),
        avg_top_three_hrs=int(a_t_th_h),
        unique_ips=auips, unique_countries=ucountries,
        window_start=first, window_end=last,
    ).model_dump(mode="json"))


def snap_by_user_agent(db):
    rows = (
        db.query(Hit.ua, func.count(Hit.id))
        .filter(Hit.is_attacker, Hit.ua.isnot(None))
        .group_by(Hit.ua)
        .order_by(func.count(Hit.id).desc())
        .limit(MAX_ROWS)
        .all()
    )
    _stage("by-user-agent",
           _dump(UserAgentCount(user_ag=u, count=c) for u, c in rows))


def snap_by_method(db):
    rows = (
        db.query(Hit.method, func.count(Hit.id))
        .filter(Hit.is_attacker, Hit.method.isnot(None))
        .group_by(Hit.method)
        .order_by(func.count(Hit.id).desc())
        .limit(MAX_ROWS)
        .all()
    )
    _stage("by-method",
           _dump(MethodCount(methd=m, count=c) for m, c in rows))


def snap_by_country_fraction(db):
    atk = db.query(func.count(Hit.id)).filter(Hit.is_attacker).scalar()
    rows = (
        db.query(Hit.country, func.count(Hit.id))
        .filter(Hit.is_attacker, Hit.country.isnot(None))
        .group_by(Hit.country)
        .order_by(func.count(Hit.id).desc())
        .all()                             # ← no limit, by design
    )
    resp: list[CountryFraction] = []
    total_fraction = 0.0
    for cn, c in rows:
        frac = (c / atk) * 100 if atk else 0.0
        if frac >= 2:
            resp.append(CountryFraction(country=cn, fraction=frac))
            total_fraction += frac
        else:
            break
    resp.append(CountryFraction(country="Other", fraction=100.0 - total_fraction))
    _stage("by-country-fraction", _dump(resp))


def main() -> int:
    print(f"SNAPSHOT_DIR = {DATA_DIR}")
    db = SessionLocal()
    try:
        snap_summary(db)
        snap_by_kind(db)
        snap_top_ips(db)
        snap_by_country(db)
        snap_by_city(db)
        for interval in ("minute", "hour", "day"):
            snap_timeline(db, interval)
            snap_bot_fraction(db, interval)
        snap_extended_summary(db)
        snap_by_user_agent(db)
        snap_by_method(db)
        snap_by_country_fraction(db)
    except Exception:
        _rollback()
        raise
    finally:
        db.close()

    _commit()
    print(f"wrote {len(_pending)} files to {DATA_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

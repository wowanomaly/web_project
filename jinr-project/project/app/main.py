import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query

from .db import Base, engine
from .ingest import ingest
from .schemas import (
    Summary, KindCount, IpCount, TimelinePoint, CountryCount, CityCount,
    BotFraction, ExtendedSummary, UserAgentCount, MethodCount, CountryFraction,
)

DATA_DIR = Path("/app/data")


def _load(name: str):
    """Load a pre-computed snapshot. 503 if cron hasn't produced it yet."""
    path = DATA_DIR / f"{name}.json"
    if not path.exists():
        raise HTTPException(
            status_code=503,
            detail=f"Snapshot '{name}' not ready; wait for the next cron run.",
        )
    return json.loads(path.read_text())


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    result = ingest()
    print("Ingested:", result)
    yield


app = FastAPI(title="JINR attack dashboard", lifespan=lifespan)


@app.get("/api/summary", response_model=Summary)
def summary():
    return _load("summary")


@app.get("/api/attackers/by-kind", response_model=list[KindCount])
def by_kind():
    return _load("by-kind")


@app.get("/api/attackers/top-ips", response_model=list[IpCount])
def top_ips(limit: int = Query(20, ge=1, le=500)):
    return _load("top-ips")[:limit]


@app.get("/api/attackers/by-country", response_model=list[CountryCount])
def by_country(limit: int = Query(20, ge=1, le=500)):
    return _load("by-country")[:limit]


@app.get("/api/attackers/by-city", response_model=list[CityCount])
def by_city(limit: int = Query(20, ge=1, le=500)):
    return _load("by-city")[:limit]


@app.get("/api/attackers/timeline", response_model=list[TimelinePoint])
def timeline(interval: str = Query("minute", pattern="^(minute|hour|day)$")):
    return _load(f"timeline-{interval}")


@app.get("/api/attackers/bot-fraction", response_model=list[BotFraction])
def bot_fraction(interval: str = Query("minute", pattern="^(minute|hour|day)$")):
    return _load(f"bot-fraction-{interval}")


@app.get("/api/extended_summary", response_model=ExtendedSummary)
def extended_summary():
    return _load("extended_summary")


@app.get("/api/attackers/by-user-agent", response_model=list[UserAgentCount])
def by_user_agent(limit: int = Query(20, ge=1, le=500)):
    return _load("by-user-agent")[:limit]


@app.get("/api/attackers/by-method", response_model=list[MethodCount])
def by_method(limit: int = Query(20, ge=1, le=500)):
    return _load("by-method")[:limit]


@app.get("/api/attackers/by-country-fraction", response_model=list[CountryFraction])
def by_country_fraction():
    return _load("by-country-fraction")